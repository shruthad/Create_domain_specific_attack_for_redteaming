from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from finance_redteam.domain_pack import DomainPack
from finance_redteam.seed_sources.resolver import resolve_category_id

from .schema import GarakCorpusCandidate, GarakCorpusConfig


PROBE_HINTS = {
    "promptinject": ("indirect_prompt_injection", "FIN-PI", 3, ["prompt injection", "instruction override"]),
    "dan": ("jailbreak", "FIN-PI", 4, ["jailbreak", "ignore instructions"]),
    "encoding": ("encoding_obfuscation", "FIN-REG", 3, ["encoding", "obfuscation"]),
    "sysprompt_extraction": ("system_prompt_extraction", "FIN-EXTRACT", 3, ["system prompt", "prompt leakage"]),
    "leakreplay": ("data_extraction", "FIN-SID", 3, ["data leakage", "sensitive information"]),
    "lmrc": ("hypothetical_scenario", "FIN-HALL", 2, ["misinformation", "harmful content"]),
    "goodside": ("jailbreak", "FIN-PI", 3, ["jailbreak", "prompt injection"]),
    "donotanswer": ("policy_bypass", "FIN-REG", 3, ["policy bypass", "unsafe request"]),
    "misleading": ("direct_request", "FIN-HALL", 2, ["misleading", "unsupported claims"]),
    "web_injection": ("indirect_prompt_injection", "FIN-RAG", 4, ["web injection", "indirect prompt injection"]),
    "latentinjection": ("indirect_prompt_injection", "FIN-RAG", 4, ["latent injection", "indirect prompt injection"]),
    "packagehallucination": ("hypothetical_scenario", "FIN-HALL", 2, ["hallucination", "package"]),
    "tap": ("jailbreak", "FIN-PI", 4, ["jailbreak", "attack prompt"]),
    "suffix": ("jailbreak", "FIN-PI", 4, ["suffix", "jailbreak"]),
    "grandma": ("roleplay", "FIN-REG", 3, ["roleplay", "policy bypass"]),
    "snowball": ("hypothetical_scenario", "FIN-HALL", 3, ["reasoning", "misinformation"]),
}


def garak_package_path() -> Path | None:
    spec = importlib.util.find_spec("garak")
    locations = list(getattr(spec, "submodule_search_locations", []) or []) if spec else []
    if locations:
        return Path(locations[0])
    if spec and spec.origin:
        return Path(spec.origin).parent
    return None


def normalize_prompt(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _candidate_id(probe_name: str, text: str) -> str:
    digest = hashlib.sha256(f"{probe_name}:{text}".encode("utf-8")).hexdigest()[:16]
    return f"garak-corpus-{digest}"


def _iter_ast_strings(path: Path) -> Iterable[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, OSError, UnicodeDecodeError):
        return []
    strings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
    return strings


def _flatten_json_strings(payload: Any) -> Iterable[str]:
    if isinstance(payload, str):
        yield payload
    elif isinstance(payload, list):
        for item in payload:
            yield from _flatten_json_strings(item)
    elif isinstance(payload, dict):
        for value in payload.values():
            yield from _flatten_json_strings(value)


def _iter_json_strings(path: Path) -> Iterable[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []
    return list(_flatten_json_strings(payload))


def _iter_text_lines(path: Path) -> Iterable[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    except (OSError, UnicodeDecodeError):
        return []


def _probe_from_path(path: Path, garak_root: Path, allowlist: list[str]) -> str | None:
    rel_parts = path.relative_to(garak_root).parts
    joined = "/".join(rel_parts).lower()
    for probe in allowlist:
        normalized_probe = probe.lower()
        if f"probes/{normalized_probe}.py" in joined:
            return normalized_probe
        if f"data/{normalized_probe}/" in joined or f"resources/{normalized_probe}/" in joined:
            return normalized_probe
        if normalized_probe in joined:
            return normalized_probe
    return None


def _iter_candidate_files(garak_root: Path, config: GarakCorpusConfig) -> Iterable[Path]:
    allowlist = [item.lower() for item in config.probe_allowlist]
    if config.include_probe_source_strings:
        probes_dir = garak_root / "probes"
        if probes_dir.exists():
            yield from sorted(path for path in probes_dir.glob("*.py") if _probe_from_path(path, garak_root, allowlist))
    if config.include_data_files:
        for folder_name in ("data", "resources"):
            folder = garak_root / folder_name
            if not folder.exists():
                continue
            for pattern in ("*.json", "*.jsonl", "*.txt", "*.py"):
                for path in sorted(folder.rglob(pattern)):
                    if _probe_from_path(path, garak_root, allowlist):
                        yield path


def _strings_from_file(path: Path) -> Iterable[str]:
    suffix = path.suffix.lower()
    if suffix == ".py":
        yield from _iter_ast_strings(path)
    elif suffix == ".json":
        yield from _iter_json_strings(path)
    elif suffix == ".jsonl":
        for line in _iter_text_lines(path):
            try:
                yield from _flatten_json_strings(json.loads(line))
            except json.JSONDecodeError:
                yield line
    elif suffix == ".txt":
        yield from _iter_text_lines(path)


def _looks_like_prompt(text: str, config: GarakCorpusConfig) -> bool:
    if not (config.min_prompt_chars <= len(text) <= config.max_prompt_chars):
        return False
    lowered = text.lower()
    if any(term.lower() in lowered for term in config.excluded_terms):
        return False
    non_prompt_markers = [
        "spdx-",
        "args:",
        "returns:",
        "raises:",
        "probes in this module",
        "further info:",
        "copyright",
        "license",
        "metaclass",
        "detector",
        "config_root",
    ]
    if any(marker in lowered for marker in non_prompt_markers):
        return False
    if text.startswith("http://") or text.startswith("https://"):
        return False
    if text.count("/") > 8 and " " not in text:
        return False
    prompt_markers = [
        "ignore",
        "prompt",
        "instruction",
        "system",
        "user",
        "assistant",
        "answer",
        "tell",
        "write",
        "summarize",
        "translate",
        "repeat",
        "secret",
        "policy",
        "jailbreak",
    ]
    return any(marker in lowered for marker in prompt_markers)


def _domain_relevance(text: str, domain_pack: DomainPack, config: GarakCorpusConfig) -> float:
    lowered = text.lower()
    domain_terms = set(config.domain_terms)
    domain_terms.update(domain_pack.default_tags)
    domain_terms.update(domain_pack.display_name.lower().split())
    for context in domain_pack.contexts:
        domain_terms.update(context.lower().split())
    for risk in domain_pack.risks:
        domain_terms.update(risk.name.lower().split())
        domain_terms.update(risk.seed_risk_request.lower().split())
    domain_terms = {term for term in domain_terms if len(term) >= 4}
    hits = sum(1 for term in domain_terms if term in lowered)
    return min(1.0, hits / 6)


def extract_garak_corpus_candidates(
    domain_pack: DomainPack,
    config: GarakCorpusConfig | None = None,
    garak_root: Path | None = None,
) -> list[GarakCorpusCandidate]:
    cfg = config or GarakCorpusConfig()
    root = garak_root or garak_package_path()
    if root is None or not root.exists():
        return []

    candidates: list[GarakCorpusCandidate] = []
    seen: set[str] = set()
    allowlist = [item.lower() for item in cfg.probe_allowlist]
    for path in _iter_candidate_files(root, cfg):
        probe_name = _probe_from_path(path, root, allowlist)
        if not probe_name:
            continue
        attack_type, preferred_category_id, difficulty, terms = PROBE_HINTS.get(
            probe_name, ("direct_request", "FIN-PI", 2, [probe_name])
        )
        category_id = resolve_category_id(
            domain_pack,
            preferred_category_id,
            terms=[probe_name, *terms],
            fallback_index=len(candidates),
        )
        for raw in _strings_from_file(path):
            normalized = normalize_prompt(raw)
            fingerprint = normalized.lower()
            if fingerprint in seen or not _looks_like_prompt(normalized, cfg):
                continue
            seen.add(fingerprint)
            candidates.append(
                GarakCorpusCandidate(
                    candidate_id=_candidate_id(probe_name, normalized),
                    probe_name=probe_name,
                    source_path=path,
                    raw_prompt=raw,
                    normalized_prompt=normalized,
                    attack_type=attack_type,
                    category_id=category_id,
                    difficulty=difficulty,
                    relevance_score=_domain_relevance(normalized, domain_pack, cfg),
                    metadata={
                        "garak_root": str(root),
                        "relative_source_path": str(path.relative_to(root)),
                        "preferred_category_id": preferred_category_id,
                        "resolved_category_id": category_id,
                        "probe_terms": terms,
                    },
                )
            )
            if len(candidates) >= cfg.max_raw_candidates:
                return candidates
    return candidates
