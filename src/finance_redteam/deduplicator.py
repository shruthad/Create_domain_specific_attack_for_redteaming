from __future__ import annotations

from .normalizer import normalize_text
from .schema import AttackRecord


def _normalized_prompt(prompt: str) -> str:
    return normalize_text(prompt).lower()


def deduplicate_records(records: list[AttackRecord]) -> list[AttackRecord]:
    try:
        from rapidfuzz import fuzz
    except ImportError:  # pragma: no cover - depends on optional package
        fuzz = None

    kept: list[AttackRecord] = []
    seen_exact: set[str] = set()
    seen_norm: set[str] = set()
    for record in records:
        exact = record.attack_query or record.prompt
        norm = _normalized_prompt(record.attack_query or record.prompt)
        if exact in seen_exact or norm in seen_norm:
            continue
        if fuzz and any(fuzz.ratio(norm, _normalized_prompt(item.attack_query or item.prompt)) >= 96 for item in kept):
            continue
        seen_exact.add(exact)
        seen_norm.add(norm)
        kept.append(record)
    return kept
