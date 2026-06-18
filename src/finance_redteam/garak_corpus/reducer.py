from __future__ import annotations

from collections import Counter

from .schema import GarakCorpusCandidate, GarakCorpusConfig


def _token_signature(text: str) -> str:
    tokens = sorted({token for token in text.lower().split() if len(token) > 3})
    return " ".join(tokens[:40])


def reduce_garak_corpus_candidates(
    candidates: list[GarakCorpusCandidate],
    config: GarakCorpusConfig | None = None,
) -> list[GarakCorpusCandidate]:
    cfg = config or GarakCorpusConfig()
    probe_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    signatures: set[str] = set()
    selected: list[GarakCorpusCandidate] = []

    ordered = sorted(
        candidates,
        key=lambda item: (
            item.relevance_score,
            -len(item.normalized_prompt),
            item.probe_name,
            item.candidate_id,
        ),
        reverse=True,
    )

    for candidate in ordered:
        if len(selected) >= cfg.max_total_seeds:
            break
        signature = _token_signature(candidate.normalized_prompt)
        if signature in signatures:
            continue
        if probe_counts[candidate.probe_name] >= cfg.max_per_probe:
            continue
        if category_counts[candidate.category_id] >= cfg.max_per_category:
            continue
        signatures.add(signature)
        probe_counts[candidate.probe_name] += 1
        category_counts[candidate.category_id] += 1
        selected.append(candidate)

    return selected
