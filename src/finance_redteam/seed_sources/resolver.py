from __future__ import annotations

from collections.abc import Iterable

from finance_redteam.domain_pack import DomainPack, DomainRiskDefinition


def _normalize(value: str) -> str:
    return value.lower().replace("_", " ").replace("-", " ")


def _contains_any(text: str, terms: Iterable[str]) -> bool:
    normalized_text = _normalize(text)
    return any(_normalize(term) in normalized_text for term in terms if term)


def _risk_text(risk: DomainRiskDefinition) -> str:
    return " ".join(
        [
            risk.category_id,
            risk.name,
            risk.description,
            risk.default_subcategory,
            risk.seed_risk_request,
            " ".join(risk.examples),
            " ".join(risk.owasp_mapping),
            " ".join(risk.mitre_atlas_mapping),
            " ".join(risk.domain_mapping),
        ]
    )


def resolve_category_id(
    domain_pack: DomainPack,
    preferred_category_id: str,
    *,
    owasp_refs: list[str] | None = None,
    mitre_refs: list[str] | None = None,
    terms: list[str] | None = None,
    fallback_index: int = 0,
) -> str:
    """Map a framework signal to the active domain pack.

    Built-in finance uses exact FIN-* category ids. Generated domain packs will
    usually have different ids, so this resolver falls back to OWASP mappings,
    MITRE mappings, and keyword intent matching.
    """

    if preferred_category_id in domain_pack.risk_by_id:
        return preferred_category_id

    owasp_refs = owasp_refs or []
    mitre_refs = mitre_refs or []
    terms = terms or []

    for risk in domain_pack.risks:
        if set(owasp_refs).intersection(risk.owasp_mapping):
            return risk.category_id

    for risk in domain_pack.risks:
        if set(mitre_refs).intersection(risk.mitre_atlas_mapping):
            return risk.category_id

    scored: list[tuple[int, DomainRiskDefinition]] = []
    for risk in domain_pack.risks:
        text = _risk_text(risk)
        score = sum(1 for term in terms if _contains_any(text, [term]))
        if score:
            scored.append((score, risk))

    if scored:
        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[0][1].category_id

    if not domain_pack.risks:
        raise ValueError(f"Domain pack {domain_pack.domain_id} has no risks.")
    return domain_pack.risks[fallback_index % len(domain_pack.risks)].category_id
