from __future__ import annotations

from pathlib import Path

import yaml

from .domain_pack import FINANCE_DOMAIN_PACK, PACKAGE_ROOT, DomainPack, get_domain_pack
from .schema import TaxonomyCategory


DEFAULT_TAXONOMY_PATH = FINANCE_DOMAIN_PACK.taxonomy_path
DEFAULT_FRAMEWORK_MAPPINGS_PATH = FINANCE_DOMAIN_PACK.framework_mappings_path


def build_default_taxonomy(domain_pack: DomainPack | None = None) -> list[TaxonomyCategory]:
    pack = domain_pack or get_domain_pack()
    return [
        TaxonomyCategory(
            category_id=risk.category_id,
            name=risk.name,
            description=risk.description,
            domain_examples=risk.examples,
            owasp_mapping=risk.owasp_mapping,
            mitre_atlas_mapping=risk.mitre_atlas_mapping,
            nist_ai_rmf_mapping=risk.nist_ai_rmf_mapping,
            severity=risk.severity,  # type: ignore[arg-type]
            default_expected_behavior=risk.default_expected_behavior,
        )
        for risk in pack.risks
    ]


def load_taxonomy(path: Path = DEFAULT_TAXONOMY_PATH, domain_pack: DomainPack | None = None) -> list[TaxonomyCategory]:
    if not path.exists():
        return build_default_taxonomy(domain_pack)
    data = yaml.safe_load(path.read_text()) or {}
    return [TaxonomyCategory.model_validate(item) for item in data.get("categories", [])]


def write_taxonomy(path: Path = DEFAULT_TAXONOMY_PATH, domain_pack: DomainPack | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    categories = [category.model_dump() for category in build_default_taxonomy(domain_pack)]
    path.write_text(yaml.safe_dump({"categories": categories}, sort_keys=False), encoding="utf-8")


def write_framework_mappings(path: Path = DEFAULT_FRAMEWORK_MAPPINGS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "owasp_top_10_llm": [
            "LLM01 Prompt Injection",
            "LLM02 Insecure Output Handling",
            "LLM03 Training Data Poisoning",
            "LLM04 Model Denial of Service",
            "LLM05 Supply Chain Vulnerabilities",
            "LLM06 Sensitive Information Disclosure",
            "LLM07 Insecure Plugin Design",
            "LLM08 Excessive Agency",
            "LLM09 Overreliance",
            "LLM10 Model Theft",
        ],
        "nist_ai_rmf_functions": ["GOVERN", "MAP", "MEASURE", "MANAGE"],
        "mitre_atlas_note": "Mappings are defensive coverage labels used for benchmark organization.",
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
