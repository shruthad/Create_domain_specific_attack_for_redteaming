import yaml

from finance_redteam.domain_pack import get_domain_pack
from finance_redteam.domain_pack_template import create_domain_pack_template
from finance_redteam.seed_sources import collect_seed_source_items, seed_source_items_to_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def test_framework_seed_sources_create_domain_adapted_seed_prompts():
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)

    items = collect_seed_source_items(["owasp", "mitre_atlas", "garak"], pack)
    seeds = seed_source_items_to_seed_prompts(items, categories, pack, max_items=8)

    assert len(items) >= 20
    assert len(seeds) == 8
    assert all("framework-seed" in seed.tags for seed in seeds)
    assert all("banking and finance" in seed.prompt.lower() for seed in seeds)
    assert all(seed.source_metadata["is_final_prompt"] is False for seed in seeds)
    assert all(seed.source_metadata["adaptation_strategy"] for seed in seeds)
    assert "source signal adapted through the domain pack" in seeds[0].prompt


def test_manual_yaml_seed_source(tmp_path):
    path = tmp_path / "manual_sources.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "seed_sources": [
                    {
                        "source_name": "INTERNAL_POLICY",
                        "source_reference": "POL-001",
                        "category_id": "FIN-PII",
                        "attack_type": "data_extraction",
                        "difficulty": 2,
                        "prompt_intent": "request customer data from an internal policy exception",
                        "tags": ["internal-policy"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)

    items = collect_seed_source_items(["manual_yaml"], pack, path)
    seeds = seed_source_items_to_seed_prompts(items, categories, pack)

    assert len(items) == 1
    assert len(seeds) == 1
    assert "internal-policy" in seeds[0].tags
    assert "POL-001".lower() in seeds[0].prompt.lower()


def test_framework_seed_sources_resolve_against_generated_domain_pack(tmp_path):
    result = create_domain_pack_template(
        domain_id="healthcare_claims",
        display_name="Healthcare Claims",
        output_root=tmp_path,
        risk_count=6,
    )
    pack = get_domain_pack(str(result.domain_pack_path))
    categories = build_default_taxonomy(pack)

    items = collect_seed_source_items(["owasp", "mitre_atlas", "garak"], pack)
    seeds = seed_source_items_to_seed_prompts(items, categories, pack, max_items=30)
    category_ids = {category.category_id for category in categories}

    assert seeds
    assert all(seed.category_id in category_ids for seed in seeds)
    assert all("healthcare claims" in seed.prompt.lower() for seed in seeds)
    assert all(seed.source_metadata["domain_pack"] == "healthcare_claims" for seed in seeds)
    assert {seed.source_metadata["source_type"] for seed in seeds} >= {
        "risk_taxonomy_signal",
        "adversary_technique_signal",
        "scanner_probe_signal",
    }
