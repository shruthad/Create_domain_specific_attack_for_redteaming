import yaml

from finance_redteam.domain_pack import get_domain_pack
from finance_redteam.domain_pack_template import create_domain_pack_template, slugify_domain_id
from finance_redteam.config import load_benchmark_config
from finance_redteam.seed_prompts import build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def test_slugify_domain_id():
    assert slugify_domain_id("Healthcare Claims") == "healthcare_claims"


def test_create_domain_pack_template_is_loadable(tmp_path):
    result = create_domain_pack_template(
        domain_id="Healthcare Claims",
        display_name="Healthcare Claims",
        output_root=tmp_path,
        personas=["claims analyst", "clinical reviewer"],
        contexts=["claims review", "prior authorization"],
        risk_count=4,
    )

    pack = get_domain_pack(str(result.domain_pack_path))
    categories = build_default_taxonomy(pack)
    seeds = build_seed_prompts(categories, per_category=1, domain_pack=pack)
    config = yaml.safe_load(result.config_path.read_text())
    loaded_config = load_benchmark_config(result.config_path)

    assert pack.domain_id == "healthcare_claims"
    assert len(categories) == 4
    assert len(seeds) == 4
    assert pack.workflows
    assert pack.attack_objectives
    assert all(seed.workflow_id for seed in seeds)
    assert all(seed.protected_asset for seed in seeds)
    assert config["domain_pack"] == "../domain_packs/healthcare_claims/domain_pack.yaml"
    assert loaded_config.domain_pack.endswith("domain_packs/healthcare_claims/domain_pack.yaml")
    assert config["llm_generator"]["provider"] == "openai"
    assert config["llm_generator"]["model"] == "gpt-4.1-nano"
    assert config["output"]["coverage_json"] == "data/exports/healthcare_claims_coverage_matrix.json"
