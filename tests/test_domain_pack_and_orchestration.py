from finance_redteam.builder import build_records_from_config
from finance_redteam.config import BenchmarkConfig
from finance_redteam.domain_pack import get_domain_pack
from finance_redteam.orchestrator import OrchestrationConfig, orchestrate_mutations
from finance_redteam.seed_prompts import build_seed_authoring_starter, build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def test_finance_is_domain_pack_not_schema_identity():
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)

    assert pack.domain_id == "banking_finance"
    assert len(categories) == 20
    assert categories[0].domain_examples


def test_seed_starter_explains_how_to_begin_domain_seed_design():
    starter = build_seed_authoring_starter(get_domain_pack("banking_finance"))

    assert starter["domain_id"] == "banking_finance"
    assert starter["questions"]
    assert "recommended_seed_shape" in starter
    assert "authoring_rules" in starter


def test_orchestrator_creates_lineage_aware_mutations():
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)
    seeds = build_seed_prompts(categories[:1], per_category=1, domain_pack=pack)
    from finance_redteam.local_generator import seeds_to_records

    records = seeds_to_records(seeds, categories[:1], domain_pack=pack)
    mutations = orchestrate_mutations(
        records,
        OrchestrationConfig(
            strategies=["authority_pretext", "policy_exception"],
            max_records=1,
            variants_per_record=2,
            include_multi_turn_plans=True,
            max_multi_turn_plans=1,
        ),
    )

    assert len(mutations) == 3
    assert {record.mutation_strategy for record in mutations} == {
        "authority_pretext",
        "policy_exception",
        "multi_turn_plan",
    }
    assert all(record.parent_attack_id == records[0].attack_id for record in mutations)
    assert all(records[0].attack_id in record.lineage for record in mutations)


def test_build_records_include_coverage_and_mutation_outputs():
    config = BenchmarkConfig(
        min_per_category=5,
        max_per_category=5,
        use_orchestrator=True,
        orchestration=OrchestrationConfig(max_records=2, variants_per_record=2, max_multi_turn_plans=1),
    )
    result = build_records_from_config(config)

    assert result.mutation_records
    assert result.coverage.total_records == len(result.records)
    assert result.coverage.max_mutation_depth >= 1
    assert all(record.coverage_trace for record in result.records)
