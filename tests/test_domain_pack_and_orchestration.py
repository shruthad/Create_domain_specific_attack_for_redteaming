from finance_redteam.builder import build_records_from_config
from finance_redteam.attack_query_builder import assess_attack_query_quality
from finance_redteam.config import BenchmarkConfig
from finance_redteam.domain_pack import get_domain_pack
from finance_redteam.orchestrator import OrchestrationConfig, orchestrate_mutations
from finance_redteam.seed_prompts import build_seed_authoring_starter, build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy
from finance_redteam.multiturn_planner import apply_multi_turn_plan


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
    assert "workflow_seed_design" in starter
    assert "recommended_seed_shape" in starter
    assert "authoring_rules" in starter


def test_finance_pack_has_workflows_assets_and_objectives():
    pack = get_domain_pack("banking_finance")

    assert len(pack.workflows) >= 5
    assert len(pack.attack_objectives) >= 3
    assert pack.workflows_for_risk("FIN-RAG")
    assert pack.objectives_for_risk("FIN-AGENCY")
    assert all(workflow.protected_assets for workflow in pack.workflows)
    assert all(workflow.attack_objective_ids for workflow in pack.workflows)


def test_seed_prompts_are_workflow_specific():
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)
    seeds = build_seed_prompts(categories[:1], per_category=2, domain_pack=pack)

    assert all(seed.workflow_id for seed in seeds)
    assert all(seed.protected_asset for seed in seeds)
    assert all(seed.attack_objective for seed in seeds)
    assert all(seed.threat_scenario_id for seed in seeds)
    assert all(seed.threat_scenario for seed in seeds)
    assert all(seed.mutation_chain for seed in seeds)
    assert all(seed.eval_assertion for seed in seeds)
    assert all(seed.source_metadata.get("workflow") for seed in seeds)
    assert all(seed.source_metadata.get("threat_scenario") for seed in seeds)
    assert assess_attack_query_quality(seeds[0].prompt).is_direct
    assert "evaluation input" not in seeds[0].prompt.lower()


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
    assert all(record.workflow_id == records[0].workflow_id for record in mutations)
    assert all(record.protected_asset == records[0].protected_asset for record in mutations)
    assert all(record.threat_scenario_id == records[0].threat_scenario_id for record in mutations)
    assert all(record.eval_assertion == records[0].eval_assertion for record in mutations)
    assert all(record.mutation_chain[-1] == record.mutation_strategy for record in mutations)


def test_loan_underwriting_multi_turn_plan_is_scenario_specific():
    pack = get_domain_pack("banking_finance")
    categories = build_default_taxonomy(pack)
    seeds = build_seed_prompts(categories, per_category=3, domain_pack=pack)
    from finance_redteam.local_generator import seeds_to_records

    records = seeds_to_records(seeds, categories, domain_pack=pack)
    loan_record = next(record for record in records if record.workflow_id == "loan_underwriting_decision_support")
    multi_turn = apply_multi_turn_plan(loan_record, 1)

    assert multi_turn.interaction_type == "multi_turn"
    assert multi_turn.attack_type == "multi_turn_setup"
    assert "Turn 4:" in multi_turn.attack_query
    assert "decision rationale" in multi_turn.attack_query
    assert "internal note" in multi_turn.attack_query
    assert "underwriting" in multi_turn.attack_query.lower()


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
    assert result.coverage.workflows
    assert result.coverage.attack_objectives
    assert result.coverage.threat_scenarios
    assert result.coverage.mutation_chains
    assert result.coverage.workflow_risk_matrix
    assert not result.coverage.missing_workflow_ids
    assert all(record.coverage_trace for record in result.records)
    assert any(record.coverage_trace.get("workflow_record_count", 0) > 0 for record in result.records)
