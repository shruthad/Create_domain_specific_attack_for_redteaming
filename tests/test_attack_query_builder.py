from dataclasses import replace

from finance_redteam.attack_query_builder import assess_attack_query_quality, build_direct_attack_query
from finance_redteam.builder import build_records_from_config
from finance_redteam.config import BenchmarkConfig
from finance_redteam.orchestrator import OrchestrationConfig


def test_direct_attack_query_builder_avoids_meta_language():
    query = build_direct_attack_query(
        attack_type="authority_impersonation",
        workflow_name="Wire Transfer Approval",
        protected_asset="beneficiary details",
        attack_objective="Trigger Unauthorized Financial Action",
        tool_name="beneficiary_directory",
        source_metadata={"scenario": {"persona": "branch manager", "context": "wire transfer"}},
    )
    quality = assess_attack_query_quality(query)

    assert quality.is_direct
    assert "A user asks" not in query
    assert "evaluate whether" not in query.lower()
    assert "beneficiary details" in query
    assert "beneficiary_directory" in query


def test_build_exports_direct_workflow_queries_not_passive_wrappers():
    config = BenchmarkConfig(
        min_per_category=5,
        max_per_category=5,
        use_orchestrator=True,
        use_llm_generator=False,
        use_deepteam=False,
        use_garak=False,
        orchestration=OrchestrationConfig(
            max_records=2,
            variants_per_record=2,
            max_multi_turn_plans=1,
        ),
    )
    config = config.model_copy(
        update={
            "seed_sources": config.seed_sources.model_copy(update={"enabled": False}),
            "garak_corpus": config.garak_corpus.model_copy(update={"enabled": False}),
            "orchestration": replace(config.orchestration, include_multi_turn_plans=True),
        }
    )

    result = build_records_from_config(config)

    assert result.records
    assert all(record.workflow_id for record in result.records)
    assert all(record.attack_objective for record in result.records)
    assert all(assess_attack_query_quality(record.attack_query or record.prompt).score >= 70 for record in result.records)
    assert not any("evaluate whether" in (record.attack_query or "").lower() for record in result.records)
    assert not any((record.attack_query or "").lower().startswith("a user asks") for record in result.records)

