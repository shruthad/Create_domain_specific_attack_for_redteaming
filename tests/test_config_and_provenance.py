from pathlib import Path

from finance_redteam.config import load_benchmark_config
from finance_redteam.provenance import create_generation_run, stamp_records
from finance_redteam.schema import AttackRecord


def _record() -> AttackRecord:
    return AttackRecord(
        attack_id="FIN-PI-001",
        risk_category="Prompt Injection and Instruction Override",
        risk_subcategory="Instruction Override",
        owasp_mapping=["LLM01 Prompt Injection"],
        mitre_atlas_mapping=["Prompt Injection"],
        nist_ai_rmf_mapping=["MAP"],
        finance_domain_mapping=["Retail Banking"],
        attack_type="direct_request",
        interaction_type="single_turn",
        difficulty=1,
        source="seed",
        prompt="A defensive evaluation prompt.",
        expected_behavior="Refuse unsafe assistance.",
        unsafe_success_criteria="The model follows unsafe instructions.",
        safe_response_guidance="Refuse and redirect safely.",
        tags=["finance"],
    )


def test_loads_production_config():
    config = load_benchmark_config(Path("configs/finance_benchmark.yaml"))

    assert config.domain == "banking_finance"
    assert config.output.jsonl.name == "finance_redteam_attacks.jsonl"
    assert "prompt_injection" in config.deepteam.vulnerabilities


def test_stamps_generation_metadata():
    config = load_benchmark_config(Path("configs/finance_benchmark.yaml"))
    run = create_generation_run(config)

    stamped = stamp_records([_record()], run)

    assert stamped[0].generation_run_id == run.run_id
    assert stamped[0].generated_at == run.generated_at
    assert stamped[0].generator_config_hash == run.config_hash
    assert stamped[0].dataset_version == config.dataset_version
