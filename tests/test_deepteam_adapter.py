from finance_redteam.deepteam_adapter import DeepTeamExpansionConfig, generate_deepteam_variants
from finance_redteam.schema import AttackRecord


def _record(attack_id: str, risk_category: str, attack_type: str = "direct_request") -> AttackRecord:
    return AttackRecord(
        attack_id=attack_id,
        risk_category=risk_category,
        risk_subcategory="Test subcategory",
        owasp_mapping=["LLM01 Prompt Injection"],
        mitre_atlas_mapping=["Prompt Injection"],
        nist_ai_rmf_mapping=["MAP"],
        finance_domain_mapping=["Customer Data Protection"],
        attack_type=attack_type,  # type: ignore[arg-type]
        interaction_type="single_turn",
        difficulty=2,
        source="seed",
        prompt="A defensive evaluation prompt that the model should refuse.",
        expected_behavior="Refuse unsafe assistance and redirect safely.",
        unsafe_success_criteria="The model provides unsafe or sensitive details.",
        safe_response_guidance="Refuse and provide compliance-safe guidance.",
        tags=["finance", "test"],
    )


def test_deepteam_filters_by_vulnerability_and_attack_type(monkeypatch):
    monkeypatch.setattr("finance_redteam.deepteam_adapter.is_deepteam_available", lambda: True)
    records = [
        _record("FIN-PII-001", "Customer PII and Account Data Leakage"),
        _record("FIN-AML-001", "AML / KYC Evasion"),
    ]
    config = DeepTeamExpansionConfig(
        vulnerabilities=["pii_leakage"],
        attack_types=["data_extraction", "roleplay"],
        max_seed_records=10,
        variants_per_seed=2,
        include_original_attack_type=False,
    )

    variants = generate_deepteam_variants(records, auto_install=False, expansion_config=config)

    assert len(variants) == 2
    assert {variant.attack_type for variant in variants} == {"data_extraction", "roleplay"}
    assert all(variant.source == "deepteam" for variant in variants)
    assert all("pii-leakage" in variant.tags for variant in variants)


def test_deepteam_rejects_unknown_selector(monkeypatch):
    monkeypatch.setattr("finance_redteam.deepteam_adapter.is_deepteam_available", lambda: True)

    try:
        generate_deepteam_variants(
            [_record("FIN-PII-001", "Customer PII and Account Data Leakage")],
            auto_install=False,
            vulnerabilities=["unknown_vulnerability"],
        )
    except ValueError as exc:
        assert "Unsupported DeepTeam vulnerabilities" in str(exc)
    else:
        raise AssertionError("Expected unsupported vulnerability selector to raise")


def test_deepteam_llm_mode_dispatches_to_llm_generator(monkeypatch):
    monkeypatch.setattr("finance_redteam.deepteam_adapter.is_deepteam_available", lambda: True)

    expected = [_record("FIN-PII-001", "Customer PII and Account Data Leakage")]
    called = {}

    def fake_llm_generator(records, config):
        called["mode"] = config.generation_mode
        called["provider"] = config.simulator_provider
        return expected

    monkeypatch.setattr("finance_redteam.deepteam_adapter._generate_llm_deepteam_variants", fake_llm_generator)

    variants = generate_deepteam_variants(
        [_record("FIN-PII-001", "Customer PII and Account Data Leakage")],
        auto_install=False,
        expansion_config=DeepTeamExpansionConfig(generation_mode="llm", simulator_provider="gemini"),
    )

    assert variants == expected
    assert called == {"mode": "llm", "provider": "gemini"}
