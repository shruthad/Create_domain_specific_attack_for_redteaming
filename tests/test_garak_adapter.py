from finance_redteam.garak_adapter import GarakExpansionConfig, run_garak_scan


def test_garak_filters_by_probe_family_without_installed_garak(monkeypatch, tmp_path):
    monkeypatch.setattr("finance_redteam.garak_adapter.is_garak_available", lambda: False)
    records = run_garak_scan(
        auto_install=False,
        report_dir=tmp_path,
        expansion_config=GarakExpansionConfig(
            probe_families=["rag_exfiltration"],
            max_patterns=10,
        ),
    )

    assert records
    assert all(record.source == "garak" for record in records)
    assert {record.source_metadata["probe_family"] for record in records} == {"rag_exfiltration"}
    assert {record.attack_type for record in records} <= {"rag_exfiltration", "summarization_attack"}


def test_garak_filters_by_attack_type_and_difficulty(monkeypatch, tmp_path):
    monkeypatch.setattr("finance_redteam.garak_adapter.is_garak_available", lambda: False)
    records = run_garak_scan(
        auto_install=False,
        report_dir=tmp_path,
        expansion_config=GarakExpansionConfig(
            attack_types=["tool_misuse"],
            min_difficulty=5,
            max_patterns=5,
        ),
    )

    assert len(records) == 1
    assert records[0].attack_type == "tool_misuse"
    assert records[0].difficulty == 5


def test_garak_rejects_unknown_probe_family(monkeypatch, tmp_path):
    monkeypatch.setattr("finance_redteam.garak_adapter.is_garak_available", lambda: False)

    try:
        run_garak_scan(
            auto_install=False,
            report_dir=tmp_path,
            expansion_config=GarakExpansionConfig(probe_families=["unknown_probe"]),
        )
    except ValueError as exc:
        assert "Unsupported Garak probe_families" in str(exc)
    else:
        raise AssertionError("Expected unsupported Garak selector to raise")
