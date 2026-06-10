from finance_redteam.normalizer import normalize_text


def test_normalize_text_collapses_whitespace():
    assert normalize_text("  hello\n   finance   ") == "hello finance"
