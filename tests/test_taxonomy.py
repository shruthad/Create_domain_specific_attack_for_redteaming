from finance_redteam.seed_prompts import build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def test_taxonomy_has_required_category_count():
    categories = build_default_taxonomy()
    assert len(categories) >= 20
    assert all(category.owasp_mapping for category in categories)


def test_seed_prompt_count():
    categories = build_default_taxonomy()
    seeds = build_seed_prompts(categories, per_category=5)
    assert len(seeds) == len(categories) * 5
