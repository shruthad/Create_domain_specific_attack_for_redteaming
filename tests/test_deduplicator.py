from finance_redteam.deduplicator import deduplicate_records
from finance_redteam.local_generator import seeds_to_records
from finance_redteam.seed_prompts import build_seed_prompts
from finance_redteam.taxonomy import build_default_taxonomy


def test_deduplicate_records_removes_prompt_duplicates():
    categories = build_default_taxonomy()
    seeds = build_seed_prompts(categories[:1], per_category=1)
    records = seeds_to_records(seeds, categories)
    duplicate = records[0].model_copy(update={"attack_id": "FIN-PI-DUP"})
    deduped = deduplicate_records([records[0], duplicate])
    assert len(deduped) == 1
