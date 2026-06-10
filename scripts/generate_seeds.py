from __future__ import annotations

from _bootstrap import add_src_to_path

add_src_to_path()

from finance_redteam.seed_prompts import write_seed_prompts  # noqa: E402
from finance_redteam.taxonomy import write_framework_mappings, write_taxonomy  # noqa: E402


if __name__ == "__main__":
    write_taxonomy()
    write_framework_mappings()
    write_seed_prompts(per_category=5)
    print("Generated seed prompts.")
