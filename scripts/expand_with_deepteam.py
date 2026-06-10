from __future__ import annotations

from pathlib import Path

from _bootstrap import add_src_to_path

add_src_to_path()

from finance_redteam.deepteam_adapter import generate_deepteam_variants  # noqa: E402
from finance_redteam.exporters import export_jsonl, load_jsonl  # noqa: E402


if __name__ == "__main__":
    input_path = Path("data/exports/finance_redteam_attacks.jsonl")
    records = load_jsonl(input_path)
    variants = generate_deepteam_variants(records)
    export_jsonl(variants, Path("data/generated/deepteam_variants.jsonl"))
    print(f"Generated {len(variants)} DeepTeam variants.")
