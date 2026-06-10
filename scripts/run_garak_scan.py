from __future__ import annotations

from pathlib import Path

from _bootstrap import add_src_to_path

add_src_to_path()

from finance_redteam.exporters import export_jsonl  # noqa: E402
from finance_redteam.garak_adapter import run_garak_scan  # noqa: E402


if __name__ == "__main__":
    records = run_garak_scan()
    export_jsonl(records, Path("data/generated/garak_patterns.jsonl"))
    print(f"Generated {len(records)} Garak patterns.")
