from __future__ import annotations

from pathlib import Path

from _bootstrap import add_src_to_path

add_src_to_path()

from finance_redteam.exporters import load_jsonl  # noqa: E402
from finance_redteam.promptfoo_exporter import export_promptfoo  # noqa: E402


if __name__ == "__main__":
    records = load_jsonl(Path("data/exports/finance_redteam_attacks.jsonl"))
    export_promptfoo(records, Path("data/exports/promptfoo_tests.yaml"))
    print("Generated Promptfoo config.")
