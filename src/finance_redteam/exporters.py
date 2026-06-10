from __future__ import annotations

import json
from pathlib import Path

from .schema import AttackRecord


def export_jsonl(records: list[AttackRecord], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.model_dump(), ensure_ascii=True) + "\n")


def load_jsonl(path: Path) -> list[AttackRecord]:
    records: list[AttackRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(AttackRecord.model_validate(json.loads(line)))
    return records
