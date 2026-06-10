from __future__ import annotations

import re

from .schema import AttackRecord


SPACE_RE = re.compile(r"\s+")


def normalize_text(value: str) -> str:
    return SPACE_RE.sub(" ", value.strip())


def normalize_record(record: AttackRecord) -> AttackRecord:
    data = record.model_dump()
    for key in ["prompt", "expected_behavior", "unsafe_success_criteria", "safe_response_guidance"]:
        data[key] = normalize_text(data[key])
    if data.get("attack_query"):
        data["attack_query"] = normalize_text(data["attack_query"])
    data["tags"] = sorted({tag.strip().lower() for tag in data["tags"] if tag.strip()})
    return AttackRecord.model_validate(data)
