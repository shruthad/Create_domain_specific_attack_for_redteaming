from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SeedSourceItem:
    source_name: str
    source_reference: str
    category_id: str
    attack_type: str
    difficulty: int
    prompt_intent: str
    source_type: str = "framework_signal"
    framework: str | None = None
    adaptation_strategy: str = "domain_pack_contextualization"
    is_final_prompt: bool = False
    expected_behavior: str | None = None
    unsafe_success_criteria: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
