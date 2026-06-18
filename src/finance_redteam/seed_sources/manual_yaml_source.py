from __future__ import annotations

from pathlib import Path

import yaml

from .types import SeedSourceItem


def manual_yaml_seed_items(path: Path | None = None) -> list[SeedSourceItem]:
    if path is None or not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = []
    for item in data.get("seed_sources", []):
        items.append(
            SeedSourceItem(
                source_name=item.get("source_name", "MANUAL_YAML"),
                source_reference=item["source_reference"],
                category_id=item["category_id"],
                attack_type=item.get("attack_type", "direct_request"),
                difficulty=item.get("difficulty", 2),
                prompt_intent=item["prompt_intent"],
                source_type=item.get("source_type", "internal_seed_signal"),
                framework=item.get("framework"),
                adaptation_strategy=item.get("adaptation_strategy", "manual_signal_to_domain_pack_prompt"),
                is_final_prompt=item.get("is_final_prompt", False),
                expected_behavior=item.get("expected_behavior"),
                unsafe_success_criteria=item.get("unsafe_success_criteria"),
                tags=item.get("tags", []),
                metadata=item.get("metadata", {}),
            )
        )
    return items
