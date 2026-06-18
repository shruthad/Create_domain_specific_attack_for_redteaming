from __future__ import annotations

from dataclasses import dataclass, field

from .multiturn_planner import apply_multi_turn_plan
from .mutation_strategies import select_mutation_strategies
from .schema import AttackRecord


@dataclass(frozen=True)
class OrchestrationConfig:
    enabled: bool = True
    strategies: list[str] = field(default_factory=lambda: ["authority_pretext", "policy_exception"])
    max_records: int = 20
    variants_per_record: int = 3
    include_multi_turn_plans: bool = True
    max_multi_turn_plans: int = 5


def orchestrate_mutations(records: list[AttackRecord], config: OrchestrationConfig | None = None) -> list[AttackRecord]:
    cfg = config or OrchestrationConfig()
    if not cfg.enabled:
        return []

    strategies = select_mutation_strategies(cfg.strategies)
    selected_records = records[: max(0, cfg.max_records)]
    mutations: list[AttackRecord] = []
    counter = 1

    for record in selected_records:
        for strategy in strategies[: max(1, cfg.variants_per_record)]:
            mutations.append(strategy.mutate(record, counter))
            counter += 1

    if cfg.include_multi_turn_plans:
        for index, record in enumerate(selected_records[: max(0, cfg.max_multi_turn_plans)], start=1):
            mutations.append(apply_multi_turn_plan(record, index))

    return mutations
