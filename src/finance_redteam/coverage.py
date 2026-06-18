from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .schema import AttackRecord, TaxonomyCategory


@dataclass(frozen=True)
class CoverageReport:
    total_records: int
    categories: dict[str, int]
    attack_types: dict[str, int]
    sources: dict[str, int]
    mutation_strategies: dict[str, int]
    interaction_types: dict[str, int]
    max_mutation_depth: int
    missing_category_ids: list[str]

    def model_dump(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "categories": self.categories,
            "attack_types": self.attack_types,
            "sources": self.sources,
            "mutation_strategies": self.mutation_strategies,
            "interaction_types": self.interaction_types,
            "max_mutation_depth": self.max_mutation_depth,
            "missing_category_ids": self.missing_category_ids,
        }


def build_coverage_report(records: list[AttackRecord], categories: list[TaxonomyCategory]) -> CoverageReport:
    category_counter = Counter(record.risk_category for record in records)
    attack_type_counter = Counter(record.attack_type for record in records)
    source_counter = Counter(record.source for record in records)
    mutation_counter = Counter(record.mutation_strategy or "none" for record in records)
    interaction_counter = Counter(record.interaction_type for record in records)
    category_names = {category.name: category.category_id for category in categories}
    covered_names = set(category_counter)
    missing = sorted(category_id for name, category_id in category_names.items() if name not in covered_names)
    max_depth = max((record.mutation_depth for record in records), default=0)
    return CoverageReport(
        total_records=len(records),
        categories=dict(sorted(category_counter.items())),
        attack_types=dict(sorted(attack_type_counter.items())),
        sources=dict(sorted(source_counter.items())),
        mutation_strategies=dict(sorted(mutation_counter.items())),
        interaction_types=dict(sorted(interaction_counter.items())),
        max_mutation_depth=max_depth,
        missing_category_ids=missing,
    )


def attach_coverage_trace(records: list[AttackRecord], report: CoverageReport) -> list[AttackRecord]:
    traced: list[AttackRecord] = []
    for record in records:
        data = record.model_dump()
        data["coverage_trace"] = {
            **data.get("coverage_trace", {}),
            "category_record_count": report.categories.get(record.risk_category, 0),
            "attack_type_record_count": report.attack_types.get(record.attack_type, 0),
            "source_record_count": report.sources.get(record.source, 0),
            "mutation_strategy_record_count": report.mutation_strategies.get(record.mutation_strategy or "none", 0),
            "lineage_depth": record.mutation_depth,
        }
        traced.append(AttackRecord.model_validate(data))
    return traced
