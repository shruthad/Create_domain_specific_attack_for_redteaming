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
    workflows: dict[str, int]
    protected_assets: dict[str, int]
    attack_objectives: dict[str, int]
    threat_scenarios: dict[str, int]
    mutation_chains: dict[str, int]
    workflow_risk_matrix: dict[str, int]
    workflow_attack_type_matrix: dict[str, int]
    max_mutation_depth: int
    missing_category_ids: list[str]
    missing_workflow_ids: list[str]

    def model_dump(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "categories": self.categories,
            "attack_types": self.attack_types,
            "sources": self.sources,
            "mutation_strategies": self.mutation_strategies,
            "interaction_types": self.interaction_types,
            "workflows": self.workflows,
            "protected_assets": self.protected_assets,
            "attack_objectives": self.attack_objectives,
            "threat_scenarios": self.threat_scenarios,
            "mutation_chains": self.mutation_chains,
            "workflow_risk_matrix": self.workflow_risk_matrix,
            "workflow_attack_type_matrix": self.workflow_attack_type_matrix,
            "max_mutation_depth": self.max_mutation_depth,
            "missing_category_ids": self.missing_category_ids,
            "missing_workflow_ids": self.missing_workflow_ids,
        }


def build_coverage_report(
    records: list[AttackRecord],
    categories: list[TaxonomyCategory],
    workflow_ids: list[str] | None = None,
) -> CoverageReport:
    category_counter = Counter(record.risk_category for record in records)
    attack_type_counter = Counter(record.attack_type for record in records)
    source_counter = Counter(record.source for record in records)
    mutation_counter = Counter(record.mutation_strategy or "none" for record in records)
    interaction_counter = Counter(record.interaction_type for record in records)
    workflow_counter = Counter(record.workflow_id or "unspecified" for record in records)
    asset_counter = Counter(record.protected_asset or "unspecified" for record in records)
    objective_counter = Counter(record.attack_objective or "unspecified" for record in records)
    scenario_counter = Counter(record.threat_scenario_id or "unspecified" for record in records)
    chain_counter = Counter(" -> ".join(record.mutation_chain) if record.mutation_chain else "unspecified" for record in records)
    workflow_risk_counter = Counter(
        f"{record.workflow_id or 'unspecified'}::{record.risk_category}" for record in records
    )
    workflow_attack_type_counter = Counter(
        f"{record.workflow_id or 'unspecified'}::{record.attack_type}" for record in records
    )
    category_names = {category.name: category.category_id for category in categories}
    covered_names = set(category_counter)
    missing = sorted(category_id for name, category_id in category_names.items() if name not in covered_names)
    covered_workflows = set(workflow_counter) - {"unspecified"}
    expected_workflows = set(workflow_ids or [])
    missing_workflows = sorted(expected_workflows - covered_workflows)
    max_depth = max((record.mutation_depth for record in records), default=0)
    return CoverageReport(
        total_records=len(records),
        categories=dict(sorted(category_counter.items())),
        attack_types=dict(sorted(attack_type_counter.items())),
        sources=dict(sorted(source_counter.items())),
        mutation_strategies=dict(sorted(mutation_counter.items())),
        interaction_types=dict(sorted(interaction_counter.items())),
        workflows=dict(sorted(workflow_counter.items())),
        protected_assets=dict(sorted(asset_counter.items())),
        attack_objectives=dict(sorted(objective_counter.items())),
        threat_scenarios=dict(sorted(scenario_counter.items())),
        mutation_chains=dict(sorted(chain_counter.items())),
        workflow_risk_matrix=dict(sorted(workflow_risk_counter.items())),
        workflow_attack_type_matrix=dict(sorted(workflow_attack_type_counter.items())),
        max_mutation_depth=max_depth,
        missing_category_ids=missing,
        missing_workflow_ids=missing_workflows,
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
            "workflow_record_count": report.workflows.get(record.workflow_id or "unspecified", 0),
            "protected_asset_record_count": report.protected_assets.get(record.protected_asset or "unspecified", 0),
            "attack_objective_record_count": report.attack_objectives.get(record.attack_objective or "unspecified", 0),
            "threat_scenario_record_count": report.threat_scenarios.get(record.threat_scenario_id or "unspecified", 0),
            "mutation_chain_record_count": report.mutation_chains.get(
                " -> ".join(record.mutation_chain) if record.mutation_chain else "unspecified",
                0,
            ),
            "workflow_risk_record_count": report.workflow_risk_matrix.get(
                f"{record.workflow_id or 'unspecified'}::{record.risk_category}",
                0,
            ),
            "lineage_depth": record.mutation_depth,
        }
        traced.append(AttackRecord.model_validate(data))
    return traced
