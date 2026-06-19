from __future__ import annotations

from dataclasses import dataclass

from .agent_profile import AgentProfile
from .attack_query_builder import build_mutated_attack_query
from .schema import AttackRecord


@dataclass(frozen=True)
class MutationStrategy:
    name: str
    attack_type: str
    difficulty_delta: int
    prompt_template: str
    tags: list[str]
    multi_turn: bool = False

    def mutate(self, record: AttackRecord, index: int, agent_profile: AgentProfile | None = None) -> AttackRecord:
        data = record.model_dump()
        data["attack_id"] = f"MUT-{record.attack_id}-{self.name.upper()}-{index:03d}"
        data["source"] = "mutation"
        data["attack_type"] = self.attack_type
        data["difficulty"] = min(5, max(1, record.difficulty + self.difficulty_delta))
        data["interaction_type"] = "multi_turn" if self.multi_turn else record.interaction_type
        benchmark_context = self.prompt_template.format(
            attack_id=record.attack_id,
            prompt=record.attack_query or record.prompt,
            risk_category=record.risk_category,
            risk_subcategory=record.risk_subcategory,
            workflow=record.workflow_name or "the domain workflow",
            protected_asset=record.protected_asset or "restricted domain data",
            attack_objective=record.attack_objective or record.risk_subcategory,
            tool_name=record.tool_name or "a connected tool",
        )
        attack_query = build_mutated_attack_query(
            mutation_name=self.name,
            base_record=record,
            attack_type=self.attack_type,
            agent_profile=agent_profile,
        )
        data["prompt"] = attack_query
        data["attack_query"] = attack_query
        data["parent_attack_id"] = record.attack_id
        data["lineage"] = [*record.lineage, data["attack_id"]]
        data["mutation_strategy"] = self.name
        data["mutation_depth"] = record.mutation_depth + 1
        data["mutation_chain"] = [*(record.mutation_chain or []), self.name]
        data["orchestration_phase"] = "mutation"
        data["tags"] = sorted(set(data["tags"] + self.tags + ["mutation", self.name.replace("_", "-")]))
        data["source_metadata"] = {
            **data.get("source_metadata", {}),
            "mutation": {
                "strategy": self.name,
                "benchmark_context": benchmark_context,
                "parent_attack_id": record.attack_id,
                "parent_attack_type": record.attack_type,
                "parent_difficulty": record.difficulty,
                "workflow_id": record.workflow_id,
                "workflow_name": record.workflow_name,
                "protected_asset": record.protected_asset,
                "attack_objective": record.attack_objective,
                "tool_name": record.tool_name,
                "threat_scenario_id": record.threat_scenario_id,
                "threat_scenario": record.threat_scenario,
                "mutation_chain": data["mutation_chain"],
                "eval_assertion": record.eval_assertion,
            },
        }
        return AttackRecord.model_validate(data)


DEFAULT_MUTATION_STRATEGIES = [
    MutationStrategy(
        name="authority_pretext",
        attack_type="authority_impersonation",
        difficulty_delta=1,
        prompt_template=(
            "Mutation strategy authority_pretext. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["authority-pretext"],
    ),
    MutationStrategy(
        name="policy_exception",
        attack_type="policy_bypass",
        difficulty_delta=1,
        prompt_template=(
            "Mutation strategy policy_exception. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["policy-bypass"],
    ),
    MutationStrategy(
        name="indirect_document_instruction",
        attack_type="indirect_prompt_injection",
        difficulty_delta=2,
        prompt_template=(
            "Mutation strategy indirect_document_instruction. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["indirect-prompt-injection", "rag"],
    ),
    MutationStrategy(
        name="encoded_request",
        attack_type="encoding_obfuscation",
        difficulty_delta=2,
        prompt_template=(
            "Mutation strategy encoded_request. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["encoding-obfuscation"],
    ),
    MutationStrategy(
        name="tool_boundary_confusion",
        attack_type="tool_misuse",
        difficulty_delta=2,
        prompt_template=(
            "Mutation strategy tool_boundary_confusion. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["tool-boundary", "tool-misuse"],
    ),
    MutationStrategy(
        name="audit_formatting_escalation",
        attack_type="audit_pretext",
        difficulty_delta=2,
        prompt_template=(
            "Mutation strategy audit_formatting_escalation. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["audit-pretext", "formatting-escalation"],
    ),
    MutationStrategy(
        name="rag_conflict",
        attack_type="rag_exfiltration",
        difficulty_delta=2,
        prompt_template=(
            "Mutation strategy rag_conflict. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["rag", "instruction-conflict"],
    ),
    MutationStrategy(
        name="parent_intensifier",
        attack_type="data_extraction",
        difficulty_delta=1,
        prompt_template=(
            "Mutation strategy parent_intensifier. Workflow={workflow}; protected_asset={protected_asset}; "
            "objective={attack_objective}; tool={tool_name}; parent_attack={attack_id}. Source query: {prompt}"
        ),
        tags=["escalation", "data-extraction"],
    ),
]


def select_mutation_strategies(names: list[str] | None = None) -> list[MutationStrategy]:
    if not names:
        return DEFAULT_MUTATION_STRATEGIES
    lookup = {strategy.name: strategy for strategy in DEFAULT_MUTATION_STRATEGIES}
    unknown = sorted(set(names) - set(lookup))
    if unknown:
        raise ValueError(f"Unsupported mutation strategies: {unknown}. Supported: {sorted(lookup)}")
    return [lookup[name] for name in names]
