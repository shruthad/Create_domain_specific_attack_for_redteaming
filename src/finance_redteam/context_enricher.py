from __future__ import annotations

from .domain_pack import DomainPack
from .schema import AttackRecord


def _category_id_from_attack_id(attack_id: str) -> str:
    parts = attack_id.split("-")
    return "-".join(parts[:2]).upper() if len(parts) >= 2 else ""


def enrich_missing_workflow_context(record: AttackRecord, domain_pack: DomainPack) -> AttackRecord:
    """Attach workflow/objective context to broad framework-derived records.

    OWASP/MITRE/Garak-style seed sources can be useful as starting signals, but
    they do not always carry domain workflow details. This function grounds those
    records in the domain pack before final query repair/export.
    """

    if record.workflow_id and record.attack_objective and record.protected_asset:
        return record

    category_id = _category_id_from_attack_id(record.attack_id)
    workflows = domain_pack.workflows_for_risk(category_id) or domain_pack.workflows
    workflow = workflows[0] if workflows else None
    objectives = domain_pack.objectives_for_risk(category_id) or domain_pack.attack_objectives
    objective = objectives[0] if objectives else None
    if not workflow:
        return record

    data = record.model_dump()
    data["workflow_id"] = data.get("workflow_id") or workflow.workflow_id
    data["workflow_name"] = data.get("workflow_name") or workflow.name
    data["protected_asset"] = data.get("protected_asset") or (
        workflow.protected_assets[0] if workflow.protected_assets else "restricted domain data"
    )
    data["tool_name"] = data.get("tool_name") or (
        workflow.tool_names[0] if workflow.tool_names else "a connected domain tool"
    )
    data["attack_objective"] = data.get("attack_objective") or (
        objective.name if objective else record.risk_subcategory
    )
    data["threat_scenario_id"] = data.get("threat_scenario_id") or f"ENRICHED-{workflow.workflow_id}-{category_id}"
    data["threat_scenario"] = data.get("threat_scenario") or (
        f"{record.risk_category} seed source grounded in {workflow.name}, targeting "
        f"{data['protected_asset']} through {data['tool_name']}."
    )
    data["mutation_chain"] = [*(data.get("mutation_chain") or []), "workflow_context_enrichment"]
    data["source_metadata"] = {
        **data.get("source_metadata", {}),
        "workflow_context_enrichment": {
            "category_id": category_id,
            "workflow_id": workflow.workflow_id,
            "workflow_name": workflow.name,
            "protected_asset": data["protected_asset"],
            "tool_name": data["tool_name"],
            "attack_objective": data["attack_objective"],
        },
    }
    return AttackRecord.model_validate(data)

