from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


AttackType = Literal[
    "direct_request",
    "roleplay",
    "authority_impersonation",
    "audit_pretext",
    "developer_override",
    "system_prompt_extraction",
    "policy_bypass",
    "encoding_obfuscation",
    "multi_turn_setup",
    "indirect_prompt_injection",
    "rag_exfiltration",
    "tool_misuse",
    "jailbreak",
    "data_extraction",
    "hypothetical_scenario",
    "translation_attack",
    "summarization_attack",
]

InteractionType = Literal["single_turn", "multi_turn"]
SourceType = Literal["seed", "deepteam", "garak", "local_template", "mutation", "orchestrator", "llm"]


class TaxonomyCategory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category_id: str
    name: str
    description: str
    domain_examples: list[str] = Field(validation_alias=AliasChoices("domain_examples", "finance_examples"))
    owasp_mapping: list[str]
    mitre_atlas_mapping: list[str]
    nist_ai_rmf_mapping: list[str]
    severity: Literal["low", "medium", "high", "critical"]
    default_expected_behavior: str


class SeedPrompt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category_id: str
    attack_type: AttackType
    difficulty: int = Field(ge=1, le=5)
    prompt: str
    expected_behavior: str
    unsafe_success_criteria: str
    tags: list[str] = Field(default_factory=list)
    seed_source: str = "domain_pack"
    source_reference: str | None = None
    source_metadata: dict[str, Any] = Field(default_factory=dict)


class AttackRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    domain: str = "banking_finance"
    risk_category: str
    risk_subcategory: str
    owasp_mapping: list[str]
    mitre_atlas_mapping: list[str]
    nist_ai_rmf_mapping: list[str]
    domain_mapping: list[str] | None = None
    finance_domain_mapping: list[str] | None = None
    attack_type: AttackType
    interaction_type: InteractionType
    difficulty: int = Field(ge=1, le=5)
    source: SourceType
    prompt: str
    attack_query: str | None = None
    expected_behavior: str
    unsafe_success_criteria: str
    safe_response_guidance: str
    tags: list[str]
    created_by: str = "system"
    version: str = "1.0.0"
    dataset_version: str = "1.0.0"
    generation_run_id: str = "manual"
    generated_at: str = "manual"
    generator_config_hash: str = "manual"
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    review_flags: list[str] = Field(default_factory=list)
    parent_attack_id: str | None = None
    lineage: list[str] = Field(default_factory=list)
    mutation_strategy: str | None = None
    mutation_depth: int = Field(default=0, ge=0)
    orchestration_phase: str | None = None
    coverage_trace: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def populate_derived_fields(self) -> "AttackRecord":
        if self.attack_query and self.attack_query.strip():
            self.attack_query = self.attack_query.strip()
        else:
            prompt = self.prompt.strip()
            if "Evaluation input:" in prompt:
                query = prompt.split("Evaluation input:", 1)[1].strip()
                query = query.split("Expected behavior remains", 1)[0].strip()
                self.attack_query = query.rstrip(". ")
            elif prompt.startswith("Garak coverage pattern for defensive evaluation:"):
                self.attack_query = prompt.split(":", 1)[1].strip()
            else:
                self.attack_query = prompt

        if self.domain_mapping is None and self.finance_domain_mapping is not None:
            self.domain_mapping = list(self.finance_domain_mapping)
        if self.finance_domain_mapping is None and self.domain == "banking_finance" and self.domain_mapping is not None:
            self.finance_domain_mapping = list(self.domain_mapping)
        if not self.lineage:
            self.lineage = [self.attack_id]
        elif self.attack_id not in self.lineage:
            self.lineage = [*self.lineage, self.attack_id]
        return self

    @field_validator(
        "attack_id",
        "risk_category",
        "risk_subcategory",
        "prompt",
        "attack_query",
        "expected_behavior",
        "unsafe_success_criteria",
        "safe_response_guidance",
    )
    @classmethod
    def non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value or not value.strip():
            raise ValueError("field must be non-empty")
        return value.strip()

    @field_validator(
        "owasp_mapping",
        "mitre_atlas_mapping",
        "nist_ai_rmf_mapping",
        "tags",
    )
    @classmethod
    def non_empty_list(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("list field must contain at least one value")
        return cleaned

    @field_validator("domain_mapping", "finance_domain_mapping")
    @classmethod
    def optional_non_empty_list(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("list field must contain at least one value")
        return cleaned
