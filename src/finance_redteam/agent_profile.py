from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class AgentTool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    allowed_uses: list[str] = Field(default_factory=list)
    forbidden_uses: list[str] = Field(default_factory=list)


class AgentProfile(BaseModel):
    """Deployment-specific context used to generate realistic attack prompts."""

    model_config = ConfigDict(extra="forbid")

    profile_id: str
    name: str
    purpose: str
    system_prompt_summary: str
    primary_users: list[str] = Field(default_factory=list)
    workflows: list[str] = Field(default_factory=list)
    tools: list[AgentTool] = Field(default_factory=list)
    protected_assets: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    dummy_records: dict[str, Any] = Field(default_factory=dict)
    realistic_pretexts: list[str] = Field(default_factory=list)
    refusal_style: str = (
        "Refuse unsafe or unauthorized requests, explain the boundary briefly, "
        "and redirect to safe banking support or compliance guidance."
    )

    @property
    def tool_names(self) -> list[str]:
        return [tool.name for tool in self.tools]


DEFAULT_AGENT_PROFILE_PATH = Path("configs/agent_profiles/banking_support_agent.yaml")


def load_agent_profile(path: Path | None) -> AgentProfile | None:
    if path is None:
        return None
    if not path.exists():
        raise FileNotFoundError(f"Agent profile not found: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AgentProfile.model_validate(payload)
