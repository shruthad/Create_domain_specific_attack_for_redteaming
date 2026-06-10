from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .deepteam_adapter import DeepTeamExpansionConfig
from .garak_adapter import GarakExpansionConfig


DEFAULT_CONFIG_PATH = Path("configs/finance_benchmark.yaml")


class GarakConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    auto_install: bool = False
    target_model: str | None = None
    max_findings: int = 10
    report_dir: Path = Path("data/generated/garak_reports")
    probe_families: list[str] = Field(default_factory=list)
    attack_types: list[str] = Field(default_factory=list)
    risk_categories: list[str] = Field(default_factory=list)
    min_difficulty: int | None = None
    max_difficulty: int | None = None
    max_patterns: int = 20
    include_static_patterns: bool = True
    include_parsed_findings: bool = True

    def expansion_config(self) -> GarakExpansionConfig:
        return GarakExpansionConfig(
            probe_families=self.probe_families,
            attack_types=self.attack_types,
            risk_categories=self.risk_categories,
            min_difficulty=self.min_difficulty,
            max_difficulty=self.max_difficulty,
            max_patterns=self.max_patterns,
            include_static_patterns=self.include_static_patterns,
            include_parsed_findings=self.include_parsed_findings,
        )


class EvaluationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    max_concurrency: int = 1
    delay_ms: int = 5000
    smoke_test_count: int = 1


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jsonl: Path = Path("data/exports/finance_redteam_attacks.jsonl")
    promptfoo_yaml: Path = Path("data/exports/promptfoo_tests.yaml")
    normalized_jsonl: Path = Path("data/generated/normalized_attacks.jsonl")
    deepteam_jsonl: Path = Path("data/generated/deepteam_variants.jsonl")
    garak_jsonl: Path = Path("data/generated/garak_patterns.jsonl")
    run_metadata_json: Path = Path("data/generated/run_metadata.json")


class BenchmarkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = "banking_finance"
    dataset_version: str = "1.0.0"
    min_per_category: int = Field(default=5, ge=1)
    max_per_category: int = Field(default=10, ge=1)
    use_deepteam: bool = False
    use_garak: bool = False
    deepteam: DeepTeamExpansionConfig = Field(default_factory=DeepTeamExpansionConfig)
    garak: GarakConfig = Field(default_factory=GarakConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def load_benchmark_config(path: Path = DEFAULT_CONFIG_PATH) -> BenchmarkConfig:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return BenchmarkConfig.model_validate(data)


def dump_config_payload(config: BenchmarkConfig) -> dict[str, Any]:
    return config.model_dump(mode="json")


def config_hash(config: BenchmarkConfig) -> str:
    payload = json.dumps(dump_config_payload(config), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
