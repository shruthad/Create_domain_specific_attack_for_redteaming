from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .deepteam_adapter import DeepTeamExpansionConfig
from .garak_adapter import GarakExpansionConfig
from .garak_corpus import DEFAULT_GARAK_PROBE_ALLOWLIST, GarakCorpusConfig
from .llm_generator import LLMGeneratorConfig
from .orchestrator import OrchestrationConfig


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

    provider: str = "openai"
    model: str = "gpt-4.1-nano"
    max_concurrency: int = 1
    delay_ms: int = 1000
    smoke_test_count: int = 1


class SeedSourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    sources: list[str] = Field(default_factory=lambda: ["owasp", "mitre_atlas", "garak"])
    manual_yaml_path: Path | None = None
    max_items: int = 50


class GarakCorpusSeedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    probe_allowlist: list[str] = Field(default_factory=lambda: list(DEFAULT_GARAK_PROBE_ALLOWLIST))
    max_raw_candidates: int = 5000
    max_per_probe: int = 20
    max_per_category: int = 20
    max_total_seeds: int = 80
    min_prompt_chars: int = 18
    max_prompt_chars: int = 1200
    include_data_files: bool = True
    include_probe_source_strings: bool = True
    domain_terms: list[str] = Field(default_factory=list)
    excluded_terms: list[str] = Field(default_factory=list)

    def corpus_config(self) -> GarakCorpusConfig:
        base = GarakCorpusConfig()
        return GarakCorpusConfig(
            enabled=self.enabled,
            probe_allowlist=self.probe_allowlist,
            max_raw_candidates=self.max_raw_candidates,
            max_per_probe=self.max_per_probe,
            max_per_category=self.max_per_category,
            max_total_seeds=self.max_total_seeds,
            min_prompt_chars=self.min_prompt_chars,
            max_prompt_chars=self.max_prompt_chars,
            include_data_files=self.include_data_files,
            include_probe_source_strings=self.include_probe_source_strings,
            domain_terms=self.domain_terms,
            excluded_terms=self.excluded_terms or base.excluded_terms,
        )


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jsonl: Path = Path("data/exports/finance_redteam_attacks.jsonl")
    promptfoo_yaml: Path = Path("data/exports/promptfoo_tests.yaml")
    normalized_jsonl: Path = Path("data/generated/normalized_attacks.jsonl")
    mutations_jsonl: Path = Path("data/generated/mutation_variants.jsonl")
    llm_jsonl: Path = Path("data/generated/llm_variants.jsonl")
    deepteam_jsonl: Path = Path("data/generated/deepteam_variants.jsonl")
    garak_jsonl: Path = Path("data/generated/garak_patterns.jsonl")
    run_metadata_json: Path = Path("data/generated/run_metadata.json")


class BenchmarkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = "banking_finance"
    domain_pack: str = "banking_finance"
    dataset_version: str = "1.0.0"
    min_per_category: int = Field(default=5, ge=1)
    max_per_category: int = Field(default=10, ge=1)
    use_orchestrator: bool = True
    use_llm_generator: bool = False
    use_deepteam: bool = False
    use_garak: bool = False
    seed_sources: SeedSourceConfig = Field(default_factory=SeedSourceConfig)
    garak_corpus: GarakCorpusSeedConfig = Field(default_factory=GarakCorpusSeedConfig)
    orchestration: OrchestrationConfig = Field(default_factory=OrchestrationConfig)
    llm_generator: LLMGeneratorConfig = Field(default_factory=LLMGeneratorConfig)
    deepteam: DeepTeamExpansionConfig = Field(default_factory=DeepTeamExpansionConfig)
    garak: GarakConfig = Field(default_factory=GarakConfig)
    evaluation: EvaluationConfig = Field(default_factory=EvaluationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def load_benchmark_config(path: Path = DEFAULT_CONFIG_PATH) -> BenchmarkConfig:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    domain_pack = data.get("domain_pack")
    if isinstance(domain_pack, str) and ("/" in domain_pack or "\\" in domain_pack or domain_pack.endswith(".yaml")):
        domain_pack_path = Path(domain_pack)
        if not domain_pack_path.is_absolute():
            domain_pack_path = (path.parent / domain_pack_path).resolve()
        data["domain_pack"] = str(domain_pack_path)
    return BenchmarkConfig.model_validate(data)


def dump_config_payload(config: BenchmarkConfig) -> dict[str, Any]:
    return config.model_dump(mode="json")


def config_hash(config: BenchmarkConfig) -> str:
    payload = json.dumps(dump_config_payload(config), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
