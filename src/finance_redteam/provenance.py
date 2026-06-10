from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import BenchmarkConfig, config_hash, dump_config_payload
from .schema import AttackRecord


@dataclass(frozen=True)
class GenerationRun:
    run_id: str
    generated_at: str
    dataset_version: str
    config_hash: str


def create_generation_run(config: BenchmarkConfig) -> GenerationRun:
    return GenerationRun(
        run_id=f"run-{uuid.uuid4().hex[:12]}",
        generated_at=datetime.now(timezone.utc).isoformat(),
        dataset_version=config.dataset_version,
        config_hash=config_hash(config),
    )


def stamp_records(records: list[AttackRecord], run: GenerationRun) -> list[AttackRecord]:
    stamped: list[AttackRecord] = []
    for record in records:
        data = record.model_dump()
        data["dataset_version"] = run.dataset_version
        data["generation_run_id"] = run.run_id
        data["generated_at"] = run.generated_at
        data["generator_config_hash"] = run.config_hash
        stamped.append(AttackRecord.model_validate(data))
    return stamped


def write_run_metadata(config: BenchmarkConfig, run: GenerationRun, output_path: Path, record_count: int) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run.run_id,
        "generated_at": run.generated_at,
        "dataset_version": run.dataset_version,
        "generator_config_hash": run.config_hash,
        "record_count": record_count,
        "config": dump_config_payload(config),
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
