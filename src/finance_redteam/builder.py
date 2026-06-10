from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import BenchmarkConfig
from .deduplicator import deduplicate_records
from .deepteam_adapter import generate_deepteam_variants
from .exporters import export_jsonl
from .garak_adapter import run_garak_scan
from .local_generator import generate_local_variants, seeds_to_records
from .normalizer import normalize_record
from .promptfoo_exporter import export_promptfoo
from .provenance import GenerationRun, create_generation_run, stamp_records, write_run_metadata
from .schema import AttackRecord
from .seed_prompts import DEFAULT_SEEDS_PATH, build_seed_prompts, write_seed_prompts
from .taxonomy import DEFAULT_FRAMEWORK_MAPPINGS_PATH, DEFAULT_TAXONOMY_PATH, load_taxonomy, write_framework_mappings, write_taxonomy
from .validator import ValidationResult, validate_records

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuildResult:
    records: list[AttackRecord]
    deepteam_records: list[AttackRecord]
    garak_records: list[AttackRecord]
    validation: ValidationResult
    run: GenerationRun


def build_records_from_config(config: BenchmarkConfig) -> BuildResult:
    run = create_generation_run(config)
    write_taxonomy(DEFAULT_TAXONOMY_PATH)
    write_framework_mappings(DEFAULT_FRAMEWORK_MAPPINGS_PATH)

    per_category = max(5, min(config.max_per_category, max(1, config.min_per_category)))
    write_seed_prompts(DEFAULT_SEEDS_PATH, per_category=per_category)
    categories = load_taxonomy()
    seeds = build_seed_prompts(categories, per_category=per_category)
    records = seeds_to_records(seeds, categories, source="seed")

    if len(records) < len(categories) * config.min_per_category:
        records.extend(generate_local_variants(categories, per_category=1, start_index=900))

    deepteam_records: list[AttackRecord] = []
    if config.use_deepteam:
        deepteam_records = generate_deepteam_variants(
            records,
            auto_install=False,
            expansion_config=config.deepteam,
        )
    records.extend(deepteam_records)

    garak_records: list[AttackRecord] = []
    if config.use_garak or config.garak.enabled:
        garak_records = run_garak_scan(
            target_model=config.garak.target_model,
            auto_install=config.garak.auto_install,
            report_dir=config.garak.report_dir,
            max_findings=config.garak.max_findings,
            expansion_config=config.garak.expansion_config(),
        )
    records.extend(garak_records)

    normalized = [normalize_record(record) for record in records]
    deduped = deduplicate_records(normalized)
    stamped = stamp_records(deduped, run)
    stamped_deepteam = stamp_records(deepteam_records, run)
    stamped_garak = stamp_records(garak_records, run)
    validation = validate_records(stamped)
    return BuildResult(
        records=stamped,
        deepteam_records=stamped_deepteam,
        garak_records=stamped_garak,
        validation=validation,
        run=run,
    )


def export_build_result(result: BuildResult, config: BenchmarkConfig) -> None:
    export_jsonl(result.deepteam_records, config.output.deepteam_jsonl)
    export_jsonl(result.garak_records, config.output.garak_jsonl)
    export_jsonl(result.records, config.output.jsonl)
    export_jsonl(result.records, config.output.normalized_jsonl)
    export_promptfoo(result.records, config.output.promptfoo_yaml)
    write_run_metadata(config, result.run, config.output.run_metadata_json, len(result.records))
