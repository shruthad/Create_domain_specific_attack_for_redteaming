from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import BenchmarkConfig
from .coverage import CoverageReport, attach_coverage_trace, build_coverage_report
from .deduplicator import deduplicate_records
from .deepteam_adapter import generate_deepteam_variants
from .domain_pack import get_domain_pack
from .exporters import export_jsonl
from .garak_adapter import run_garak_scan
from .garak_corpus import (
    extract_garak_corpus_candidates,
    garak_candidates_to_seed_prompts,
    reduce_garak_corpus_candidates,
)
from .local_generator import generate_local_variants, seeds_to_records
from .llm_generator import generate_llm_variants
from .normalizer import normalize_record
from .orchestrator import orchestrate_mutations
from .promptfoo_exporter import export_promptfoo
from .provenance import GenerationRun, create_generation_run, stamp_records, write_run_metadata
from .schema import AttackRecord
from .seed_prompts import DEFAULT_SEEDS_PATH, build_seed_prompts, write_seed_prompt_records, write_seed_prompts
from .seed_sources import collect_seed_source_items, seed_source_items_to_seed_prompts
from .taxonomy import DEFAULT_FRAMEWORK_MAPPINGS_PATH, DEFAULT_TAXONOMY_PATH, load_taxonomy, write_framework_mappings, write_taxonomy
from .validator import ValidationResult, validate_records

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuildResult:
    records: list[AttackRecord]
    mutation_records: list[AttackRecord]
    llm_records: list[AttackRecord]
    deepteam_records: list[AttackRecord]
    garak_records: list[AttackRecord]
    validation: ValidationResult
    run: GenerationRun
    coverage: CoverageReport


def build_records_from_config(config: BenchmarkConfig) -> BuildResult:
    domain_pack = get_domain_pack(config.domain_pack)
    run = create_generation_run(config)
    write_taxonomy(domain_pack.taxonomy_path, domain_pack=domain_pack)
    write_framework_mappings(DEFAULT_FRAMEWORK_MAPPINGS_PATH)

    per_category = max(5, min(config.max_per_category, max(1, config.min_per_category)))
    write_seed_prompts(domain_pack.seeds_path, per_category=per_category, domain_pack=domain_pack)
    categories = load_taxonomy(domain_pack.taxonomy_path, domain_pack=domain_pack)
    seeds = build_seed_prompts(categories, per_category=per_category, domain_pack=domain_pack)
    if config.seed_sources.enabled:
        seed_source_items = collect_seed_source_items(
            config.seed_sources.sources,
            domain_pack,
            config.seed_sources.manual_yaml_path,
        )
        seeds.extend(
            seed_source_items_to_seed_prompts(
                seed_source_items,
                categories,
                domain_pack,
                max_items=config.seed_sources.max_items,
            )
        )
        write_seed_prompt_records(domain_pack.seeds_path, seeds)
    if config.garak_corpus.enabled:
        garak_corpus_config = config.garak_corpus.corpus_config()
        garak_candidates = extract_garak_corpus_candidates(domain_pack, garak_corpus_config)
        reduced_garak_candidates = reduce_garak_corpus_candidates(garak_candidates, garak_corpus_config)
        seeds.extend(garak_candidates_to_seed_prompts(reduced_garak_candidates, categories, domain_pack))
        write_seed_prompt_records(domain_pack.seeds_path, seeds)
    records = seeds_to_records(seeds, categories, source="seed", domain_pack=domain_pack)

    if len(records) < len(categories) * config.min_per_category:
        records.extend(generate_local_variants(categories, per_category=1, start_index=900, domain_pack=domain_pack))

    mutation_records: list[AttackRecord] = []
    if config.use_orchestrator:
        mutation_records = orchestrate_mutations(records, config.orchestration)
    records.extend(mutation_records)

    llm_records: list[AttackRecord] = []
    if config.use_llm_generator:
        llm_records = generate_llm_variants(records, config.llm_generator)
    records.extend(llm_records)

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
    coverage = build_coverage_report(deduped, categories)
    traced = attach_coverage_trace(deduped, coverage)
    stamped = stamp_records(traced, run)
    stamped_deepteam = stamp_records(deepteam_records, run)
    stamped_garak = stamp_records(garak_records, run)
    validation = validate_records(stamped)
    return BuildResult(
        records=stamped,
        mutation_records=stamp_records(mutation_records, run),
        llm_records=stamp_records(llm_records, run),
        deepteam_records=stamped_deepteam,
        garak_records=stamped_garak,
        validation=validation,
        run=run,
        coverage=coverage,
    )


def export_build_result(result: BuildResult, config: BenchmarkConfig) -> None:
    export_jsonl(result.mutation_records, config.output.mutations_jsonl)
    export_jsonl(result.llm_records, config.output.llm_jsonl)
    export_jsonl(result.deepteam_records, config.output.deepteam_jsonl)
    export_jsonl(result.garak_records, config.output.garak_jsonl)
    export_jsonl(result.records, config.output.jsonl)
    export_jsonl(result.records, config.output.normalized_jsonl)
    export_promptfoo(
        result.records,
        config.output.promptfoo_yaml,
        provider=config.evaluation.provider,
        model=config.evaluation.model,
    )
    write_run_metadata(config, result.run, config.output.run_metadata_json, len(result.records), result.coverage)
