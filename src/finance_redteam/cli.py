from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from .builder import build_records_from_config, export_build_result
from .config import BenchmarkConfig, DEFAULT_CONFIG_PATH, OutputConfig, load_benchmark_config
from .deduplicator import deduplicate_records
from .deepteam_adapter import DeepTeamExpansionConfig, generate_deepteam_variants
from .domain_pack_template import create_domain_pack_template
from .exporters import export_jsonl, load_jsonl
from .garak_adapter import GarakExpansionConfig, run_garak_scan
from .garak_corpus import (
    GarakCorpusConfig,
    extract_garak_corpus_candidates,
    garak_candidates_to_seed_prompts,
    reduce_garak_corpus_candidates,
)
from .local_generator import generate_local_variants, seeds_to_records
from .normalizer import normalize_record
from .promptfoo_exporter import export_promptfoo
from .domain_pack import get_domain_pack
from .seed_prompts import DEFAULT_SEEDS_PATH, build_seed_authoring_starter, build_seed_prompts, load_seed_prompts, write_seed_prompts
from .seed_sources import collect_seed_source_items, seed_source_items_to_seed_prompts
from .taxonomy import DEFAULT_FRAMEWORK_MAPPINGS_PATH, DEFAULT_TAXONOMY_PATH, load_taxonomy, write_framework_mappings, write_taxonomy
from .validator import validate_records

app = typer.Typer(help="Build a static finance-domain LLM red-team benchmark.")


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def _build_records(
    min_per_category: int,
    max_per_category: int,
    use_deepteam: bool,
    use_garak: bool,
) -> list:
    config = BenchmarkConfig(
        min_per_category=min_per_category,
        max_per_category=max_per_category,
        use_deepteam=use_deepteam,
        use_garak=use_garak,
    )
    result = build_records_from_config(config)
    return result.records


@app.command()
def build(
    output: Path = typer.Option(Path("data/exports/finance_redteam_attacks.jsonl")),
    promptfoo_output: Path = typer.Option(Path("data/exports/promptfoo_tests.yaml")),
    min_per_category: int = typer.Option(5),
    max_per_category: int = typer.Option(10),
    use_deepteam: bool = typer.Option(False),
    use_garak: bool = typer.Option(False),
) -> None:
    _setup_logging()
    config = BenchmarkConfig(
        min_per_category=min_per_category,
        max_per_category=max_per_category,
        use_deepteam=use_deepteam,
        use_garak=use_garak,
        output=OutputConfig(jsonl=output, promptfoo_yaml=promptfoo_output),
    )
    result = build_records_from_config(config)
    for warning in result.validation.review_warnings:
        logging.warning("Review warning: %s", warning)
    if not result.validation.valid:
        for error in result.validation.errors:
            logging.error(error)
        raise typer.Exit(code=1)
    export_build_result(result, config)
    typer.echo(f"Exported {len(result.records)} records to {output}")
    typer.echo(f"Exported Promptfoo config to {promptfoo_output}")
    typer.echo(f"Wrote run metadata to {config.output.run_metadata_json}")


@app.command("build-from-config")
def build_from_config(config_path: Path = typer.Argument(DEFAULT_CONFIG_PATH)) -> None:
    _setup_logging()
    config = load_benchmark_config(config_path)
    result = build_records_from_config(config)
    for warning in result.validation.review_warnings:
        logging.warning("Review warning: %s", warning)
    if not result.validation.valid:
        for error in result.validation.errors:
            logging.error(error)
        raise typer.Exit(code=1)
    export_build_result(result, config)
    typer.echo(f"Exported {len(result.records)} records to {config.output.jsonl}")
    typer.echo(f"Exported Promptfoo config to {config.output.promptfoo_yaml}")
    typer.echo(f"Wrote run metadata to {config.output.run_metadata_json}")


@app.command("generate-taxonomy")
def generate_taxonomy() -> None:
    write_taxonomy()
    write_framework_mappings()
    typer.echo(f"Wrote {DEFAULT_TAXONOMY_PATH} and {DEFAULT_FRAMEWORK_MAPPINGS_PATH}")


@app.command("generate-seeds")
def generate_seeds(per_category: int = 5) -> None:
    write_taxonomy()
    write_seed_prompts(per_category=per_category)
    typer.echo(f"Wrote {DEFAULT_SEEDS_PATH}")


@app.command("seed-starter")
def seed_starter(domain_pack: str = typer.Option("banking_finance")) -> None:
    pack = get_domain_pack(domain_pack)
    starter = build_seed_authoring_starter(pack)
    typer.echo(json.dumps(starter, indent=2))


@app.command("create-domain-pack-template")
def create_domain_pack_template_command(
    domain_id: str = typer.Option(..., help="Stable domain id, for example healthcare, insurance, hr, legal."),
    display_name: str = typer.Option(..., help="Human-readable domain name."),
    description: str | None = typer.Option(None, help="Short description of the assistant/domain workflow."),
    output_root: Path = typer.Option(Path("."), help="Project root where files should be generated."),
    persona: list[str] | None = typer.Option(None, "--persona", help="Repeatable persona option."),
    context: list[str] | None = typer.Option(None, "--context", help="Repeatable workflow/context option."),
    risk_count: int = typer.Option(10, min=3, max=10, help="Number of starter risk categories to create."),
    overwrite: bool = typer.Option(False, help="Overwrite an existing generated pack/config."),
) -> None:
    result = create_domain_pack_template(
        domain_id=domain_id,
        display_name=display_name,
        description=description,
        output_root=output_root,
        personas=persona,
        contexts=context,
        risk_count=risk_count,
        overwrite=overwrite,
    )
    typer.echo(
        json.dumps(
            {
                "domain_pack": str(result.domain_pack_path),
                "config": str(result.config_path),
                "taxonomy": str(result.taxonomy_path),
                "seeds": str(result.seeds_path),
                "next_commands": [
                    f"python -m finance_redteam.cli seed-starter --domain-pack {result.domain_pack_path}",
                    f"python -m finance_redteam.cli build-from-config {result.config_path}",
                ],
            },
            indent=2,
        )
    )


@app.command("ingest-seed-sources")
def ingest_seed_sources(
    domain_pack: str = typer.Option("banking_finance"),
    sources: list[str] | None = typer.Option(None),
    manual_yaml_path: Path | None = typer.Option(None),
    max_items: int = typer.Option(50),
) -> None:
    pack = get_domain_pack(domain_pack)
    categories = load_taxonomy(pack.taxonomy_path, domain_pack=pack)
    selected_sources = sources or ["owasp", "mitre_atlas", "garak"]
    items = collect_seed_source_items(selected_sources, pack, manual_yaml_path)
    seeds = seed_source_items_to_seed_prompts(items, categories, pack, max_items=max_items)
    typer.echo(json.dumps({"source_items": len(items), "seed_prompts": [seed.model_dump() for seed in seeds]}, indent=2))


@app.command("preview-garak-corpus")
def preview_garak_corpus(
    domain_pack: str = typer.Option("banking_finance"),
    probe: list[str] | None = typer.Option(None, "--probe", help="Repeatable Garak probe/module allowlist item."),
    max_total_seeds: int = typer.Option(20),
    max_per_probe: int = typer.Option(5),
) -> None:
    pack = get_domain_pack(domain_pack)
    categories = load_taxonomy(pack.taxonomy_path, domain_pack=pack)
    cfg = GarakCorpusConfig(
        enabled=True,
        probe_allowlist=probe or GarakCorpusConfig().probe_allowlist,
        max_total_seeds=max_total_seeds,
        max_per_probe=max_per_probe,
    )
    raw = extract_garak_corpus_candidates(pack, cfg)
    reduced = reduce_garak_corpus_candidates(raw, cfg)
    seeds = garak_candidates_to_seed_prompts(reduced, categories, pack)
    typer.echo(
        json.dumps(
            {
                "domain_pack": pack.domain_id,
                "raw_candidates": len(raw),
                "reduced_candidates": len(reduced),
                "seed_prompts": len(seeds),
                "preview": [seed.model_dump() for seed in seeds[:5]],
            },
            indent=2,
            default=str,
        )
    )


@app.command("expand-deepteam")
def expand_deepteam(
    input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl"),
    vulnerabilities: list[str] | None = typer.Option(None),
    attack_types: list[str] | None = typer.Option(None),
    generation_mode: str = typer.Option("local_template"),
    simulator_provider: str = typer.Option("openai"),
    simulator_model: str = typer.Option("gpt-4.1-nano"),
    api_key_env: str = typer.Option("OPENAI_API_KEY"),
    max_seed_records: int = typer.Option(20),
    variants_per_seed: int = typer.Option(1),
    attacks_per_vulnerability_type: int = typer.Option(1),
    max_llm_records: int = typer.Option(20),
) -> None:
    records = load_jsonl(input_path)
    variants = generate_deepteam_variants(
        records,
        expansion_config=DeepTeamExpansionConfig(
            generation_mode=generation_mode,
            simulator_provider=simulator_provider,
            simulator_model=simulator_model,
            api_key_env=api_key_env,
            vulnerabilities=vulnerabilities or [],
            attack_types=attack_types or [],
            max_seed_records=max_seed_records,
            variants_per_seed=variants_per_seed,
            attacks_per_vulnerability_type=attacks_per_vulnerability_type,
            max_llm_records=max_llm_records,
        ),
    )
    export_jsonl(variants, Path("data/generated/deepteam_variants.jsonl"))
    typer.echo(f"Wrote {len(variants)} DeepTeam variants")


@app.command("run-garak")
def run_garak(
    target_model: str | None = None,
    probe_families: list[str] | None = typer.Option(None),
    attack_types: list[str] | None = typer.Option(None),
    risk_categories: list[str] | None = typer.Option(None),
    min_difficulty: int | None = None,
    max_difficulty: int | None = None,
    max_patterns: int = 20,
) -> None:
    records = run_garak_scan(
        target_model=target_model,
        expansion_config=GarakExpansionConfig(
            probe_families=probe_families or [],
            attack_types=attack_types or [],
            risk_categories=risk_categories or [],
            min_difficulty=min_difficulty,
            max_difficulty=max_difficulty,
            max_patterns=max_patterns,
        ),
    )
    export_jsonl(records, Path("data/generated/garak_patterns.jsonl"))
    typer.echo(f"Wrote {len(records)} Garak-derived patterns")


@app.command("export-promptfoo")
def export_promptfoo_command(
    input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl"),
    output_path: Path = Path("data/exports/promptfoo_tests.yaml"),
    provider: str = typer.Option("openai"),
    model: str = typer.Option("gpt-4.1-nano"),
) -> None:
    records = load_jsonl(input_path)
    export_promptfoo(records, output_path, provider=provider, model=model)
    typer.echo(f"Wrote {output_path}")


@app.command("validate")
def validate(input_path: Path = Path("data/exports/finance_redteam_attacks.jsonl")) -> None:
    records = load_jsonl(input_path)
    result = validate_records(records)
    for warning in result.review_warnings:
        typer.echo(f"WARNING: {warning}")
    if not result.valid:
        for error in result.errors:
            typer.echo(f"ERROR: {error}")
        raise typer.Exit(code=1)
    typer.echo(f"Validated {len(records)} records")


if __name__ == "__main__":
    app()
