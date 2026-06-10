from __future__ import annotations

from _bootstrap import add_src_to_path

add_src_to_path()

from finance_redteam.builder import build_records_from_config, export_build_result  # noqa: E402
from finance_redteam.config import DEFAULT_CONFIG_PATH, load_benchmark_config  # noqa: E402


if __name__ == "__main__":
    config = load_benchmark_config(DEFAULT_CONFIG_PATH)
    result = build_records_from_config(config)
    if not result.validation.valid:
        for error in result.validation.errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    export_build_result(result, config)
    print(f"Exported {len(result.records)} records to {config.output.jsonl}")
    print(f"Exported Promptfoo config to {config.output.promptfoo_yaml}")
    print(f"Wrote run metadata to {config.output.run_metadata_json}")
