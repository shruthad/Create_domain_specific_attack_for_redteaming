from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from finance_redteam.exporters import load_jsonl  # noqa: E402
from finance_redteam.promptfoo_exporter import export_promptfoo  # noqa: E402


def main() -> None:
    input_path = ROOT / "data" / "exports" / "finance_redteam_attacks.jsonl"
    output_path = ROOT / "data" / "exports" / "promptfoo_banking_agent_tests.yaml"
    records = load_jsonl(input_path)
    export_promptfoo(records, output_path, provider="local_banking_agent")
    print(f"Wrote {output_path.relative_to(ROOT)} with {len(records)} tests")


if __name__ == "__main__":
    main()
