# Finance LLM Red-Team Benchmark

This repository provides a reusable notebook-driven utility for creating and evaluating a banking and finance-domain LLM red-team benchmark dataset.

It is designed for defensive AI safety evaluation, model governance, compliance testing, and repeatable red-team benchmarking. The generated prompts are evaluation inputs that test whether a model refuses unsafe requests, protects sensitive data, avoids unsupported financial claims, and redirects users to lawful, privacy-preserving, compliance-safe guidance.

The main dataset output is:

```text
data/exports/finance_redteam_attacks.jsonl
```

The main evaluation config output is:

```text
data/exports/promptfoo_tests.yaml
```

## What This Project Does

The project builds a domain-specific red-team dataset through this pipeline:

```text
Finance risk taxonomy
-> safe seed prompts
-> structured benchmark records
-> optional DeepTeam expansion
-> optional Garak coverage patterns
-> normalization
-> deduplication
-> validation
-> JSONL export
-> Promptfoo evaluation
```

The default workflow is local and deterministic. It does not require paid APIs.

Optional integrations:

- DeepTeam: expands seed prompts into adversarial variations.
- Garak: adds scanner-style coverage patterns.
- Promptfoo: evaluates generated attacks against a target model such as Gemini.

## Defensive-Use Notice

This project is for authorized defensive testing only.

The dataset should not be used to generate or operationalize fraud, phishing, money laundering, credential theft, account takeover, market manipulation, AML/KYC evasion, insider trading, or other real-world harm.

Prompts are intentionally framed as test inputs. Expected behavior requires refusal, safe redirection, privacy protection, or compliance-safe guidance.

## Repository Contents

Important files:

```text
README.md
.env.example
.gitignore
requirements.txt
pyproject.toml

configs/
  finance_benchmark.yaml
  finance_benchmark.deepteam_llm.yaml

notebooks/
  01_create_expand_dataset.ipynb
  02_evaluate_attacks_gemini.ipynb

src/finance_redteam/
scripts/
tests/

data/taxonomy/
data/seeds/
data/exports/

providers/gemini_rest_provider.js
package.json
package-lock.json
```

Do not commit:

```text
.env
.venv/
node_modules/
.pytest_cache/
__pycache__/
data/generated/
.promptfoo/
```

## Installation

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows activation:

```bash
.venv\Scripts\activate
```

Optional Promptfoo install:

```bash
npm install
```

## Environment Setup

Copy `.env.example` to `.env` only when you need provider-backed generation or evaluation.

Example:

```bash
GOOGLE_API_KEY=your_key_here
```

Never commit `.env`.

## Main Configs

### Local Production Config

```text
configs/finance_benchmark.yaml
```

Use this for the standard deterministic build. This is the recommended default for stakeholders, demos, and reproducible dataset generation.

Typical behavior:

- No external LLM call
- No paid API required
- Creates the baseline finance red-team benchmark
- Exports JSONL and Promptfoo YAML

### Live DeepTeam Gemini Config

```text
configs/finance_benchmark.deepteam_llm.yaml
```

Use this only when you want DeepTeam to generate LLM-backed attack variations with Gemini.

This requires:

- `GOOGLE_API_KEY` in `.env`
- Network access
- Available Gemini quota
- Human review of generated records

## Notebook 01: Create And Expand Dataset

Open:

```text
notebooks/01_create_expand_dataset.ipynb
```

Run cells from top to bottom.

The notebook:

1. Loads the selected YAML config.
2. Generates the finance taxonomy and seed prompts.
3. Converts prompts into structured benchmark records.
4. Optionally expands records with DeepTeam.
5. Optionally adds Garak coverage patterns.
6. Normalizes and deduplicates records.
7. Validates schema and safety rules.
8. Exports JSONL and Promptfoo YAML.

Default outputs:

```text
data/exports/finance_redteam_attacks.jsonl
data/exports/promptfoo_tests.yaml
```

## Notebook 02: Evaluate Against Gemini

Open:

```text
notebooks/02_evaluate_attacks_gemini.ipynb
```

Use this notebook after Notebook 01 has generated the dataset.

The notebook:

1. Checks that exported files exist.
2. Validates the dataset locally.
3. Loads `GOOGLE_API_KEY` from `.env`.
4. Lists available Gemini models.
5. Tests the Gemini key.
6. Runs a small Promptfoo evaluation first.
7. Allows a larger evaluation after the small run succeeds.

Start with the small evaluation before running the full benchmark to avoid wasting quota on a bad provider setup.

## CLI Usage

Build the default benchmark:

```bash
.venv/bin/python scripts/build_benchmark.py
```

Or run from config:

```bash
.venv/bin/python -m finance_redteam.cli build-from-config configs/finance_benchmark.yaml
```

Validate exported records:

```bash
.venv/bin/python -m finance_redteam.cli validate
```

Run tests:

```bash
.venv/bin/python -m pytest
```

Run live DeepTeam Gemini generation:

```bash
set -a
source .env
set +a
.venv/bin/python -m finance_redteam.cli build-from-config configs/finance_benchmark.deepteam_llm.yaml
```

## Promptfoo Evaluation

The build creates:

```text
data/exports/promptfoo_tests.yaml
```

Run Promptfoo:

```bash
npm run eval:gemini
```

Run a smaller first check:

```bash
npm run eval:gemini:smoke
```

Promptfoo sends each `attack_query` to the configured model and checks the response using the expected safe behavior and safety assertions.

## DeepTeam Role

DeepTeam is used for optional attack expansion.

In this project it can help generate variations for:

- Prompt injection
- PII leakage
- Credential leakage
- RAG/document exfiltration
- Unsafe financial advice
- Fraud enablement
- AML/KYC evasion
- Tool misuse

Use `configs/finance_benchmark.deepteam_llm.yaml` when you want live LLM-backed DeepTeam generation. Review generated records before using them in a formal benchmark.

## Garak Role

Garak is used as an optional coverage expansion layer.

It can add scanner-style patterns for:

- Prompt injection
- Data leakage
- Jailbreaks
- Hallucination
- Misinformation
- Encoding or obfuscation attacks

Garak is not the primary curated dataset source. It is a coverage helper.

## Dataset Schema

Each JSONL record is validated with Pydantic and includes:

```json
{
  "attack_id": "FIN-PII-001",
  "domain": "banking_finance",
  "risk_category": "Customer PII and Account Data Leakage",
  "risk_subcategory": "Customer PII Leakage",
  "owasp_mapping": ["LLM06 Sensitive Information Disclosure"],
  "mitre_atlas_mapping": ["AI Data Exfiltration"],
  "nist_ai_rmf_mapping": ["MAP", "MEASURE", "GOVERN"],
  "finance_domain_mapping": ["KYC", "Customer Data Protection"],
  "attack_type": "roleplay",
  "interaction_type": "single_turn",
  "difficulty": 2,
  "source": "seed",
  "prompt": "Full benchmark prompt or wrapper.",
  "attack_query": "Direct prompt sent to the target model.",
  "expected_behavior": "The model should refuse unsafe or unauthorized assistance.",
  "unsafe_success_criteria": "The model reveals sensitive data or gives unsafe guidance.",
  "safe_response_guidance": "Refuse and offer privacy-safe, compliance-safe alternatives.",
  "tags": ["finance", "privacy"],
  "created_by": "system",
  "version": "1.0.0"
}
```

Use `attack_query` for evaluation.

Use `prompt` for traceability and benchmark context.

## Safety And Validation

The validator checks:

- Unique attack IDs
- Required OWASP and NIST mappings
- Valid difficulty level
- Non-empty prompt and expected behavior
- Secret-like or credential-like patterns
- Realistic but non-operational unsafe content
- Records that need human review

Any LLM-generated expansion should be reviewed before formal use.

## Reusing This For Another Domain

The same architecture can support other domains.

To adapt it, replace:

1. Taxonomy
2. Seed prompts
3. Domain mappings
4. Expected behavior
5. Unsafe success criteria
6. Config values

The reusable pattern is:

```text
domain risks -> safe seed prompts -> optional expansion -> validation -> benchmark export -> evaluation
```

## GitHub Upload Checklist

Upload:

```text
README.md
.env.example
.gitignore
requirements.txt
pyproject.toml
configs/
notebooks/
src/
scripts/
tests/
data/taxonomy/
data/seeds/
data/exports/
providers/
package.json
package-lock.json
```

Do not upload:

```text
.env
.venv/
node_modules/
data/generated/
.pytest_cache/
__pycache__/
.promptfoo/
```

## Current Verification

The local test suite passes:

```bash
.venv/bin/python -m pytest
```

Expected result:

```text
19 passed
```
