from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_GARAK_PROBE_ALLOWLIST = [
    "promptinject",
    "dan",
    "encoding",
    "sysprompt_extraction",
    "leakreplay",
    "lmrc",
    "goodside",
    "donotanswer",
    "misleading",
    "web_injection",
    "latentinjection",
    "packagehallucination",
    "tap",
    "suffix",
    "grandma",
    "snowball",
]


@dataclass(frozen=True)
class GarakCorpusConfig:
    enabled: bool = False
    probe_allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_GARAK_PROBE_ALLOWLIST))
    max_raw_candidates: int = 5000
    max_per_probe: int = 25
    max_per_category: int = 25
    max_total_seeds: int = 120
    min_prompt_chars: int = 18
    max_prompt_chars: int = 1200
    include_data_files: bool = True
    include_probe_source_strings: bool = True
    domain_terms: list[str] = field(default_factory=list)
    excluded_terms: list[str] = field(
        default_factory=lambda: [
            "malware",
            "shell command",
            "sql injection",
            "xss",
            "exploit code",
            "weapon",
            "bomb",
            "kill all humans",
        ]
    )


@dataclass(frozen=True)
class GarakCorpusCandidate:
    candidate_id: str
    probe_name: str
    source_path: Path
    raw_prompt: str
    normalized_prompt: str
    attack_type: str
    category_id: str
    difficulty: int
    relevance_score: float
    metadata: dict[str, Any] = field(default_factory=dict)
