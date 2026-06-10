from __future__ import annotations

import re
from dataclasses import dataclass, field

from .schema import AttackRecord


SECRET_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(password|api key|secret token)\s*[:=]\s*\S+"),
]

OPERATIONAL_HARM_PATTERNS = [
    "step-by-step method to avoid aml",
    "exact amounts to split",
    "how to steal",
    "bypass sanctions screening with exact",
    "credential theft steps",
    "phishing kit",
    "malware",
]


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    review_warnings: list[str] = field(default_factory=list)


def scan_prompt_for_real_secrets(prompt: str) -> list[str]:
    findings: list[str] = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(prompt):
            findings.append(f"possible real secret or identifier matched: {pattern.pattern}")
    return findings


def scan_prompt_for_operational_harm(prompt: str) -> list[str]:
    prompt_lower = prompt.lower()
    return [
        f"suspicious operational wording: {pattern}"
        for pattern in OPERATIONAL_HARM_PATTERNS
        if pattern in prompt_lower
    ]


def validate_records(records: list[AttackRecord]) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    ids: set[str] = set()
    for index, record in enumerate(records, start=1):
        prefix = f"record {index} ({record.attack_id})"
        if record.attack_id in ids:
            errors.append(f"{prefix}: duplicate attack_id")
        ids.add(record.attack_id)
        if not record.owasp_mapping:
            errors.append(f"{prefix}: missing OWASP mapping")
        if not record.nist_ai_rmf_mapping:
            errors.append(f"{prefix}: missing NIST AI RMF mapping")
        if not record.risk_category:
            errors.append(f"{prefix}: missing risk category")
        if record.difficulty < 1 or record.difficulty > 5:
            errors.append(f"{prefix}: difficulty out of range")
        if not record.prompt:
            errors.append(f"{prefix}: prompt is empty")
        if not record.attack_query:
            errors.append(f"{prefix}: attack_query is empty")
        if not record.expected_behavior:
            errors.append(f"{prefix}: expected behavior is empty")
        if not record.unsafe_success_criteria:
            errors.append(f"{prefix}: unsafe success criteria is empty")
        secret_findings = scan_prompt_for_real_secrets(record.attack_query or record.prompt)
        if secret_findings:
            errors.extend(f"{prefix}: {finding}" for finding in secret_findings)
        harm_findings = scan_prompt_for_operational_harm(record.attack_query or record.prompt)
        if harm_findings:
            warnings.extend(f"{prefix}: {finding}" for finding in harm_findings)
    return ValidationResult(valid=not errors, errors=errors, review_warnings=warnings)
