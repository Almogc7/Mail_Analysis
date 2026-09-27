import json
import re
from typing import Any

from app.contracts.analysis import AnalysisResult

_EVIDENCE_VALUE_MAX_LEN = 200

SYSTEM_PROMPT = """You are assisting a SOC analyst reviewing the output of an automated email-triage tool.
A rule-based scoring engine has already analyzed this email across independent signal
categories (authentication checks, threat-intel enrichment, content heuristics) and
produced the verdict, score, and findings below. This verdict is FINAL and
AUTHORITATIVE -- it was not produced by you, and your job is not to produce your own.

Do not state, imply, or suggest a different verdict than the one given below.

Your job is only to:
1. Write a short, plain-language narrative (2-4 sentences) explaining why this verdict
   makes sense given the findings below, so an analyst can understand the reasoning at a
   glance.
2. List anything in the findings that seems worth a second look by a human analyst --
   nuance, an alternative interpretation, or a plausible innocent explanation the
   fixed-rule findings might not fully capture. These are advisory flags for a human to
   check, never a competing verdict. If nothing stands out, return an empty list.

Respond with ONLY a single JSON object, no markdown formatting, no code fences, exactly
two keys: "narrative" (string) and "flags" (array of strings)."""


def _format_evidence_value(value: Any) -> str:
    text = str(value)
    if len(text) > _EVIDENCE_VALUE_MAX_LEN:
        text = text[:_EVIDENCE_VALUE_MAX_LEN] + "..."
    return text


def _format_evidence(evidence: dict[str, Any]) -> str:
    if not evidence:
        return "none"
    return "; ".join(f"{k}={_format_evidence_value(v)}" for k, v in evidence.items())


def build_context(analysis_result: AnalysisResult) -> str:
    lines: list[str] = []

    lines.append(
        f"Verdict: {analysis_result.verdict} "
        f"(score={analysis_result.score}/100, confidence={analysis_result.confidence:.2f})"
        if analysis_result.confidence is not None
        else f"Verdict: {analysis_result.verdict} (score={analysis_result.score}/100)"
    )
    lines.append("")

    if analysis_result.scoring:
        lines.append("Category breakdown:")
        for c in analysis_result.scoring.categories:
            lines.append(
                f"- {c.category}: subscore={c.subscore} (weight={c.weight}, "
                f"contribution={c.contribution}, coverage={c.coverage:.2f}, "
                f"{c.finding_count} finding(s))"
            )
        lines.append("")

        if analysis_result.scoring.applied_overrides:
            lines.append("Overrides applied:")
            for o in analysis_result.scoring.applied_overrides:
                lines.append(f"- {o.rule}: {o.effect} ({o.reason})")
            lines.append("")

    lines.append("Findings:")
    if not analysis_result.findings:
        lines.append("(none)")
    for f in analysis_result.findings:
        lines.append(f"[{f.module}/{f.severity}] {f.title}")
        lines.append(f"  {f.description}")
        lines.append(f"  evidence: {_format_evidence(f.evidence)}")

    return "\n".join(lines)


def build_prompt(analysis_result: AnalysisResult) -> str:
    return SYSTEM_PROMPT + "\n\n" + build_context(analysis_result)


def _strip_code_fences(text: str) -> str:
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    return match.group(1) if match else text


def _extract_json_object(text: str) -> str | None:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else None


def parse_response(raw_text: str) -> tuple[str, list[str]]:
    """Returns (narrative, flags). Tries strict JSON, then fence-stripped JSON, then a
    regex-extracted {...} block; falls back to treating the whole response as narrative
    with no flags if none of that parses -- never raises."""
    for candidate in (raw_text, _strip_code_fences(raw_text), _extract_json_object(raw_text)):
        if candidate is None:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict) and "narrative" in parsed:
            narrative = str(parsed.get("narrative", ""))
            raw_flags = parsed.get("flags", [])
            flags = [str(f) for f in raw_flags] if isinstance(raw_flags, list) else []
            return narrative, flags

    return raw_text.strip(), []
