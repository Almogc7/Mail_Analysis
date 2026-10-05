import ipaddress
import json
import re

from app.contracts.analysis import AnalysisResult
from app.verdict_labels import verdict_label

SYSTEM_PROMPT = """You are assisting a SOC analyst reviewing the output of an automated email-triage tool.
A rule-based scoring engine has already analyzed this email across independent signal
categories (authentication checks, threat-intel enrichment, content heuristics) and
produced the verdict, score, and findings below. This verdict is FINAL and
AUTHORITATIVE -- it was not produced by you, and your job is not to produce your own.

Do not state, imply, or suggest a different verdict than the one given below.

Privacy: every address, hostname, URL, file name, IP and internal-looking name has been replaced by a
placeholder such as <URL_1>, <HOST_2>, <EMAIL_1>, <FILE_1> or <IP_1>. Refer to things by their placeholder;
never try to guess the original value. Only the TITLES of findings are shown, not their evidence.

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

MAX_FINDING_LINES = 60


# --------------------------------------------------------------------------------------------
# Tokenization: nothing identifying leaves the machine
# --------------------------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_FILE_RE = re.compile(
    r"[^\s'\"()<>:]+\.(?:pdf|docx?|xlsx?|pptx?|docm|xlsm|zip|rar|7z|exe|dll|scr|js|vbs|bat|ps1|jar|lnk|iso|img|msg|eml|"
    r"txt|csv|rtf|one|html?)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# candidates incl. compressed forms (2001:db8::1); each is validated with ipaddress before being replaced
_IPV6_RE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
_INTERNAL_NAME_RE = re.compile(r"\b[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]{2,})+\b")


class Tokenizer:
    """Replaces identifying strings with stable placeholders (<URL_1>, <HOST_2> ...) and can restore them,
    so the external model never sees an address, hostname, URL, file name, IP or internal-looking name,
    while the analyst still reads the model's answer with the real values put back (locally)."""

    def __init__(self) -> None:
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def _token(self, kind: str, original: str) -> str:
        key = (kind, original)
        if key not in self._forward:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            token = f"<{kind}_{self._counts[kind]}>"
            self._forward[key] = token
            self._reverse[token] = original
        return self._forward[key]

    @staticmethod
    def _ip_kind(text: str) -> str | None:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return None
        return "IP" if ip.is_global else "INTERNAL_IP"

    def _sub_ip(self, match: re.Match) -> str:
        kind = self._ip_kind(match.group(0))
        return self._token(kind, match.group(0)) if kind else match.group(0)  # not a valid address: leave as is

    def scrub(self, text: str) -> str:
        text = _URL_RE.sub(lambda m: self._token("URL", m.group(0)), text)
        text = _EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), text)
        text = _FILE_RE.sub(lambda m: self._token("FILE", m.group(0)), text)
        for rx in (_IPV4_RE, _IPV6_RE):
            text = rx.sub(self._sub_ip, text)
        text = _HASH_RE.sub(lambda m: self._token("HASH", m.group(0)), text)
        text = _HOST_RE.sub(lambda m: self._token("HOST", m.group(0)), text)
        text = _INTERNAL_NAME_RE.sub(lambda m: self._token("INTERNAL_NAME", m.group(0)), text)
        return text

    def restore(self, text: str) -> str:
        for token, original in self._reverse.items():
            text = text.replace(token, original)
        return text

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._reverse)


# --------------------------------------------------------------------------------------------
# The prompt: verdict, numbers, and finding TITLES only -- never descriptions or evidence
# --------------------------------------------------------------------------------------------

def build_context(analysis_result: AnalysisResult, tokenizer: Tokenizer | None = None) -> str:
    tok = tokenizer or Tokenizer()
    lines: list[str] = []

    lines.append(
        f"Verdict: {verdict_label(analysis_result.verdict)} "
        f"(score={analysis_result.score}/100, confidence={analysis_result.confidence:.2f})"
        if analysis_result.confidence is not None
        else f"Verdict: {verdict_label(analysis_result.verdict)} (score={analysis_result.score}/100)"
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
                lines.append(tok.scrub(f"- {o.rule}: {o.effect} ({o.reason})"))
            lines.append("")

    lines.append("Findings (titles only):")
    if not analysis_result.findings:
        lines.append("(none)")
    shown = analysis_result.findings[:MAX_FINDING_LINES]
    for f in shown:
        lines.append(tok.scrub(f"[{f.module}/{f.severity}] {f.title}"))
    if len(analysis_result.findings) > len(shown):
        lines.append(f"(+{len(analysis_result.findings) - len(shown)} more findings not shown)")

    return "\n".join(lines)


def build_prompt(analysis_result: AnalysisResult, tokenizer: Tokenizer | None = None) -> str:
    return SYSTEM_PROMPT + "\n\n" + build_context(analysis_result, tokenizer)


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
