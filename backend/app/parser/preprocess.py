"""Strip mail-gateway noise (injected banners, subject tags) before content analysis.

Reporting/security gateways rewrite messages: they prepend a banner to the HTML and plain
parts and tag the subject. That text describes the *gateway's* opinion, not the sender's
message, and would otherwise be scored as content ("reported as malicious" next to an
urgency lexicon) or hide the real first words of the mail.

Three layers, strongest first. Nothing here modifies ParsedEmail -- the original bodies stay
available and the raw file hash is taken before any of this runs.

1. Structural (no configuration): when an HTML body contains a *non-leading* <!DOCTYPE>, the
   visible text before it is an injected prefix (the wrapped original document starts at the
   doctype). If the plain-text part begins with the same words, that prefix is removed there
   too. Guarded: the prefix must be short (MAX_PREFIX_TEXT_CHARS of visible text).
2. Defaults: a few widely used generic tags ("[EXTERNAL]", "[SPAM]", ...).
3. Local configuration: regexes from the untracked environment (backend/.env):
       GATEWAY_BANNER_PATTERNS='["regex", ...]'       matched against body text
       GATEWAY_SUBJECT_TAG_PATTERNS='["regex", ...]'  matched against the subject
   Tenant-specific wording belongs ONLY there, never in the repo. Patterns are matched
   case-insensitively with DOTALL; an invalid regex is skipped and reported.

Every removal is returned in a StripReport so the analyst can see what was ignored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from app.config import GATEWAY_BANNER_PATTERNS, GATEWAY_SUBJECT_TAG_PATTERNS

MAX_PREFIX_TEXT_CHARS = 2000

# Generic only. Deliberately narrow: stripping *any* leading "[...]" would also eat a
# legitimate "[PayPal] Invoice" subject.
DEFAULT_SUBJECT_TAG_PATTERNS: tuple[str, ...] = (
    r"\[\s*(?:external|external email|external sender|ext|spam|suspected spam)\s*\]\s*",
    r"\[\s*caution[^\]]{0,60}\]\s*",
)
DEFAULT_BANNER_PATTERNS: tuple[str, ...] = (
    r"caution:\s*this (?:e-?mail|message) (?:originated|came) from outside (?:of )?(?:the|your) organi[sz]ation\.?[^\n]{0,200}",
)

_DOCTYPE_RE = re.compile(r"<!doctype", re.IGNORECASE)


@dataclass
class StripReport:
    removed: list[dict] = field(default_factory=list)  # {"kind", "pattern"?, "chars", "preview"}
    warnings: list[str] = field(default_factory=list)

    def add(self, kind: str, removed_text: str, pattern: str | None = None) -> None:
        entry = {"kind": kind, "chars": len(removed_text), "preview": " ".join(removed_text.split())[:80]}
        if pattern is not None:
            entry["pattern"] = pattern
        self.removed.append(entry)


def _visible_text(html: str) -> str:
    return " ".join(BeautifulSoup(html, "html.parser").get_text(" ").split())


def strip_injected_html_prefix(html: str, report: StripReport | None = None) -> tuple[str, str | None]:
    """Returns (html_without_prefix, prefix_visible_text or None)."""
    m = _DOCTYPE_RE.search(html)
    if not m or html[: m.start()].strip() == "" or m.start() == 0:
        return html, None
    prefix_html = html[: m.start()]
    prefix_text = _visible_text(prefix_html)
    if not prefix_text or len(prefix_text) > MAX_PREFIX_TEXT_CHARS:
        return html, None
    if report is not None:
        report.add("html_injected_prefix", prefix_text)
    return html[m.start() :], prefix_text


def _strip_leading_words(text: str, words_text: str, report: StripReport | None) -> str:
    """Remove `words_text` (compared as a whitespace-insensitive word sequence) from the very
    start of `text`, if present."""
    words = words_text.split()
    if not words:
        return text
    rx = re.compile(r"\A\s*" + r"\s*".join(re.escape(w) for w in words) + r"\s*")
    m = rx.match(text)
    if not m:
        return text
    if report is not None:
        report.add("plain_injected_prefix", m.group(0))
    return text[m.end() :]


def _compile(patterns, report: StripReport) -> list[re.Pattern]:
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE | re.DOTALL))
        except re.error as exc:
            report.warnings.append(f"invalid gateway strip pattern skipped: {exc}")
    return compiled


def strip_text(
    text: str,
    report: StripReport,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> str:
    pats = list(DEFAULT_BANNER_PATTERNS) + list(GATEWAY_BANNER_PATTERNS if patterns is None else patterns)
    for rx in _compile(pats, report):
        def _sub(m: re.Match, rx=rx) -> str:
            report.add("banner_pattern", m.group(0), rx.pattern)
            return " "

        text = rx.sub(_sub, text)
    return text


def clean_subject(
    subject: str | None,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> tuple[str | None, StripReport]:
    report = StripReport()
    if not subject:
        return subject, report
    pats = list(DEFAULT_SUBJECT_TAG_PATTERNS) + list(GATEWAY_SUBJECT_TAG_PATTERNS if patterns is None else patterns)
    for rx in _compile(pats, report):
        def _sub(m: re.Match, rx=rx) -> str:
            report.add("subject_tag", m.group(0), rx.pattern)
            return ""

        subject = rx.sub(_sub, subject)
    return " ".join(subject.split()), report


def clean_body_text(
    body_text: str | None,
    body_html: str | None,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> tuple[str, StripReport]:
    """The text content heuristics should read: prefers the plain part, falls back to the
    HTML's visible text, with gateway noise removed from whichever is used."""
    report = StripReport()
    prefix_text: str | None = None
    html = body_html
    if html:
        html, prefix_text = strip_injected_html_prefix(html, report)
    if body_text:
        text = body_text
        if prefix_text:
            text = _strip_leading_words(text, prefix_text, report)
    elif html:
        text = BeautifulSoup(html, "html.parser").get_text(separator=" ")
    else:
        return "", report
    return strip_text(text, report, patterns), report
