from bs4 import BeautifulSoup

from app.contracts.email import ParsedEmail


def get_searchable_text(parsed: ParsedEmail) -> str:
    """Plain text to run content heuristics against. Prefers body_text; falls back to
    stripping body_html (this also picks up anchor text, since bs4's get_text() includes
    it -- so a brand mentioned only inside a link's visible text is still caught)."""
    if parsed.body_text:
        return parsed.body_text
    if parsed.body_html:
        return BeautifulSoup(parsed.body_html, "html.parser").get_text(separator=" ")
    return ""


# Scripts our phrase lists (URGENCY_PHRASES, GENERIC_GREETINGS, KNOWN_BRANDS) actually have
# coverage for. Extend this set only after adding real phrase-list entries for that script --
# it's used to report reduced coverage/confidence for scripts we can't meaningfully check,
# not as a language detector in its own right.
_SUPPORTED_SCRIPTS = {"latin", "hebrew"}


def _script_of(char: str) -> str | None:
    if not char.isalpha():
        return None
    codepoint = ord(char)
    if codepoint < 128:
        return "latin"
    if 0x0590 <= codepoint <= 0x05FF:  # Hebrew block
        return "hebrew"
    return "other"


def estimate_script_coverage(text: str) -> float:
    """1.0 if the text is predominantly in a script our phrase lists cover, 0.5 otherwise.

    Deliberately coarse -- not a language detector, just enough signal so category_coverage
    can tell "checked, clean" apart from "couldn't meaningfully check because the heuristics
    don't cover this script", the same distinction auth_check already makes for a missing
    Authentication-Results header. Without this, a non-English phishing email with weak
    findings elsewhere can look fully "checked" when content_analysis actually had nothing
    to say about it one way or the other.
    """
    scripts = [s for s in (_script_of(c) for c in text) if s]
    if len(scripts) < 20:  # not enough text to judge either way -- don't penalize
        return 1.0
    supported_ratio = sum(1 for s in scripts if s in _SUPPORTED_SCRIPTS) / len(scripts)
    return 1.0 if supported_ratio >= 0.5 else 0.5
