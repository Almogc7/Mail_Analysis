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
