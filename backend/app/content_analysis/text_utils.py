from dataclasses import dataclass

from app.contracts.email import ParsedEmail
from app.parser.preprocess import StripReport, clean_body_text


def searchable_text_with_report(parsed: ParsedEmail) -> tuple[str, StripReport]:
    """Plain text to run content heuristics against, plus a report of the gateway noise
    removed from it. Prefers body_text; falls back to the visible text of body_html (this also
    picks up anchor text, so a brand mentioned only inside a link's visible text is still
    caught). Injected gateway banners are stripped first (see app/parser/preprocess.py)."""
    return clean_body_text(parsed.body_text, parsed.body_html)


def get_searchable_text(parsed: ParsedEmail) -> str:
    return searchable_text_with_report(parsed)[0]


# --------------------------------------------------------------------------------------------
# Language-aware content coverage
#
# The urgency phrases, greetings and brand logic only exist for English and Hebrew. Text in any other language
# is therefore NOT "checked and clean" by content analysis -- it was not checked at all -- and must not be
# allowed to support a benign verdict. Coverage reflects that:
#
#   supported     English or Hebrew                                  1.00
#   undetermined  too little text to tell the language               0.50
#   unsupported   another language or script                         0.25
#   none          no readable text (image-only / empty body)         0.25
#
# No lexicons are added for other languages: the function-word lists below are used ONLY to identify the
# language (so a German mail is recognised as not-English), never to detect anything about the content.
# --------------------------------------------------------------------------------------------

SUPPORTED_COVERAGE = 1.0
UNDETERMINED_COVERAGE = 0.5
UNSUPPORTED_COVERAGE = 0.25
NONE_COVERAGE = 0.25

_NON_LATIN_SHARE = 0.3  # share of letters that makes a text "in" a non-Latin script
_MIN_LETTERS = 20
_LONG_TEXT_WORDS = 25
_LONG_EN_SHARE = 0.10
_SHORT_EN_SHARE, _SHORT_EN_HITS = 0.15, 3

# LANGUAGE IDENTIFICATION ONLY -- not content lexicons.
_FUNCTION_WORDS: dict[str, frozenset[str]] = {
    "english": frozenset("the and to of a in is you that for it with this your are be on as have we".split()),
    "german": frozenset("der die das und ist in den von zu mit sich auf für nicht ein eine dem des auch als an bei sie ihr".split()),
    "french": frozenset("le la les de des du et en un une que qui dans pour pas sur au avec ce il est vous nous votre".split()),
    "spanish": frozenset("el la de que y en los las un una por con para su se no es al del lo como más pero sus le".split()),
    "portuguese": frozenset("o a de que e do da em um uma para com não os as se na no por mais dos como mas foi ao ele".split()),
    "italian": frozenset("il lo la le di che e un una per con non in del della sono gli dei si da come più ha anche".split()),
    "dutch": frozenset("de het een en van in is dat op te voor met zijn niet aan er maar om ook als bij uw u".split()),
}


@dataclass(frozen=True)
class LanguageInfo:
    status: str  # supported | undetermined | unsupported | none
    language: str  # english | hebrew | a script or language name | unknown | none
    coverage: float
    reason: str

    def as_dict(self) -> dict:
        return {"status": self.status, "language": self.language, "coverage": self.coverage, "reason": self.reason}


def _script_of(char: str) -> str | None:
    if not char.isalpha():
        return None
    cp = ord(char)
    if cp < 0x250:
        return "latin"
    if 0x0590 <= cp <= 0x05FF:
        return "hebrew"
    if 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F:
        return "arabic"
    if 0x0400 <= cp <= 0x04FF:
        return "cyrillic"
    if 0x4E00 <= cp <= 0x9FFF or 0x3040 <= cp <= 0x30FF or 0xAC00 <= cp <= 0xD7AF:
        return "cjk"
    return "other script"


def detect_language(text: str) -> LanguageInfo:
    """Which language the readable text is in, and how much of it content analysis can cover."""
    # Link text ("<https://...>") is Latin script whatever the language: leave it out.
    visible = " ".join(w for w in text.split() if "://" not in w)
    scripts: dict[str, int] = {}
    for ch in visible:
        s = _script_of(ch)
        if s:
            scripts[s] = scripts.get(s, 0) + 1
    letters = sum(scripts.values())
    if letters == 0:
        return LanguageInfo("none", "none", NONE_COVERAGE, "no readable text (image-only or empty body): nothing for content analysis to read")
    if letters < _MIN_LETTERS:
        return LanguageInfo("undetermined", "unknown", UNDETERMINED_COVERAGE, f"only {letters} letters of text: too little to identify the language")

    non_latin = {k: v for k, v in scripts.items() if k != "latin"}
    top_script = max(non_latin, key=non_latin.get) if non_latin else None
    if top_script and non_latin[top_script] / letters >= _NON_LATIN_SHARE:
        if top_script == "hebrew":
            return LanguageInfo("supported", "hebrew", SUPPORTED_COVERAGE, "Hebrew text: Hebrew lexicons apply")
        return LanguageInfo("unsupported", top_script, UNSUPPORTED_COVERAGE,
                            f"text is mainly in {top_script} script: content lexicons cover English and Hebrew only")

    words = [w.strip(".,!?;:()[]\"'¿¡«»").lower() for w in visible.split()]
    words = [w for w in words if w.isalpha()]
    n = len(words)
    if n == 0:
        return LanguageInfo("undetermined", "unknown", UNDETERMINED_COVERAGE, "no word-like text to identify the language from")
    shares = {lang: sum(1 for w in words if w in fw) / n for lang, fw in _FUNCTION_WORDS.items()}
    en = shares["english"]
    en_hits = sum(1 for w in words if w in _FUNCTION_WORDS["english"])
    best_other_lang = max((k for k in shares if k != "english"), key=lambda k: shares[k])
    best_other = shares[best_other_lang]

    if n >= _LONG_TEXT_WORDS:
        if en >= _LONG_EN_SHARE and en >= best_other:
            return LanguageInfo("supported", "english", SUPPORTED_COVERAGE, "English text: English lexicons apply")
        # not English: another language's function words clearly outweigh English ones, or English is almost absent
        if best_other > en or en <= 0.06:
            name = best_other_lang if best_other >= 0.10 else "a language other than English"
            return LanguageInfo("unsupported", name, UNSUPPORTED_COVERAGE,
                                f"text looks like {name}, not English or Hebrew: content lexicons do not apply")
        return LanguageInfo("undetermined", "unknown", UNDETERMINED_COVERAGE, "function-word evidence is ambiguous")
    # short text: only a decisive English signal counts as supported
    if en >= _SHORT_EN_SHARE and en_hits >= _SHORT_EN_HITS and en >= best_other:
        return LanguageInfo("supported", "english", SUPPORTED_COVERAGE, "short English text")
    if best_other >= 0.25 and best_other > en + 0.10:
        return LanguageInfo("unsupported", best_other_lang, UNSUPPORTED_COVERAGE, f"short text that looks like {best_other_lang}")
    return LanguageInfo("undetermined", "unknown", UNDETERMINED_COVERAGE, f"only {n} words: too short to confirm the language")


def estimate_script_coverage(text: str) -> float:
    """Content-analysis coverage for this text (see the table above). Kept under its old name because the scoring
    layer reads it from raw_data['script_coverage']."""
    return detect_language(text).coverage
