"""Token-based brand matching and registrable-domain helpers.

Replaces the old `rapidfuzz.partial_ratio >= 80` substring match, which flagged
"Maple Leaf Foods", "Pineapple Bistro" and "Example Store" as the brand "apple".

Rules:
  * Text is normalized (NFKC, casefold, accents stripped, digits stripped) and split into
    WHOLE tokens. A brand is never matched as a substring of a longer word.
  * A match at any normalization level is "exact": plain, homoglyph-folded (Cyrillic/Greek
    lookalikes), or leet-folded (paypa1 -> paypal). Homoglyph/leet matches are labelled so
    the evidence shows the evasion.
  * Edit distance 1 ("fuzzy") is only considered when BOTH the brand token and the candidate
    token are at least FUZZY_MIN_LEN characters, and only for single-token brands.
  * Multi-word brands ("bank of america") match as a contiguous token sequence.

Brand names are normalized with the same function as the text, so a brand token like
"kvish6" becomes "kvish" (digits are stripped on both sides).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

import tldextract
from rapidfuzz.distance import Levenshtein

FUZZY_MIN_LEN = 6

# Cyrillic / Greek / Latin-extended lookalikes -> ASCII.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
        "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "ɡ": "g",
        "ı": "i", "ɑ": "a", "ѵ": "v", "ү": "y",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "ϲ": "c", "τ": "t",
    }
)
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})  # m1crosoft
_LEVELS = ("plain", "homoglyph", "leet", "leet_i")
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

# Offline: bundled public-suffix snapshot only, no runtime fetch, no on-disk cache.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registrable_domain(host: str | None) -> str | None:
    """eTLD+1 of a hostname (vh319.sweb.ru -> sweb.ru), or None if it has no registrable part."""
    if not host:
        return None
    ext = _EXTRACT(host.strip().strip(".").lower())
    return ext.top_domain_under_public_suffix or None


def domain_matches_any(host: str | None, legit_domains: list[str]) -> bool:
    reg = registrable_domain(host)
    return reg is not None and any(reg == registrable_domain(d) for d in legit_domains)


def _strip_marks(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def _tokens(text: str, level: str) -> list[str]:
    """level: plain | homoglyph | leet | leet_i. Digit-only tokens are dropped; digits inside a token
    are stripped (plain, homoglyph) or folded to lookalike letters (leet)."""
    text = _strip_marks(unicodedata.normalize("NFKC", text).casefold())
    if level != "plain":
        text = text.translate(_HOMOGLYPHS)
    out: list[str] = []
    for tok in _TOKEN_RE.findall(text):
        if level.startswith("leet") and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
            tok = tok.translate(_LEET_I if level == "leet_i" else _LEET)
        tok = "".join(c for c in tok if not c.isdigit())
        if tok:
            out.append(tok)
    return out


@lru_cache(maxsize=None)
def _brand_tokens(brand: str) -> tuple[str, ...]:
    return tuple(_tokens(brand, "plain"))


def _contains_sequence(haystack: list[str], needle: tuple[str, ...]) -> bool:
    n = len(needle)
    return n > 0 and any(tuple(haystack[i : i + n]) == needle for i in range(len(haystack) - n + 1))


@dataclass(frozen=True)
class BrandMatch:
    brand: str
    kind: str  # "exact" | "fuzzy"
    via: str  # "plain" | "homoglyph" | "leet" (exact) ; "plain" for fuzzy
    matched_text: str


def find_brand_matches(text: str | None, brands) -> list[BrandMatch]:
    """All brands present in `text` as whole tokens (exact) or, for long single-token brands,
    one edit away (fuzzy). Exact matches shadow fuzzy ones for the same brand."""
    if not text:
        return []
    levels = {lvl: _tokens(text, lvl) for lvl in _LEVELS}
    found: dict[str, BrandMatch] = {}
    for brand in brands:
        needle = _brand_tokens(brand)
        if not needle:
            continue
        for lvl in _LEVELS:
            if _contains_sequence(levels[lvl], needle):
                found[brand] = BrandMatch(brand, "exact", "leet" if lvl.startswith("leet") else lvl, " ".join(needle))
                break
    for brand in brands:
        needle = _brand_tokens(brand)
        if brand in found or len(needle) != 1 or len(needle[0]) < FUZZY_MIN_LEN:
            continue
        for tok in levels["homoglyph"]:
            if len(tok) >= FUZZY_MIN_LEN and Levenshtein.distance(tok, needle[0]) == 1:
                found[brand] = BrandMatch(brand, "fuzzy", "plain", tok)
                break
    return list(found.values())
