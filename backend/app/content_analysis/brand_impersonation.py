import re
from typing import Any
from urllib.parse import urlparse

from app.contracts.email import ParsedEmail
from app.shared.brands import KNOWN_BRANDS

_BRAND_PATTERNS: dict[str, re.Pattern] = {
    brand: re.compile(rf"\b{re.escape(brand)}\b", re.IGNORECASE) for brand in KNOWN_BRANDS
}


def detect_brand_in_body(text: str) -> list[str]:
    """Exact-phrase, word-boundary, case-insensitive brand mentions in body content.
    Deliberately not fuzzy-matched (unlike auth_check's display-name check) -- scoring a
    short brand token against a full paragraph of prose is prone to incidental high-score
    matches, especially for common-word brand names (e.g. "chase", "apple")."""
    return [brand for brand, pattern in _BRAND_PATTERNS.items() if pattern.search(text)]


def check_brand_url_mismatch(parsed: ParsedEmail, matched_brands: list[str]) -> list[dict[str, Any]]:
    """Only considers URLs that Module 1 already flagged as anchor-mismatched (displayed
    link text looks like a URL/domain but doesn't match the actual href) -- a bare
    domain-doesn't-match-brand check would misfire on nearly all legitimate marketing email,
    which routes links through an unrelated ESP tracking domain."""
    mismatches: list[dict[str, Any]] = []
    for url in parsed.urls:
        if not url.is_anchor_mismatch:
            continue
        domain = (urlparse(url.url).netloc or url.url).lower()
        for brand in matched_brands:
            legit_domains = KNOWN_BRANDS[brand]
            domain_matches_brand = any(domain == d or domain.endswith(f".{d}") for d in legit_domains)
            if not domain_matches_brand:
                mismatches.append(
                    {
                        "brand": brand,
                        "url": url.url,
                        "anchor_text": url.anchor_text,
                        "domain": domain,
                    }
                )
    return mismatches
