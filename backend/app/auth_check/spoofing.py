from typing import Any

from rapidfuzz import fuzz

from app.contracts.email import EmailAddress, ParsedEmail

# Small curated list for v1 — brand name to its legitimate domain(s).
# Extend as needed; false negatives here just mean "not flagged", not "safe".
KNOWN_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "meta.com"],
}

FUZZY_MATCH_THRESHOLD = 80


def _domain_mismatch(a: EmailAddress | None, b: EmailAddress | None) -> dict[str, Any]:
    domain_a = a.domain if a else None
    domain_b = b.domain if b else None
    if domain_a is None or domain_b is None:
        return {"mismatch": False, "domain_a": domain_a, "domain_b": domain_b}
    return {"mismatch": domain_a != domain_b, "domain_a": domain_a, "domain_b": domain_b}


def _check_display_name_spoofing(from_addr: EmailAddress) -> dict[str, Any]:
    display_name = (from_addr.display_name or "").lower().strip()
    actual_domain = from_addr.domain
    if not display_name:
        return {"suspected": False, "claimed_brand": None, "actual_domain": actual_domain, "match_score": 0}

    best_brand: str | None = None
    best_score = 0.0
    for brand, legit_domains in KNOWN_BRANDS.items():
        score = fuzz.partial_ratio(brand, display_name)
        if score > best_score:
            best_score = score
            best_brand = brand

    if best_brand is None or best_score < FUZZY_MATCH_THRESHOLD:
        return {"suspected": False, "claimed_brand": None, "actual_domain": actual_domain, "match_score": best_score}

    legit_domains = KNOWN_BRANDS[best_brand]
    domain_matches_brand = actual_domain is not None and any(
        actual_domain == d or actual_domain.endswith(f".{d}") for d in legit_domains
    )
    return {
        "suspected": not domain_matches_brand,
        "claimed_brand": best_brand,
        "actual_domain": actual_domain,
        "match_score": best_score,
    }


def check_identity_mismatch(parsed: ParsedEmail) -> dict[str, Any]:
    from_return_path = _domain_mismatch(parsed.from_, parsed.return_path)
    from_reply_to = _domain_mismatch(
        parsed.from_, parsed.reply_to[0] if parsed.reply_to else None
    )
    display_name_spoofing = _check_display_name_spoofing(parsed.from_)

    return {
        "from_return_path_mismatch": {
            "mismatch": from_return_path["mismatch"],
            "from_domain": from_return_path["domain_a"],
            "return_path_domain": from_return_path["domain_b"],
        },
        "from_reply_to_mismatch": {
            "mismatch": from_reply_to["mismatch"],
            "from_domain": from_reply_to["domain_a"],
            "reply_to_domain": from_reply_to["domain_b"],
        },
        "display_name_spoofing": display_name_spoofing,
    }
