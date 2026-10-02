from typing import Any

from app.contracts.email import EmailAddress, ParsedEmail
from app.shared.brands import KNOWN_BRANDS
from app.shared.matching import domain_matches_any, find_brand_matches, registrable_domain


def _domain_mismatch(a: EmailAddress | None, b: EmailAddress | None) -> dict[str, Any]:
    domain_a = a.domain if a else None
    domain_b = b.domain if b else None
    if domain_a is None or domain_b is None:
        return {"mismatch": False, "domain_a": domain_a, "domain_b": domain_b}
    return {"mismatch": domain_a != domain_b, "domain_a": domain_a, "domain_b": domain_b}


def _check_display_name_spoofing(from_addr: EmailAddress) -> dict[str, Any]:
    """Token-based (see app.shared.matching). `suspected` -- which drives the SUSPICIOUS
    floor -- requires an EXACT whole-token brand match (plain, homoglyph or leet-folded)
    AND a sender registrable domain outside that brand's legitimate domains. A fuzzy-only
    (edit distance 1) look-alike sets `fuzzy_suspected` instead: a medium finding, no floor."""
    actual_domain = from_addr.domain
    result: dict[str, Any] = {
        "suspected": False,
        "fuzzy_suspected": False,
        "match_type": None,
        "normalization": None,
        "claimed_brand": None,
        "actual_domain": actual_domain,
        "actual_registrable_domain": registrable_domain(actual_domain),
        "match_score": 0,
    }
    matches = find_brand_matches(from_addr.display_name, KNOWN_BRANDS)
    # Only brands the sender domain does NOT belong to are impersonation candidates; prefer
    # exact over fuzzy.
    candidates = [m for m in matches if not domain_matches_any(actual_domain, KNOWN_BRANDS[m.brand])]
    candidates.sort(key=lambda m: m.kind != "exact")
    if not candidates:
        legit = matches[0] if matches else None
        if legit:
            result.update(match_type=legit.kind, claimed_brand=legit.brand, normalization=legit.via,
                          match_score=100.0 if legit.kind == "exact" else 90.0)
        return result
    top = candidates[0]
    result.update(
        match_type=top.kind,
        normalization=top.via,
        claimed_brand=top.brand,
        match_score=100.0 if top.kind == "exact" else 90.0,
        suspected=top.kind == "exact",
        fuzzy_suspected=top.kind == "fuzzy",
    )
    return result


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
