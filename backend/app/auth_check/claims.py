"""Claim-family signals (docs/DETECTION_DESIGN.md): what the message presents itself as, against who sent it.

C1b brand mention in the body      additive only, never a family signal
C2  claimed-entity mismatch        brand-agnostic, trust-independent; family 'claim'
C3  decoy links to the claimed entity                                    family 'claim'

These live in auth_check (not content_analysis) because C2 must know whether a TRUSTED receiver verified an aligned
DKIM/DMARC pass, and only this module has that result. No brand or alias is hardcoded here: brands come from the generic
map plus the untracked local file (see shared/brands.py).
"""
from __future__ import annotations

from typing import Any

from app.content_analysis.links import _clickable_hosts, _host, _reg
from app.content_analysis.text_utils import get_searchable_text
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding
from app.enrichment.policy import platform_of
from app.parser.preprocess import clean_subject
from app.shared.brands import KNOWN_BRANDS
from app.shared.matching import domain_matches_any, find_brand_matches

MODULE_NAME = "auth_check"
FAMILY = "claim"

_DOMINANT_SHARE = 0.5
_MIN_OCCURRENCES = 2
_MIN_TOKEN_LEN = 4

# Words that name a kind of mail or business rather than an entity. A display-name token that is one of these never
# counts as "the claimed entity" for C3, whatever domain it matches.
GENERIC_WORDS = frozenset({
    "news", "mail", "email", "info", "blog", "shop", "store", "online", "group", "team", "service", "services", "support",
    "account", "accounts", "update", "updates", "notice", "invoice", "order", "orders", "payment", "billing", "weekly",
    "daily", "monthly", "newsletter", "digest", "hello", "welcome", "your", "this", "that", "with", "from", "have", "dear",
    "please", "urgent", "important", "security", "secure", "login", "verify", "confirm", "document", "documents",
    "message", "reminder", "alert", "center", "centre", "health", "dental", "clinic", "bank", "home", "free", "sale", "deal",
    "deals", "offer", "offers", "promo", "report", "statement", "delivery", "parcel", "package", "tracking", "reset",
    "password", "internal", "customer", "customers", "member", "members", "student", "students", "company", "business",
})


def verified_aligned_pass(auth: dict[str, Any], alignment: dict[str, Any]) -> bool:
    """A TRUSTED receiver verified an aligned DKIM pass, or a DMARC pass. (A header the sender could have written is
    not this; evaluate_authentication only marks a method evaluated for a trusted receiver.)"""
    dkim, dmarc = auth.get("dkim", {}), auth.get("dmarc", {})
    dkim_ok = bool(dkim.get("evaluated")) and dkim.get("result") == "pass" and alignment.get("dkim", {}).get("aligned") is True
    return dkim_ok or (bool(dmarc.get("evaluated")) and dmarc.get("result") == "pass")


def has_dkim_signature(parsed: ParsedEmail) -> bool:
    return any(h.name.lower() == "dkim-signature" for h in parsed.headers)


def _word_tokens(text: str | None) -> list[str]:
    """Whole alphanumeric tokens, lower-cased, digits stripped ('kvish6' -> 'kvish'), keeping only those that are long
    enough, purely alphabetic after stripping, and not generic words."""
    tokens: list[str] = []
    current: list[str] = []
    for ch in (text or "").lower() + " ":
        if ch.isalnum():
            current.append(ch)
            continue
        if current:
            word = "".join(c for c in current if not c.isdigit())
            if len(word) >= _MIN_TOKEN_LEN and word.isalpha() and word not in GENERIC_WORDS:
                tokens.append(word)
            current = []
    return tokens


def _label(registrable: str | None) -> str:
    """The name part of a registrable domain, digits and hyphens removed ('kvish6.co.il' -> 'kvish')."""
    first = (registrable or "").split(".")[0]
    return "".join(c for c in first if c.isalpha())


def dominant_foreign_domain(parsed: ParsedEmail) -> dict[str, Any] | None:
    """C2's core: one non-platform registrable domain that dominates the links AND images, hosts at least one link, and is not
    the sender's (nor the Return-Path's). Platform hosts are excluded because ESPs, wrappers and CDNs carry everyone's mail."""
    hosts = list(_clickable_hosts(parsed)) + [h for i in parsed.images if (h := _host(i.url))]
    hosts = [h for h in hosts if platform_of(h) is None]
    if not hosts:
        return None
    counts: dict[str, int] = {}
    for h in hosts:
        reg = _reg(h)
        if reg:
            counts[reg] = counts.get(reg, 0) + 1
    if not counts:
        return None
    reg, n = max(counts.items(), key=lambda item: item[1])
    related = {_reg(parsed.from_.domain), _reg(parsed.return_path.domain) if parsed.return_path else None}
    if reg in related or n < _MIN_OCCURRENCES or n / len(hosts) < _DOMINANT_SHARE:
        return None
    # Iteration 2: the entity a message claims to be is something the recipient can REACH. A domain that only serves
    # images (a stock-photo or asset CDN the links never use) is not a claimed entity; L2 applies the same condition.
    if reg not in {_reg(h) for h in _clickable_hosts(parsed)}:
        return None
    return {"domain": reg, "occurrences": n, "non_platform_hosts_total": len(hosts)}


def claimed_entity_mismatch(parsed: ParsedEmail, auth: dict[str, Any], alignment: dict[str, Any]) -> dict[str, Any] | None:
    """C2. A message whose links and assets belong to an entity that is not the sender, with no DKIM-Signature at all.
    Needs no brand list. A DKIM-Signature that is merely PRESENT is a claim and cannot be judged here, so C2 stays silent
    (which an attacker can arrange for free -- see docs/DETECTION_DESIGN.md); a verified aligned pass from a trusted
    receiver is the stronger negative."""
    dominant = dominant_foreign_domain(parsed)
    if dominant is None:
        return None
    if verified_aligned_pass(auth, alignment) or has_dkim_signature(parsed):
        return None
    return {**dominant, "dkim_signature_present": False, "sender_domain": _reg(parsed.from_.domain)}


def _claimed_brands(parsed: ParsedEmail) -> list[str]:
    """Brands the display name or subject claims as exact whole tokens, that the sender domain does not belong to."""
    subject, _ = clean_subject(parsed.subject)
    domain = parsed.from_.domain
    brands: list[str] = []
    for text in (parsed.from_.display_name, subject):
        for match in find_brand_matches(text, KNOWN_BRANDS):
            if match.kind == "exact" and not domain_matches_any(domain, KNOWN_BRANDS[match.brand]) and match.brand not in brands:
                brands.append(match.brand)
    return brands


def decoy_links(parsed: ParsedEmail) -> dict[str, Any] | None:
    """C3. Two forms, both needing a link the sender does not own:
      a) a token of the display name or subject IS the name of a linked registrable domain (display 'kvish6', link
         kvish6.co.il) -- no brand list needed;
      b) the display name or subject claims a known brand and a link goes to that brand's real domain. A bare link to a
         brand's domain is NOT enough (every newsletter links to social networks and app stores); the claim is required."""
    sender = _reg(parsed.from_.domain)
    sender_label = _label(sender)
    subject, _ = clean_subject(parsed.subject)
    tokens = set(_word_tokens(parsed.from_.display_name)) | set(_word_tokens(subject))
    tokens.discard(sender_label)

    link_regs = {r for h in _clickable_hosts(parsed) if platform_of(h) is None and (r := _reg(h)) and r != sender}
    by_name = sorted({r for r in link_regs if _label(r) in tokens})

    by_brand: list[dict[str, str]] = []
    for brand in _claimed_brands(parsed):
        for host in _clickable_hosts(parsed):
            if domain_matches_any(host, KNOWN_BRANDS[brand]):
                by_brand.append({"brand": brand, "link_host": host})
                break
    if not by_name and not by_brand:
        return None
    return {"matches_display_or_subject": by_name, "claimed_brand_links": by_brand, "sender_domain": sender}


def body_brand_mentions(parsed: ParsedEmail) -> list[str]:
    """C1b. Exact brand tokens in the body that the sender does not own and the display name/subject did not claim."""
    claimed = set(_claimed_brands(parsed))
    domain = parsed.from_.domain
    found: list[str] = []
    for match in find_brand_matches(get_searchable_text(parsed), KNOWN_BRANDS):
        if match.kind == "exact" and match.brand not in claimed and not domain_matches_any(domain, KNOWN_BRANDS[match.brand]):
            found.append(match.brand)
    return sorted(set(found))


def claim_findings(parsed: ParsedEmail, auth: dict[str, Any], alignment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if (c2 := claimed_entity_mismatch(parsed, auth, alignment)) is not None:
        findings.append(Finding(
            module=MODULE_NAME, severity="low", weight=8.0,
            title="Links and images belong to a different entity than the sender, and the message is unsigned",
            description=(
                f"{c2['occurrences']} of {c2['non_platform_hosts_total']} non-platform link and image hosts are on "
                f"'{c2['domain']}', which has nothing to do with the sending domain '{c2['sender_domain']}', and the message "
                "has no DKIM-Signature header at all. A lure built from another entity's assets but sent from an unsigned "
                "origin looks like this. (A present DKIM-Signature would have hidden this signal.)"),
            evidence={**c2, "structural": True, "family": FAMILY, "signal": "C2"},
        ))
    if (c3 := decoy_links(parsed)) is not None:
        names = ", ".join(c3["matches_display_or_subject"] + [b["link_host"] for b in c3["claimed_brand_links"]])
        findings.append(Finding(
            module=MODULE_NAME, severity="medium", weight=10.0,
            title="Links point at the entity the sender claims to be",
            description=(
                f"The display name or subject names an entity whose own domain is linked ({names}), but the message was not "
                f"sent from that entity's domain ('{c3['sender_domain']}'). Linking the real service lends a lure credibility "
                "while the call to action goes elsewhere."),
            evidence={**c3, "structural": True, "family": FAMILY, "signal": "C3"},
        ))
    if mentions := body_brand_mentions(parsed):
        findings.append(Finding(
            module=MODULE_NAME, severity="info", weight=3.0,
            title="Body mentions a known brand the sender does not own",
            description=(f"The body mentions {', '.join(mentions)}. Common in benign mail; it adds a little to the score and "
                         "never counts toward the corroboration floor."),
            evidence={"brands": mentions, "signal": "C1b"},
        ))
    return findings
