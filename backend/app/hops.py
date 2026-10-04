"""Hiding the analyst's own hops, and the trust boundary that limits it.

INTERNAL_HOP_PATTERNS (untracked backend/.env, JSON array of regexes, matched case-insensitively against the host name) names the analyst's own
systems, for example the mail gateway and the mail-security service.

SAFETY RULE. A Received line is text, and every hop BELOW the first trusted hop was written before the message reached the analyst's own
infrastructure, so the sender controls it. An attacker can forge a line that claims an internal host or a private address. So a hop may be hidden
only when ALL of these hold:
  1. It sits at or above the first trusted hop (the oldest hop that wrote an authentication result the app trusts: see auth_check). Hops
     below that boundary are never hidden, whatever they claim, and are labelled "claimed / unverified". With NO trusted hop there is no
     boundary, so nothing is hidden and every hop is labelled unverified.
  2. Its SENDING side (the `from` host) matches a pattern, or its RECEIVING side (the `by` host) matches one AND the sender's address is private
     or missing (one of your own machines handing the message to another of your own systems).
A hop where an OUTSIDE server (public address) hands the message to one of your systems is not hidden: that address is the best evidence of where
the message came from.

Hiding is DISPLAY ONLY. Scoring, coverage, blockers and the trusted-receiver check always see the full chain; the raw headers are never touched. The
response says how many hops were hidden, and carries no name or address of a hidden hop.
"""
import ipaddress
import re

from app import config
from app.contracts.findings import ModuleResult


def _compiled() -> list[re.Pattern]:
    patterns = []
    for pattern in config.INTERNAL_HOP_PATTERNS:
        try:
            patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"INTERNAL_HOP_PATTERNS has an invalid regex ({exc})") from exc
    return patterns


def _matches(host: str | None, patterns: list[re.Pattern]) -> bool:
    host = (host or "").strip(".").lower()
    return bool(host) and any(p.search(host) for p in patterns)


def _public_address(value: str | None) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip("[]")).is_global
    except ValueError:
        return False


def is_internal_hop(hop) -> bool:
    """Whether the hop LOOKS like one of the analyst's own systems. This alone never hides anything: see hidden_indexes."""
    patterns = _compiled()
    if not patterns:
        return False
    if _matches(getattr(hop, "from_host", None), patterns):
        return True
    return _matches(getattr(hop, "by_host", None), patterns) and not _public_address(getattr(hop, "from_ip", None))


def trusted_hop_indexes(auth: ModuleResult | None) -> set[int]:
    """Newest-first indexes of the hops that wrote an authentication result the app trusts (host AND hop evidence)."""
    found: set[int] = set()
    if auth is None or auth.status != "ok":
        return found
    for method in ("spf", "dkim", "dmarc"):
        entry = ((auth.raw_data or {}).get("auth_headers") or {}).get(method) or {}
        hop_index = (entry.get("trust_basis") or {}).get("hop_index")
        if entry.get("evaluated") and isinstance(hop_index, int):
            found.add(hop_index)
    return found


def trust_boundary(auth: ModuleResult | None) -> int | None:
    """Newest-first index of the OLDEST trusted hop; hops with a larger index are below it. None when no hop is trusted."""
    indexes = trusted_hop_indexes(auth)
    return max(indexes) if indexes else None


def is_unverified(index: int, boundary: int | None) -> bool:
    return boundary is None or index > boundary


def hidden_indexes(chain, auth: ModuleResult | None) -> set[int]:
    """Newest-first indexes of the hops the analyst's config hides: looks internal AND at or above the trust boundary."""
    boundary = trust_boundary(auth)
    if boundary is None:
        return set()
    return {i for i, hop in enumerate(chain) if i <= boundary and is_internal_hop(hop)}
