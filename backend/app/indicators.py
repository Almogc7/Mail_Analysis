"""Indicator pack: every domain, IP, email address and file hash in the message, in one list, with where it was seen, what
the automatic lookups said, and plain hyperlinks to look it up by hand.

This exists for the analyst who would otherwise open each threat-intelligence site one by one. It adds NOTHING to the score
and changes no verdict. Two rules keep it honest:

  * "Not looked up", "unknown" and "shared platform" are shown as things to CHECK BY HAND (manual_check=True), never as clean.
  * Pivot links are only strings. The app never contacts those sites for them; the analyst's click does. They carry a host,
    an IP or a hash, never a URL path or query (per-recipient tracking tokens live there).
"""
from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import quote, urlsplit

from app.contracts.analysis import Indicator, IndicatorPack, Pivot
from app.contracts.email import ParsedEmail
from app.contracts.findings import ModuleResult
from app.enrichment.policy import classify_host, host_of

_DOMAIN_PIVOTS = (
    ("VirusTotal", "https://www.virustotal.com/gui/domain/{v}"),
    ("urlscan.io", "https://urlscan.io/search/#page.domain%3A{v}"),
    ("ICANN lookup (registration, age)", "https://lookup.icann.org/en/lookup?name={v}"),
    ("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={v}"),
)
_IP_PIVOTS = (
    ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{v}"),
    ("AbuseIPDB", "https://www.abuseipdb.com/check/{v}"),
    ("Shodan", "https://www.shodan.io/host/{v}"),
    ("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={v}"),
)
_HASH_PIVOTS = (
    ("VirusTotal", "https://www.virustotal.com/gui/file/{v}"),
    ("MalwareBazaar", "https://bazaar.abuse.ch/sample/{v}/"),
    ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query={v}"),
)

_PROVIDER_KEYS = ("vt", "urlscan", "threatfox", "malwarebazaar")
_PROVIDER_NAMES = {"vt": "VirusTotal", "urlscan": "urlscan.io", "threatfox": "ThreatFox", "malwarebazaar": "MalwareBazaar"}
_ORDER = {"provider_hit": 0, "unknown": 1, "shared_platform": 2, "not_looked_up": 3, "internal": 4, "nothing_found": 5, "n/a": 6}


def _pivots(templates, value: str) -> list[Pivot]:
    safe = quote(value, safe="")
    return [Pivot(name=name, url=tpl.format(v=safe)) for name, tpl in templates]


def _provider_state(result: Any) -> str:
    """One short word per provider, so 'VirusTotal never saw this file' is not shown as 'failed'."""
    if not isinstance(result, dict):
        return "no answer"
    status = result.get("status")
    if status == "ok":
        return "answered"
    if status == "failed" and result.get("http_status") == 404:
        return "never seen by this source"
    if status == "disabled":
        return "disabled"
    if status in (None, "invalid_response"):
        return "no usable answer"
    return f"unavailable ({status})"


def _entry_for_host(raw: dict[str, Any], host: str) -> Any:
    if host in raw:
        return raw[host]
    for key, value in raw.items():  # path/query opt-in keys the lookups by full URL
        if "/" in key and host_of(key) == host:
            return value
    return None


def _assess(entry: Any, dropped: bool) -> tuple[str, str, dict[str, str]]:
    """(status, note, per-provider states) from one enrichment raw_data entry."""
    if entry is None:
        note = "Skipped: the per-email lookup limit was reached." if dropped else "Not looked up."
        return "not_looked_up", note + " Check it by hand.", {}
    if isinstance(entry, dict) and "uninformative" in entry:
        platform = entry["uninformative"].get("platform", "a shared platform")
        return ("shared_platform",
                f"Hosted on {platform}. Reputation of the platform says nothing about this page, so it was not looked up. "
                "Open the specific link in your sandbox.", {})
    if isinstance(entry, dict) and entry.get("internal_host_not_sent"):
        return "internal", "Internal-looking name; deliberately not sent to any outside service.", {}
    if not isinstance(entry, dict):
        return "unknown", "No usable lookup result. Check it by hand.", {}
    states = {_PROVIDER_NAMES[k]: _provider_state(entry[k]) for k in _PROVIDER_KEYS if k in entry}
    total = ((entry.get("risk_explain") or {}).get("total")) or 0
    if total > 0:
        return "provider_hit", "A lookup source reported something. See the enrichment findings for the detail.", states
    answered = [s for s in states.values() if s == "answered"]
    if not answered:
        return "unknown", "No source gave a usable answer, so this is UNKNOWN, not clean. Check it by hand.", states
    if len(answered) < len(states):
        return "unknown", "Some sources answered with nothing found, others did not: treat as unknown.", states
    return "nothing_found", "Every source that was asked reported nothing. That is not proof of safety.", states


class _Collector:
    def __init__(self, enrichment: dict[str, Any], dropped: set[str]) -> None:
        self.enrichment, self.dropped = enrichment, dropped
        self.items: dict[tuple[str, str], Indicator] = {}

    def add(self, kind: str, value: str, seen_in: str, **extra: Any) -> Indicator:
        key = (kind, value)
        item = self.items.get(key)
        if item is None:
            item = Indicator(kind=kind, value=value, **extra)
            self.items[key] = item
        item.count += 1
        if seen_in not in item.seen_in:
            item.seen_in.append(seen_in)
        for field, val in extra.items():
            if val and not getattr(item, field):
                setattr(item, field, val)
        return item


def build_indicator_pack(parsed: ParsedEmail, module_results: list[ModuleResult]) -> IndicatorPack:
    enrichment = next((m for m in module_results if m.module == "enrichment" and m.status == "ok"), None)
    raw = (enrichment.raw_data or {}) if enrichment is not None else {}
    dropped = {f.evidence.get("ioc_value") for f in (enrichment.findings if enrichment else []) if f.title.startswith("Not enriched:")}
    c = _Collector(raw, dropped)

    # ---- links and images -> hosts ------------------------------------------------------------------------------
    for u in parsed.urls:
        host = host_of(u.url)
        if not host:
            continue
        role = "link in the message"
        if u.source == "attachment":
            role = "link inside an attachment"
        elif u.anchor_text and u.source == "body_html":
            role = "clickable link (call to action)"
        if u.is_anchor_mismatch:
            role += ", text shows a different address"
        kind = "ip" if classify_host(host) in {"ip", "internal"} and _is_ip(host) else "domain"
        c.add(kind, host, role)
    for image in parsed.images:
        host = host_of(image.url)
        if host:
            c.add("ip" if _is_ip(host) else "domain", host, "image loaded by the message")

    # ---- sender side ----------------------------------------------------------------------------------------------
    for label, address in (("From", parsed.from_), ("Return-Path", parsed.return_path),
                           *[("Reply-To", a) for a in parsed.reply_to[:3]]):
        if address is None or not address.address:
            continue
        c.add("email", address.address.lower(), f"{label} address")
        if address.domain:
            c.add("domain", address.domain.lower(), f"{label} domain")

    # ---- network path ---------------------------------------------------------------------------------------------
    chain = parsed.received_chain
    for index, hop in enumerate(chain):
        origin = index == len(chain) - 1
        if hop.from_ip and _is_public_ip(hop.from_ip):
            c.add("ip", hop.from_ip, "origin hop (where the message entered the mail system)" if origin else "Received hop")
        if origin and hop.from_host and "." in hop.from_host:
            c.add("domain", hop.from_host.strip(".").lower(), "origin hop host name")

    # ---- attachments (hashes only; files are never opened) ----------------------------------------------------------
    for att in parsed.attachments:
        label = f"attachment ({att.content_type or 'unknown type'}, {att.size_bytes} bytes)"
        c.add("hash", att.sha256, label, filename=att.filename)

    items: list[Indicator] = []
    for item in c.items.values():
        if item.kind in ("domain", "ip") and classify_host(item.value) == "internal":
            # An internal-looking name or address is never sent anywhere by the app, and no lookup link is offered either: clicking one
            # would hand the internal name to a third party. It is UNKNOWN for the analyst to check, never clean.
            item.status = "internal"
            item.note = ("Internal-looking name or address: the app never sends it to any outside service, so it was not looked up, "
                         "and no lookup links are offered. Check it by hand.")
            item.providers, item.pivots = {}, []
        elif item.kind in ("domain", "ip"):
            entry = _entry_for_host(raw, item.value)
            item.status, item.note, item.providers = _assess(entry, item.value in dropped)
            if enrichment is None:
                item.status, item.note = "not_looked_up", "Enrichment did not run. Check it by hand."
            item.pivots = _pivots(_IP_PIVOTS if item.kind == "ip" else _DOMAIN_PIVOTS, item.value)
        elif item.kind == "hash":
            item.status, item.note, item.providers = _assess(raw.get(item.value), item.value in dropped)
            if enrichment is None:
                item.status, item.note = "not_looked_up", "Enrichment did not run. Check it by hand."
            if item.status == "unknown" and all(s in ("never seen by this source", "answered") for s in item.providers.values()):
                item.note = ("No source has a record of this file (never seen), which is common for new or targeted files and says "
                             "nothing either way. The app never opens or uploads attachments: inspect it in your sandbox.")
            item.pivots = _pivots(_HASH_PIVOTS, item.value)
        else:  # email
            item.status, item.note = "n/a", "Address seen in the headers; compare it with the display name and the story."
        item.manual_check = item.status in {"unknown", "shared_platform", "not_looked_up", "internal"}
        items.append(item)

    items.sort(key=lambda i: (_ORDER.get(i.status, 9), i.kind))
    counts: dict[str, int] = {}
    for i in items:
        counts[i.kind] = counts.get(i.kind, 0) + 1
    return IndicatorPack(indicators=items, counts=counts, manual_check_count=sum(i.manual_check for i in items))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
