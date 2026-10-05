"""Link-family signals (docs/DETECTION_DESIGN.md): L1 platform-mismatched click tracker, L2 hot-linked third-party
assets, L3 redirector chain. All three are tagged family 'link', so together they count ONCE toward the structural
corroboration floor; they are weak on their own and matter only next to evidence from another family.

The platform list (enrichment/shared_platforms.json) says which hosts ARE trackers, wrappers and shorteners. It never
decides whether a message legitimately used one: L1 compares the tracker against the OBSERVED SENDING PATH.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding
from app.enrichment.policy import platform_of
from app.finding_codes import code as finding_code
from app.parser.preprocess import clean_subject
from app.shared.matching import registrable_domain

MODULE_NAME = "content_analysis"
FAMILY = "link"

_MIN_IMAGES = 2
_DOMINANT_SHARE = 0.5
_MIN_LABEL_LEN = 4


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.strip(".").lower() if host else None


def _reg(host: str | None) -> str | None:
    return (registrable_domain(host) or host) if host else None


def _clickable_hosts(parsed: ParsedEmail) -> list[str]:
    """Hosts of links a recipient can click (body text/HTML). Attachments are never opened, and images are separate."""
    return [h for u in parsed.urls if u.source != "attachment" and (h := _host(u.url))]


def _dkim_domains(parsed: ParsedEmail) -> set[str]:
    """The d= of every DKIM-Signature header: the domain that took responsibility for the message."""
    found: set[str] = set()
    for header in parsed.headers:
        if header.name.lower() != "dkim-signature":
            continue
        for part in header.value.split(";"):
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "d" and value.strip():
                found.add(value.strip().strip(".").lower())
    return found


def _unsubscribe_hosts(parsed: ParsedEmail) -> set[str]:
    hosts: set[str] = set()
    for header in parsed.headers:
        if header.name.lower() == "list-unsubscribe":
            for token in header.value.replace("<", " ").replace(">", " ").replace(",", " ").split():
                if token.lower().startswith(("http://", "https://")) and (h := _host(token)):
                    hosts.add(h)
    return hosts


def sending_path(parsed: ParsedEmail) -> dict[str, set[str]]:
    """What the message itself says about how it was sent: Received hop hosts, DKIM d=, envelope domains (Return-Path,
    Received-SPF, a hop's envelope-from), List-Unsubscribe hosts, the Message-ID domain. Each entry is a claim the sender
    controls EXCEPT the hop hosts added by receivers; L1 only asks whether the tracker's platform appears anywhere, so a
    sender cannot create a mismatch by lying -- only avoid one, which costs it the thing L1 is measuring."""
    hops: set[str] = set()
    envelope: set[str] = set()
    for hop in parsed.received_chain:
        for host in (hop.from_host, hop.by_host):
            if host and "." in host:
                hops.add(host.strip(".").lower())
        if hop.envelope_from and "@" in hop.envelope_from:
            envelope.add(hop.envelope_from.rsplit("@", 1)[1].strip("<>. ").lower())
    if parsed.return_path and parsed.return_path.domain:
        envelope.add(parsed.return_path.domain.lower())
    for spf in parsed.received_spf:
        if spf.envelope_from and "@" in spf.envelope_from:
            envelope.add(spf.envelope_from.rsplit("@", 1)[1].strip("<>. ").lower())
    message_id: set[str] = set()
    if parsed.message_id and "@" in parsed.message_id:
        message_id.add(parsed.message_id.rsplit("@", 1)[1].strip("<>. ").lower())
    return {"received_hops": hops, "dkim_d": _dkim_domains(parsed), "envelope": envelope,
            "list_unsubscribe": _unsubscribe_hosts(parsed), "message_id": message_id}


def _same_organisation(path_host: str, platform_name: str, tracker_registrables: set[str | None]) -> bool:
    platform = platform_of(path_host)
    return (platform is not None and platform.name == platform_name) or _reg(path_host) in tracker_registrables


def platform_mismatched_trackers(parsed: ParsedEmail) -> dict | None:
    """L1. A clickable link goes through an ESP click tracker, but nothing in the observed sending path involves that
    platform. A real send through the platform leaves a trace (its relay in the hops, its DKIM d=, its envelope domain,
    its unsubscribe host); a message that borrowed the tracker's reputation, or reused a cloned template's links, does
    not. Not decidable without a sending path (stripped headers), so no path means no signal."""
    trackers: dict[str, set[str]] = {}
    for host in _clickable_hosts(parsed):
        platform = platform_of(host)
        if platform is not None and platform.kind == "esp_tracker":
            trackers.setdefault(platform.name, set()).add(host)
    if not trackers:
        return None
    path = sending_path(parsed)
    path_hosts = set().union(*path.values())
    if not path_hosts:
        return None
    # Branded ESP sending (CNAME'd return-path, DKIM d= on the From domain) is the standard documented ESP setup, so the
    # platform's own name is EXPECTED to be absent from the path and its absence is not evidence. That reading is only
    # available when the message came in over the network: a local submission means the mail was composed on the box that
    # sent it, with no platform in between, however the identifiers are named.
    first = parsed.received_chain[-1] if parsed.received_chain else None
    local_origin = bool(first and first.is_local_submission and not first.authenticated)
    sender = _reg(parsed.from_.domain)
    sender_aligned = sender is not None and sender in {_reg(h) for h in path["dkim_d"] | path["envelope"]}
    if sender_aligned and not local_origin:
        return None
    mismatched = {}
    for name, hosts in trackers.items():
        regs = {_reg(h) for h in hosts}
        if not any(_same_organisation(p, name, regs) for p in path_hosts):
            mismatched[name] = sorted(hosts)
    if not mismatched:
        return None
    return {"platforms": sorted(mismatched), "tracker_hosts": mismatched, "local_submission_origin": local_origin,
            "path_aligned_with_sender": sender_aligned, "path_elements_checked": {k: len(v) for k, v in path.items()}}


def hot_linked_assets(parsed: ParsedEmail) -> dict | None:
    """L2. At least two images, and at least half of them, come from ONE non-platform registrable domain that is not the
    sender's, AND that domain also hosts some of the message's links (or its name is a token of the display name or
    subject). A cloned template keeps the original vendor's assets and links. Images from an unrelated CDN or stock site
    that the links never use are not evidence of anything."""
    if len(parsed.images) < _MIN_IMAGES:
        return None
    sender = _reg(parsed.from_.domain)
    counts: dict[str, int] = {}
    for image in parsed.images:
        host = _host(image.url)
        if host and platform_of(host) is None and (reg := _reg(host)) and reg != sender:
            counts[reg] = counts.get(reg, 0) + 1
    if not counts:
        return None
    reg, n = max(counts.items(), key=lambda item: item[1])
    if n < _MIN_IMAGES or n / len(parsed.images) < _DOMINANT_SHARE:
        return None
    link_regs = {_reg(h) for h in _clickable_hosts(parsed)}
    subject, _ = clean_subject(parsed.subject)
    named = " ".join(filter(None, [parsed.from_.display_name, subject])).lower()
    label = reg.split(".")[0]
    in_name = len(label) >= _MIN_LABEL_LEN and label in named.replace("-", " ").split()
    if reg not in link_regs and not in_name:
        return None
    return {"asset_domain": reg, "images_from_it": n, "images_total": len(parsed.images),
            "also_hosts_links": reg in link_regs, "named_in_display_or_subject": in_name}


def redirector_links(parsed: ParsedEmail) -> dict | None:
    """L3. A link is a known URL shortener, or carries another full URL in its query string that points to a different
    registrable domain (an open redirect). Gateway wrappers and ESP trackers are excluded (their purpose is to rewrite
    links; L1 judges trackers), and so are links back to the sender's own domain."""
    sender = _reg(parsed.from_.domain)
    shorteners: set[str] = set()
    redirects: set[str] = set()
    for u in parsed.urls:
        if u.source == "attachment":
            continue
        host = _host(u.url)
        if not host or _reg(host) == sender:
            continue
        platform = platform_of(host)
        if platform is not None and platform.kind in ("link_wrapper", "esp_tracker"):
            continue
        if platform is not None and platform.kind == "shortener":
            shorteners.add(host)
            continue
        try:
            query = parse_qsl(urlsplit(u.url).query)
        except ValueError:
            continue
        for _, value in query:
            if value.lower().startswith(("http://", "https://")):
                target = _host(value)
                if target and _reg(target) != _reg(host):
                    redirects.add(host)
                    break
    if not shorteners and not redirects:
        return None
    return {"shorteners": sorted(shorteners), "open_redirect_hosts": sorted(redirects)}


# The finding code of each link signal (one code per kind; see app/finding_codes.py).
_CODES = {"L1": "CONTENT_LINK_TRACKER_PLATFORM_MISMATCH", "L2": "CONTENT_LINK_HOTLINKED_ASSETS", "L3": "CONTENT_LINK_REDIRECTOR"}


def _finding(signal: str, severity: str, weight: float, title: str, description: str, evidence: dict) -> Finding:
    return Finding(module=MODULE_NAME, severity=severity, title=title, description=description, weight=weight, code=finding_code(_CODES[signal]),
                   evidence={**evidence, "structural": True, "family": FAMILY, "signal": signal})


def link_findings(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    if (l1 := platform_mismatched_trackers(parsed)) is not None:
        findings.append(_finding(
            "L1", "medium", 8.0, "Click tracker of a platform that did not send this message",
            f"A link goes through the click tracker of {', '.join(l1['platforms'])}, but nothing in the sending path "
            "(Received hops, DKIM d=, envelope domain, List-Unsubscribe, Message-ID) involves that platform. A message "
            "really sent through it leaves a trace; one that borrowed its links or reputation does not.", l1))
    if (l2 := hot_linked_assets(parsed)) is not None:
        findings.append(_finding(
            "L2", "low", 5.0, "Images hot-linked from a third party that also hosts the links",
            f"{l2['images_from_it']} of {l2['images_total']} images load from '{l2['asset_domain']}', which is not the sender's "
            "domain" + (" and also hosts links in the message" if l2["also_hosts_links"] else " but is named in the sender or subject")
            + ". Cloned templates keep the original vendor's assets and links.", l2))
    if (l3 := redirector_links(parsed)) is not None:
        findings.append(_finding(
            "L3", "low", 5.0, "Link goes through a shortener or open redirect",
            "A link hides its destination behind a URL shortener or carries another URL in its query string, "
            "which borrows the redirector's reputation.", l3))
    return findings
