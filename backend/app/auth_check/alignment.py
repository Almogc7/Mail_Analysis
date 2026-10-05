"""From / envelope / DKIM-d= alignment, and what it does and does not prove.

SPF authenticates the *envelope* sender (MAIL FROM) against the connecting IP; DKIM authenticates
a signing domain (d=); neither says anything about the visible From header unless the domain they
authenticated *aligns* with it (same registrable domain, "relaxed" alignment as in DMARC).

What a passing, aligned result proves -- and every finding below says so explicitly:
  * SPF: the sending IP is authorised by the envelope domain's DNS, and that domain is the From
    domain. It proves the sender controls that domain. It does NOT prove the domain is who the
    display name claims, nor that the content is safe: an attacker authorises their own
    infrastructure for their own domain (e.g. a throwaway or shared-hosting domain) as a matter of
    course, and a pass is the expected result.
  * DKIM: the message was signed by a key published under d= and not altered since. Same caveat.

All findings here have weight 0 except "no aligned authentication", which needs BOTH SPF and DKIM
evaluated by a trusted receiver (see spf_dkim_dmarc.evaluate_authentication) and neither aligned.
Alignment is only ever computed from results a trusted receiver established; an unevaluated method
yields no conclusion.
"""
from __future__ import annotations

from typing import Any

from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding
from app.finding_codes import code as finding_code
from app.shared.matching import registrable_domain

MODULE_NAME = "auth_check"


def _reg(domain: str | None) -> str | None:
    return registrable_domain(domain) if domain else None


def _aligned(a: str | None, b: str | None) -> bool | None:
    ra, rb = _reg(a), _reg(b)
    if ra is None or rb is None:
        return None  # cannot tell
    return ra == rb


def _envelope_domain(parsed: ParsedEmail, auth: dict[str, Any]) -> tuple[str | None, str | None]:
    """(domain, where it came from), preferring what a trusted receiver actually checked."""
    spf = auth["spf"]
    if spf["evaluated"] and spf["domain"]:
        return spf["domain"].lower(), "trusted SPF result"
    if parsed.return_path and parsed.return_path.domain:
        return parsed.return_path.domain, "Return-Path header"
    if parsed.received_chain and parsed.received_chain[-1].envelope_from:
        addr = parsed.received_chain[-1].envelope_from
        return addr.rsplit("@", 1)[-1].lower() if "@" in addr else None, "first-hop envelope-from"
    for spf_header in parsed.received_spf:
        if spf_header.envelope_from and "@" in spf_header.envelope_from:
            return spf_header.envelope_from.rsplit("@", 1)[-1].lower(), "Received-SPF header (unverified)"
    return None, None


def compute_alignment(parsed: ParsedEmail, auth: dict[str, Any]) -> dict[str, Any]:
    from_domain = parsed.from_.domain
    envelope_domain, envelope_source = _envelope_domain(parsed, auth)
    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]
    spf_aligned = _aligned(envelope_domain, from_domain) if spf["evaluated"] else None
    dkim_aligned = _aligned(dkim["domain"], from_domain) if dkim["evaluated"] and dkim["result"] == "pass" else None
    return {
        "from_domain": from_domain,
        "from_registrable_domain": _reg(from_domain),
        "envelope_domain": envelope_domain,
        "envelope_registrable_domain": _reg(envelope_domain),
        "envelope_source": envelope_source,
        "envelope_equals_from": _aligned(envelope_domain, from_domain),
        "spf": {"evaluated": spf["evaluated"], "result": spf["result"], "aligned": spf_aligned},
        "dkim": {"evaluated": dkim["evaluated"], "result": dkim["result"], "domain": dkim["domain"], "aligned": dkim_aligned},
        "dmarc": {"evaluated": dmarc["evaluated"], "result": dmarc["result"]},
    }


def alignment_findings(alignment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    frm = alignment["from_registrable_domain"] or alignment["from_domain"]
    env = alignment["envelope_registrable_domain"] or alignment["envelope_domain"]
    spf, dkim = alignment["spf"], alignment["dkim"]

    if spf["evaluated"] and spf["result"] == "pass":
        if spf["aligned"] is True:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title="SPF passed and aligns with the From domain",
                    code=finding_code("AUTH_ALIGN_SPF_ALIGNED"),
                    description=(
                        f"SPF authenticated the sending infrastructure only: the sending IP is authorised by "
                        f"'{env}' and the envelope domain equals the From domain ('{frm}'). This proves the sender "
                        f"controls '{frm}'; it does not show that '{frm}' is who the display name claims, and it "
                        "says nothing about what the message contains -- an attacker authorises their own servers for their own domain."
                    ),
                    evidence=alignment,
                    weight=0.0,
                )
            )
        elif spf["aligned"] is False:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title="SPF passed for a different domain than From",
                    code=finding_code("AUTH_ALIGN_SPF_OTHER_DOMAIN"),
                    description=(
                        f"SPF authenticated '{env}', which is not the From domain ('{frm}'), so it says nothing "
                        "about the visible sender. Normal for mail sent through an ESP; DMARC then relies on a "
                        "DKIM signature aligned with the From domain instead."
                    ),
                    evidence=alignment,
                    weight=0.0,
                )
            )

    if dkim["evaluated"] and dkim["result"] == "pass":
        if dkim["aligned"] is True:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title="DKIM passed and aligns with the From domain",
                    code=finding_code("AUTH_ALIGN_DKIM_ALIGNED"),
                    description=(
                        f"The message carries a valid DKIM signature from '{dkim['domain']}', the From domain's "
                        "registrable domain: it was signed with a key that domain publishes and not altered in "
                        "transit. This proves who signed it; it says nothing about what the message contains."
                    ),
                    evidence=alignment,
                    weight=0.0,
                )
            )
        elif dkim["aligned"] is False:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title="DKIM passed for a different domain than From",
                    code=finding_code("AUTH_ALIGN_DKIM_OTHER_DOMAIN"),
                    description=(
                        f"The valid DKIM signature is from '{dkim['domain']}', not the From domain ('{frm}'): "
                        "the signer is a third party (often the ESP) and vouches for nothing about the From identity."
                    ),
                    evidence=alignment,
                    weight=0.0,
                )
            )

    # Both evaluated by a trusted receiver, SPF PASSED for another domain, and DKIM neither aligned
    # nor failed (a fail already has its own high-severity finding).
    if (
        spf["evaluated"] and spf["result"] == "pass" and spf["aligned"] is False
        and dkim["evaluated"] and dkim["result"] != "fail" and dkim["aligned"] in (False, None)
    ):
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="medium",
                title="No authentication is aligned with the From domain",
                code=finding_code("AUTH_ALIGN_NONE_ALIGNED"),
                description=(
                    f"A trusted receiver evaluated SPF and DKIM, but neither authenticated the From domain "
                    f"('{frm}'): SPF covered '{env}'"
                    + (f" and DKIM was signed by '{dkim['domain']}'." if dkim["domain"] else " and there is no usable DKIM signature.")
                    + " Nothing ties the visible sender to any authenticated identity."
                ),
                evidence=alignment,
                weight=10.0,
            )
        )
    return findings
