from app.auth_check.alignment import alignment_findings, compute_alignment
from app.auth_check.spf_dkim_dmarc import check_auth_headers, evaluate_authentication
from app.auth_check.spoofing import check_identity_mismatch
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.parser.addresses import AMBIGUITY_PREFIX

_FAIL_RESULTS = {"fail", "softfail", "permerror"}
_UNTRUSTED_FAIL_WEIGHT = 4.0

MODULE_NAME = "auth_check"


_REASON_TEXT = {
    "no_trusted_receivers_configured": (
        "No trusted receivers are configured (TRUSTED_RECEIVER_PATTERNS is empty), so authentication "
        "results in the headers cannot be relied on: any hop, including the sender's, can add them."
    ),
    "claim_from_untrusted_source": (
        "The only result for this method came from a host that is not a configured trusted receiver "
        "(or is not a hop in the Received chain), so it was ignored."
    ),
    "receiver_evaluated_spf_only": (
        "The trusted receiver evaluated SPF only (x-conformance=spf_only); it did not evaluate "
        "DKIM or DMARC."
    ),
    "no_trusted_result": "No trusted receiver reported a result for this method.",
}


def _auth_findings(auth: dict) -> list[Finding]:
    """Findings only ever come from results a TRUSTED receiver established. A pass has no
    scoring effect (weight 0): it proves who authorized the sending infrastructure, never that
    the message is benign."""
    findings: list[Finding] = []

    for method in ("spf", "dkim", "dmarc"):
        entry = auth[method]
        result = entry["result"]
        if result in _FAIL_RESULTS:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="high" if result == "fail" else "medium",
                    title=f"{method.upper()} check failed",
                    description=f"{method.upper()} authentication result was '{result}' (reported by a trusted receiver).",
                    evidence={"raw": entry["raw"], "domain": entry["domain"], "trust_basis": entry["trust_basis"]},
                    weight=25.0 if result == "fail" else 15.0,
                )
            )
        elif not entry["evaluated"]:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title=f"{method.upper()} not evaluated",
                    description=_REASON_TEXT[entry["reason"]],
                    evidence={
                        "reason": entry["reason"],
                        "claims": [c for c in auth["claims"] if c["method"] == method],
                    },
                    weight=0.0,
                )
            )

    if all(auth[m]["evaluated"] and auth[m]["result"] == "pass" for m in ("spf", "dkim", "dmarc")):
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="info",
                title="SPF/DKIM/DMARC all passed",
                description=(
                    "A trusted receiver reported SPF, DKIM and DMARC all passed. This authenticates the "
                    "sending infrastructure and domain; it does not make the content safe."
                ),
                evidence={
                    "spf_domain": auth["spf"]["domain"],
                    "dkim_domain": auth["dkim"]["domain"],
                    "dmarc_domain": auth["dmarc"]["domain"],
                },
                weight=0.0,
            )
        )

    # An untrusted PASS is worth nothing, but an untrusted FAIL is a weak signal: an attacker has no
    # reason to forge a failure. Low weight because stale or forwarded upstream results also fail.
    for method in ("spf", "dkim", "dmarc"):
        fails = [c for c in auth["claims"] if c["method"] == method and not c["trusted"] and c["result"] in _FAIL_RESULTS]
        if fails and not auth[method]["evaluated"]:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="low",
                    title=f"{method.upper()} failure claimed by an untrusted source",
                    description=(
                        f"A header from '{fails[0]['host']}' reports {method.upper()} '{fails[0]['result']}', but that "
                        "host is not a configured trusted receiver, so it is not treated as established. Scored as a "
                        "weak signal only: forging a failure gains an attacker nothing, but forwarded or stale "
                        "upstream results can fail legitimately."
                    ),
                    evidence={"claims": fails},
                    weight=_UNTRUSTED_FAIL_WEIGHT,
                )
            )

    for method in ("spf", "dkim", "dmarc"):
        basis = auth[method]["trust_basis"]
        if basis and basis.get("positional_ok") is False:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title=f"Trusted {method.upper()} result sits below its receiving hop's Received line",
                    description=(
                        "The header normally appears above the Received line of the hop that added it. Here it is below, "
                        "so it was present before that hop handled the message. Exchange and some gateways reorder "
                        "headers, so this is a reason to look closer, not proof of forgery. It does not change the "
                        "result (trust is decided by host + hop evidence)."
                    ),
                    evidence={"trust_basis": basis},
                    weight=0.0,
                )
            )
            break

    untrusted = [c for c in auth["claims"] if not c["trusted"]]
    if untrusted:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="info",
                title="Authentication claims from untrusted sources were ignored",
                description=(
                    f"{len(untrusted)} SPF/DKIM/DMARC claim(s) in the headers were not added by a configured "
                    "trusted receiver and have no effect on the verdict (a sender can write any such header)."
                ),
                evidence={"claims": untrusted},
                weight=0.0,
            )
        )

    return findings


def _identity_findings(identity: dict) -> list[Finding]:
    findings: list[Finding] = []

    rp = identity["from_return_path_mismatch"]
    if rp["mismatch"]:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="low",
                title="From / Return-Path domain mismatch",
                description=(
                    f"From domain '{rp['from_domain']}' differs from Return-Path domain "
                    f"'{rp['return_path_domain']}'. Common with legitimate ESPs — treat as a "
                    "weak signal on its own."
                ),
                evidence=rp,
                weight=5.0,
            )
        )

    rt = identity["from_reply_to_mismatch"]
    if rt["mismatch"]:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="medium",
                title="From / Reply-To domain mismatch",
                description=(
                    f"From domain '{rt['from_domain']}' differs from Reply-To domain "
                    f"'{rt['reply_to_domain']}'. Common phishing pattern to redirect replies."
                ),
                evidence=rt,
                weight=15.0,
            )
        )

    spoof = identity["display_name_spoofing"]
    if spoof["suspected"]:
        via = spoof.get("normalization")
        evasion = f" (matched after {via} folding -- deliberate look-alike characters)" if via in ("homoglyph", "leet") else ""
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="high",
                title=f"Possible display-name spoofing of '{spoof['claimed_brand']}'",
                description=(
                    f"From display name contains the brand '{spoof['claimed_brand']}' as a whole word{evasion} "
                    f"but the sending domain '{spoof['actual_domain']}' is not one of that brand's known domains."
                ),
                evidence=spoof,
                weight=25.0,
            )
        )
    elif spoof["fuzzy_suspected"]:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="medium",
                title=f"Display name resembles brand '{spoof['claimed_brand']}'",
                description=(
                    f"From display name is one character away from the brand '{spoof['claimed_brand']}' "
                    f"and the sending domain '{spoof['actual_domain']}' is not one of its known domains. "
                    "Fuzzy-only match: possible typosquat, but not enough alone to raise the verdict floor."
                ),
                evidence=spoof,
                weight=10.0,
            )
        )

    hosting = identity["hosting_fqdn_sender"]
    if hosting["suspected"]:
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="medium",
                title="Machine-provisioned sender claiming a brand",
                description=(
                    f"The {hosting['brand_source'].replace('_', ' ')} references '{hosting['brand']}', but the sender "
                    f"looks machine-provisioned: {'; '.join(hosting['indicators'])}. Mail sent from a hosting "
                    "provider's server identity rather than the brand's own infrastructure is a common phishing pattern."
                ),
                evidence=hosting,
                weight=15.0,
            )
        )

    return findings


def _from_ambiguity_findings(parsed: ParsedEmail) -> list[Finding]:
    """Informational only (weight 0): the From header was not a clean 'Display <address>'. The extractor recovered
    an address so sender checks still run, but the analyst should know the sender line is sloppy or tricky.
    It must never score on its own -- plenty of benign senders have a sloppy header."""
    prefix = f"{AMBIGUITY_PREFIX}:from: "
    reasons = [w[len(prefix):] for w in parsed.parse_warnings if w.startswith(prefix)]
    if not reasons:
        return []
    return [
        Finding(
            module=MODULE_NAME,
            severity="low",
            title="From header parse ambiguity",
            description=(
                "The From header is not a clean single 'Display <address>' (" + "; ".join(reasons) + "). "
                f"The sender address used for checks is '{parsed.from_.address}'. Informational: this does not "
                "affect the score by itself."
            ),
            evidence={"reasons": reasons, "address_used": parsed.from_.address, "domain_used": parsed.from_.domain},
            weight=0.0,
        )
    ]


def run_auth_check(parsed: ParsedEmail) -> ModuleResult:
    auth = evaluate_authentication(
        parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain, headers=parsed.headers
    )
    identity = check_identity_mismatch(parsed)

    alignment = compute_alignment(parsed, auth)
    findings = _auth_findings(auth) + alignment_findings(alignment) + _identity_findings(identity) + _from_ambiguity_findings(parsed)

    return ModuleResult(
        module=MODULE_NAME,
        status="ok",
        findings=findings,
        raw_data={"auth_headers": auth, "identity": identity, "alignment": alignment},
    )


__all__ = ["run_auth_check", "check_auth_headers", "check_identity_mismatch"]
