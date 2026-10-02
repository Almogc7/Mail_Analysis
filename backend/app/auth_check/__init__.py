from app.auth_check.spf_dkim_dmarc import check_auth_headers
from app.auth_check.spoofing import check_identity_mismatch
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult

_FAIL_RESULTS = {"fail", "softfail", "permerror"}

MODULE_NAME = "auth_check"


def _auth_findings(auth: dict) -> list[Finding]:
    findings: list[Finding] = []

    for method in ("spf", "dkim", "dmarc"):
        result = auth[method]["result"]
        if result in _FAIL_RESULTS:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="high" if result == "fail" else "medium",
                    title=f"{method.upper()} check failed",
                    description=f"{method.upper()} authentication result was '{result}'.",
                    evidence={"raw": auth[method]["raw"], "domain": auth[method]["domain"]},
                    weight=25.0 if result == "fail" else 15.0,
                )
            )
        elif result == "none" and not auth["header_present"]:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title=f"No {method.upper()} data available",
                    description="No Authentication-Results header was present on this message.",
                    evidence={},
                    weight=0.0,
                )
            )

    if auth["header_present"] and all(auth[m]["result"] == "pass" for m in ("spf", "dkim", "dmarc")):
        # Module 2 otherwise only ever reports failures -- without this, a cleanly
        # authenticated email renders identically to "no Authentication-Results header at
        # all" (both show zero findings), which reads as "couldn't check" rather than
        # "checked and confirmed clean". info/weight=0: visibility only, no scoring effect.
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="info",
                title="SPF/DKIM/DMARC all passed",
                description="Authentication-Results confirmed SPF, DKIM, and DMARC all passed for this message.",
                evidence={
                    "spf_domain": auth["spf"]["domain"],
                    "dkim_domain": auth["dkim"]["domain"],
                    "dmarc_domain": auth["dmarc"]["domain"],
                },
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

    return findings


def run_auth_check(parsed: ParsedEmail) -> ModuleResult:
    auth = check_auth_headers(parsed.authentication_results_raw)
    identity = check_identity_mismatch(parsed)

    findings = _auth_findings(auth) + _identity_findings(identity)

    return ModuleResult(
        module=MODULE_NAME,
        status="ok",
        findings=findings,
        raw_data={"auth_headers": auth, "identity": identity},
    )


__all__ = ["run_auth_check", "check_auth_headers", "check_identity_mismatch"]
