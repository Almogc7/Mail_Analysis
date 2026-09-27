from app.content_analysis.brand_impersonation import check_brand_url_mismatch, detect_brand_in_body
from app.content_analysis.text_utils import estimate_script_coverage, get_searchable_text
from app.content_analysis.urgency import detect_urgency
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult

MODULE_NAME = "content_analysis"

GENERIC_GREETINGS: list[str] = [
    "dear customer",
    "dear user",
    "dear valued customer",
    "dear account holder",
    "dear member",
    "dear sir/madam",
    "to whom it may concern",
    # Hebrew -- drafted, not reviewed by a native speaker; correct/extend as needed.
    "לקוח יקר",  # "dear customer"
    "משתמש יקר",  # "dear user"
    "שלום רב",  # formal generic "hello"
]

_GREETING_LEAD_CHARS = 200


def _urgency_severity(match_count: int) -> str:
    if match_count >= 4:
        return "high"
    if match_count >= 2:
        return "medium"
    return "low"


def _urgency_finding(matches: list[str]) -> Finding:
    return Finding(
        module=MODULE_NAME,
        severity=_urgency_severity(len(matches)),
        title="Urgency/pressure language detected",
        description=f"Matched {len(matches)} urgency/pressure phrase(s): {', '.join(matches)}.",
        evidence={"matched_phrases": matches},
        weight=min(5.0 * len(matches), 25.0),
    )


def _brand_impersonation_finding(mismatches: list[dict]) -> Finding:
    first = mismatches[0]
    brands = ", ".join(sorted({m["brand"] for m in mismatches}))
    return Finding(
        module=MODULE_NAME,
        severity="high",
        title=f"Body content claims to be '{first['brand']}' but a linked URL doesn't match its domain",
        description=(
            f"Body mentions brand(s) [{brands}], but a link displaying "
            f"'{first['anchor_text']}' actually points to '{first['domain']}'."
        ),
        evidence={"mismatches": mismatches},
        weight=25.0,
    )


def _find_generic_greeting(text: str) -> str | None:
    lead = text[:_GREETING_LEAD_CHARS].lower()
    for greeting in GENERIC_GREETINGS:
        if greeting in lead:
            return greeting
    return None


def _greeting_mismatch_finding(greeting: str, urgency_matches: list[str]) -> Finding:
    return Finding(
        module=MODULE_NAME,
        severity="medium",
        title="Generic greeting combined with personalized account claim",
        description=(
            f"Email opens with a generic greeting ('{greeting}') but claims personalized/"
            f"account-specific action is needed: {', '.join(urgency_matches)}."
        ),
        evidence={"greeting": greeting, "urgency_phrases": urgency_matches},
        weight=15.0,
    )


def run_content_analysis(parsed: ParsedEmail) -> ModuleResult:
    text = get_searchable_text(parsed)
    findings: list[Finding] = []

    urgency_matches = detect_urgency(text)
    if urgency_matches:
        findings.append(_urgency_finding(urgency_matches))

    matched_brands = detect_brand_in_body(text)
    if matched_brands:
        mismatches = check_brand_url_mismatch(parsed, matched_brands)
        if mismatches:
            findings.append(_brand_impersonation_finding(mismatches))

    greeting = _find_generic_greeting(text)
    if greeting and urgency_matches:
        findings.append(_greeting_mismatch_finding(greeting, urgency_matches))

    raw_data = {"script_coverage": estimate_script_coverage(text)}
    return ModuleResult(module=MODULE_NAME, status="ok", findings=findings, raw_data=raw_data)


__all__ = ["run_content_analysis"]
