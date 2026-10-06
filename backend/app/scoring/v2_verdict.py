"""From compute_tier's output to the response fields verdict_v2 and checks_completed (docs/PHASE_B_PREREGISTRATION.md 1.7 and 2). PURE: no I/O, no logging, nothing mutated.

Every string comes from app/verdict_v2_text.py (fixed text) or from the finding registry's content-free template; nothing is taken from the message. A finding reason points at its finding by index in
`analysis_result.findings` (evidence_ref), where the page shows the real title. The hard-evidence indicator is the defanged link host or URL, or the attachment hash, that the page already shows.
"""
from __future__ import annotations

from typing import Any

from app.contracts.analysis import ChecksCompleted, V2Blocker, V2HardEvidence, V2Reason, VerdictV2
from app.finding_codes import BY_CODE
from app.reason_classes import CLASSES
from app.verdict_v2_text import BLOCKER_TEXT, PSEUDO_REASON_KIND, PSEUDO_REASON_TEXT, TIER_KEYS, TIER_LABELS, blocker_text

_SUB_REASONS = ("signals_present", "no_signals_insufficient_evidence")


def count_checks(coverage_items: list[Any]) -> ChecksCompleted:
    """'Checks completed: N of M, K not checked' from the coverage report alone. M counts the items that apply and are not by design, N those with status checked, K the rest (not checked or partly);
    the by-design items are counted separately and are in none of the three."""
    counted = [item for item in coverage_items if not item.by_design]
    completed = sum(1 for item in counted if item.status == "checked")
    return ChecksCompleted(completed=completed, total=len(counted), not_checked=len(counted) - completed, by_design=len(coverage_items) - len(counted))


def _evidence_ref(findings: list[Any], code: str, severity: str) -> str | None:
    for index, finding in enumerate(findings):
        if finding.code == code and finding.severity == severity:
            return str(index)
    for index, finding in enumerate(findings):
        if finding.code == code:
            return str(index)
    return None


def assemble_verdict_v2(tier_output: dict, analysis_result: Any, blocker_items: list[dict]) -> VerdictV2:
    tier_key = TIER_KEYS[tier_output["tier"]]
    reasons: list[V2Reason] = []
    for item in tier_output["reasons"]:
        code, cls = item["code"], item["class"]
        if cls in CLASSES and code in BY_CODE:
            reasons.append(V2Reason(kind="finding", code=code, text=BY_CODE[code].description, evidence_ref=_evidence_ref(analysis_result.findings, code, item["severity"])))
        elif code in PSEUDO_REASON_TEXT:
            reasons.append(V2Reason(kind=PSEUDO_REASON_KIND[code], code=code, text=PSEUDO_REASON_TEXT[code]))
        elif code in BLOCKER_TEXT:  # a gap of a Needs analyst result that names a blocker
            reasons.append(V2Reason(kind="gap", code=code, text=blocker_text(code, None)[0]))
    hard = [V2HardEvidence(code=e["rule"], indicator=e["indicator"], source=e["source"]) for e in tier_output["hard_evidence"]]

    shown: set[tuple[str, str | None]] = set()
    blockers: list[V2Blocker] = []
    for item in blocker_items:
        text, how = blocker_text(item["code"], item["detail"])
        blockers.append(V2Blocker(code=item["code"], detail=item["detail"], text=text, how_to_clear=how))
        shown.add((item["code"], item["detail"]))
    for code in tier_output["blockers"]:  # a code the function added itself (an unknown finding code) has no item
        if not any(shown_code == code for shown_code, _d in shown):
            text, how = blocker_text(code, None)
            blockers.append(V2Blocker(code=code, detail=None, text=text, how_to_clear=how))

    needs = next((r for r in tier_output["needs_analyst_reason"] if r in _SUB_REASONS), None)
    priority = analysis_result.scoring.priority if tier_key == "needs_analyst" and analysis_result.scoring is not None else None
    return VerdictV2(tier=tier_key, label=TIER_LABELS[tier_key], route=tier_output["route_id"], reasons=reasons, hard_evidence=hard, blockers=blockers,
                     needs_analyst_reason=needs, priority=priority)
