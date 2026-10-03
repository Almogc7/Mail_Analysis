"""Low coverage / needs_review must NEVER downgrade a floor-based SUSPICIOUS or MALICIOUS verdict.

A floor means "a hard indicator fired"; uncertainty about OTHER evidence cannot erase it. This was a known
defect (the low_confidence_needs_review override ran after the floors) pinned by strict xfails; it is fixed
and these are now ordinary tests. needs_review still applies when NO floor trigger exists.
"""
import pytest

from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring

FLAGGED = {"suspicious", "malicious"}


def _f(module, severity, weight, title="finding", **evidence):
    return Finding(module=module, severity=severity, title=title, description="d", evidence=evidence, weight=weight)


def _auth(findings, header_present=False):
    return ModuleResult(module="auth_check", status="ok", findings=findings,
                        raw_data={"auth_headers": {"header_present": header_present}, "identity": {}})


def _content(findings=(), script_coverage=1.0):
    return ModuleResult(module="content_analysis", status="ok", findings=list(findings),
                        raw_data={"script_coverage": script_coverage})


def _enrichment(findings=(), iocs=()):
    return ModuleResult(module="enrichment", status="ok", findings=list(findings), raw_data={i: {} for i in iocs})


def _errored_enrichment():
    return ModuleResult(module="enrichment", status="error", findings=[], raw_data={"error": "x"})


def auth_floor_low_coverage():
    auth = _auth([_f("auth_check", "high", 25, "display-name spoof"), _f("auth_check", "medium", 15, "second signal")])
    return [auth, _errored_enrichment(), _content(script_coverage=0.5)]


def enrichment_floor_low_coverage():
    enr = _enrichment(
        [_f("enrichment", "critical", 70, "Suspicious URL: u1"), _f("enrichment", "info", 0, "Enrichment incomplete for u2", ioc_value="u2")],
        iocs=("u1", "u2"),
    )
    return [_auth([], header_present=False), enr, _content(script_coverage=0.5)]


def content_floor_low_coverage():
    content = _content([_f("content_analysis", "high", 25, "a"), _f("content_analysis", "high", 25, "b")], script_coverage=0.5)
    return [_auth([], header_present=False), _errored_enrichment(), content]


def floor_trigger_but_score_already_suspicious():
    # the score alone (35) says suspicious, so no floor OVERRIDE is recorded -- yet a floor trigger exists
    auth = _auth([_f("auth_check", "high", 100, "x")])
    return [auth, _errored_enrichment(), _content(script_coverage=0.5)]


def malicious_low_coverage():
    auth = _auth([_f("auth_check", "high", 100, "x")])
    enr = _enrichment(
        [_f("enrichment", "critical", 100, "Suspicious URL: u1"), _f("enrichment", "info", 0, "Enrichment incomplete for u1", ioc_value="u1"),
         _f("enrichment", "info", 0, "Enrichment incomplete for u2", ioc_value="u2")],
        iocs=("u1", "u2"),
    )
    return [auth, enr, _content(script_coverage=0.5)]


@pytest.mark.parametrize(
    "build,expected",
    [
        (auth_floor_low_coverage, "suspicious"),
        (enrichment_floor_low_coverage, "suspicious"),
        (content_floor_low_coverage, "suspicious"),
        (floor_trigger_but_score_already_suspicious, "suspicious"),
        (malicious_low_coverage, "malicious"),
    ],
    ids=["auth-floor", "enrichment-floor", "content-floor", "floor-trigger-with-score-already-suspicious", "malicious"],
)
def test_low_coverage_never_downgrades_a_floor_based_verdict(build, expected):
    outcome = run_scoring(build())
    assert outcome.confidence < 0.6  # the scenario really is low-confidence
    assert outcome.verdict == expected, (outcome.verdict, [o.rule for o in outcome.breakdown.applied_overrides])


@pytest.mark.parametrize("build", [auth_floor_low_coverage, enrichment_floor_low_coverage, content_floor_low_coverage,
                                   floor_trigger_but_score_already_suspicious],
                         ids=["auth-floor", "enrichment-floor", "content-floor", "score-already-suspicious"])
def test_the_protection_is_recorded_so_the_analyst_can_see_why(build):
    outcome = run_scoring(build())
    rules = [o.rule for o in outcome.breakdown.applied_overrides]
    assert "floor_protects_verdict" in rules and "low_confidence_needs_review" not in rules
    protect = next(o for o in outcome.breakdown.applied_overrides if o.rule == "floor_protects_verdict")
    assert "hard indicator" in protect.reason and "not downgraded" in protect.reason and protect.effect == "verdict stays suspicious"


def test_needs_review_still_applies_when_no_floor_trigger_exists():
    # medium findings only: weighted score 14 (>= 10), no high/critical anywhere, low coverage
    auth = _auth([_f("auth_check", "medium", 20, "a"), _f("auth_check", "medium", 20, "b")])
    outcome = run_scoring([auth, _errored_enrichment(), _content(script_coverage=0.5)])
    rules = [o.rule for o in outcome.breakdown.applied_overrides]
    assert outcome.verdict == "needs_review" and rules == ["low_confidence_needs_review"]
    assert "floor_protects_verdict" not in rules


def test_a_score_only_suspicious_with_low_coverage_and_no_floor_is_still_needs_review():
    # weighted score >= 35 from MEDIUM findings alone: suspicious by score, no floor trigger, low confidence
    auth = _auth([_f("auth_check", "medium", 100, "a")])
    enr = _enrichment([_f("enrichment", "medium", 30, "Suspicious URL: u"), _f("enrichment", "info", 0, "Enrichment incomplete for v", ioc_value="v")], iocs=("u", "v"))
    outcome = run_scoring([auth, enr, _content(script_coverage=0.5)])
    assert outcome.breakdown.weighted_score >= 35  # the base bucket really was 'suspicious' by score alone
    assert outcome.verdict == "needs_review" and outcome.breakdown.applied_overrides[-1].rule == "low_confidence_needs_review"


def test_high_confidence_is_untouched_by_the_protection():
    outcome = run_scoring([_auth([_f("auth_check", "high", 25, "spoof")], header_present=True),
                           _enrichment(), _content()])
    rules = [o.rule for o in outcome.breakdown.applied_overrides]
    assert outcome.verdict == "suspicious" and "floor_protects_verdict" not in rules and "low_confidence_needs_review" not in rules


def test_a_clean_low_coverage_email_is_not_pushed_to_needs_review_or_flagged():
    outcome = run_scoring([_auth([], header_present=False), _errored_enrichment(), _content(script_coverage=0.5)])
    assert outcome.verdict == "legit" and not outcome.breakdown.applied_overrides  # score < 10: nothing to review
