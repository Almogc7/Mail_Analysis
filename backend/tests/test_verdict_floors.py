"""Low coverage / needs_review must NEVER downgrade a floor-based SUSPICIOUS or MALICIOUS verdict.

A floor means "a hard indicator fired"; uncertainty about OTHER evidence cannot erase it. Today the
`low_confidence_needs_review` override runs after the floors and can turn a floor-based SUSPICIOUS
into `needs_review`, which is a downgrade for anyone treating that as 'not flagged'.

The two floor-based SUSPICIOUS cases are strict xfails: they document the defect now, and because
they are strict they FAIL as soon as the verdict-model commit fixes it, which forces the xfail
markers to be removed in that same commit. The MALICIOUS case already holds and stays a normal test.
"""
import pytest

from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring

FLAGGED = {"suspicious", "malicious"}
XFAIL = pytest.mark.xfail(
    strict=True,
    reason="known defect: needs_review runs after the floors and can downgrade a floor-based SUSPICIOUS; "
    "fixed (and this marker removed) in the verdict-model commit",
)


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


def _auth_floor_with_low_coverage():
    # high auth finding => auth_check floor; auth coverage 0.4, enrichment errored (0), content 0.5
    auth = _auth([_f("auth_check", "high", 25, "display-name spoof"), _f("auth_check", "medium", 15, "second signal")])
    enrichment = ModuleResult(module="enrichment", status="error", findings=[], raw_data={"error": "x"})
    return [auth, enrichment, _content(script_coverage=0.5)]


def _enrichment_floor_with_low_coverage():
    # critical enrichment finding => enrichment floor; half the IOCs could not be checked
    enr = _enrichment(
        [_f("enrichment", "critical", 70, "Suspicious URL: u1"),
         _f("enrichment", "info", 0, "Enrichment incomplete for u2", ioc_value="u2")],
        iocs=("u1", "u2"),
    )
    return [_auth([], header_present=False), enr, _content(script_coverage=0.5)]


def _malicious_with_low_coverage():
    auth = _auth([_f("auth_check", "high", 100, "x")])
    enr = _enrichment(
        [_f("enrichment", "critical", 100, "Suspicious URL: u1"),
         _f("enrichment", "info", 0, "Enrichment incomplete for u1", ioc_value="u1"),
         _f("enrichment", "info", 0, "Enrichment incomplete for u2", ioc_value="u2")],
        iocs=("u1", "u2"),
    )  # no IOC could be fully checked -> enrichment coverage 0
    return [auth, enr, _content(script_coverage=0.5)]


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_auth_floor_with_low_coverage, id="auth-floor", marks=XFAIL),
        pytest.param(_enrichment_floor_with_low_coverage, id="enrichment-floor", marks=XFAIL),
        pytest.param(_malicious_with_low_coverage, id="malicious"),
    ],
)
def test_low_coverage_never_downgrades_a_floor_based_verdict(build):
    outcome = run_scoring(build())
    assert outcome.confidence < 0.6  # the scenario really is low-confidence
    assert outcome.verdict in FLAGGED, (outcome.verdict, [o.rule for o in outcome.breakdown.applied_overrides])


@pytest.mark.parametrize("build", [_auth_floor_with_low_coverage, _enrichment_floor_with_low_coverage],
                         ids=["auth-floor", "enrichment-floor"])
def test_the_defect_is_real_today_it_downgrades_to_needs_review(build):
    # Pins the current behaviour so the xfails above cannot pass or fail for the wrong reason: a
    # floor fired, then the low-confidence rule replaced the verdict.
    outcome = run_scoring(build())
    rules = [o.rule for o in outcome.breakdown.applied_overrides]
    assert outcome.verdict == "needs_review" and outcome.confidence < 0.6
    assert rules[-1] == "low_confidence_needs_review" and any(r.endswith("_floor") for r in rules)
