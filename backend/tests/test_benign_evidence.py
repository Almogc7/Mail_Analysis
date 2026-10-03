"""'Benign' requires POSITIVE evidence; 'no findings' is not evidence of safety. Everything else not flagged is
inconclusive (needs_review until the literal rename)."""
import pytest

from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring
from app.scoring.config import ScoringConfig
from app.scoring.overrides import benign_evidence_gaps


def _auth(*, trusted=True, dkim_pass=True, dkim_aligned=True, dmarc_pass=False, findings=(), status="ok"):
    headers = {
        "header_present": True,
        "trusted_receivers_configured": trusted,
        "dkim": {"evaluated": dkim_pass, "result": "pass" if dkim_pass else "not_evaluated"},
        "dmarc": {"evaluated": dmarc_pass, "result": "pass" if dmarc_pass else "not_evaluated"},
    }
    raw = {"auth_headers": headers, "identity": {}, "alignment": {"dkim": {"aligned": dkim_aligned if dkim_pass else None}}}
    return ModuleResult(module="auth_check", status=status, findings=list(findings), raw_data=raw)


def _enrichment(findings=()):
    return ModuleResult(module="enrichment", status="ok", findings=list(findings), raw_data={})


def _content(findings=(), coverage=1.0):
    return ModuleResult(module="content_analysis", status="ok", findings=list(findings), raw_data={"script_coverage": coverage})


def _f(module, severity, title="finding", weight=0.0):
    return Finding(module=module, severity=severity, title=title, description="d", evidence={}, weight=weight)


def _verdict(auth, enrichment=None, content=None):
    out = run_scoring([auth, enrichment or _enrichment(), content or _content()])
    return out.verdict, [o.rule for o in out.breakdown.applied_overrides]


# ---- what makes benign ------------------------------------------------------------------------------

def test_a_verified_aligned_dkim_pass_with_nothing_else_is_benign():
    assert _verdict(_auth()) == ("legit", [])


def test_a_trusted_dmarc_pass_alone_also_counts_as_positive_evidence():
    assert _verdict(_auth(dkim_pass=False, dmarc_pass=True)) == ("legit", [])


def test_info_findings_do_not_block_benign():
    auth = _auth(findings=[_f("auth_check", "info", "SPF not evaluated")])
    assert _verdict(auth, _enrichment([_f("enrichment", "info", "Enrichment incomplete for x")]))[0] == "legit"


# ---- each way it fails -------------------------------------------------------------------------------

def test_no_trusted_receiver_means_benign_is_unreachable():
    verdict, rules = _verdict(_auth(trusted=False, dkim_pass=False))
    assert verdict == "needs_review" and rules == ["no_positive_evidence_for_benign"]
    gaps = benign_evidence_gaps({"auth_check": _auth(trusted=False, dkim_pass=False)}, 1.0, ScoringConfig())
    assert "no trusted receiver is configured" in gaps[0]


def test_a_dkim_pass_that_is_not_aligned_with_the_from_domain_is_not_enough():
    verdict, _ = _verdict(_auth(dkim_aligned=False))
    assert verdict == "needs_review"  # signed by a third party (the ESP): says nothing about the From identity


def test_a_trusted_receiver_without_a_dkim_or_dmarc_pass_is_not_enough():
    verdict, rules = _verdict(_auth(dkim_pass=False, dmarc_pass=False))
    assert verdict == "needs_review" and rules == ["no_positive_evidence_for_benign"]
    gaps = benign_evidence_gaps({"auth_check": _auth(dkim_pass=False)}, 1.0, ScoringConfig())
    assert "no verified, aligned DKIM pass or DMARC pass" in gaps[0]


@pytest.mark.parametrize(
    "build",
    [
        lambda: (_auth(findings=[_f("auth_check", "low", "From header parse ambiguity")]), None, None),
        lambda: (_auth(), _enrichment([_f("enrichment", "low", "Not enriched: per-email limit reached (host)")]), None),
        lambda: (_auth(), None, _content([_f("content_analysis", "medium", "Urgency/pressure language detected", 10)])),
    ],
    ids=["low-auth-finding", "low-enrichment-finding", "medium-content-finding"],
)
def test_any_finding_above_info_blocks_benign(build):
    auth, enrichment, content = build()
    verdict, rules = _verdict(auth, enrichment, content)
    assert verdict == "needs_review" and "no_positive_evidence_for_benign" in rules


def test_low_coverage_blocks_benign_even_with_a_dkim_pass():
    # content in an unsupported language (0.25) and enrichment gone: confidence falls below the threshold
    out = run_scoring([_auth(), ModuleResult(module="enrichment", status="error", findings=[], raw_data={}), _content(coverage=0.25)])
    assert out.confidence < 0.6 and out.verdict == "needs_review"
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")
    assert "coverage is too low" in reason


def test_content_in_an_unsupported_language_is_never_the_reason_for_benign():
    unsupported = _content(coverage=0.25)
    # without authentication evidence, a quiet content result in a language we cannot read supports nothing
    assert _verdict(_auth(trusted=False, dkim_pass=False), content=unsupported)[0] == "needs_review"
    assert _verdict(_auth(trusted=False, dkim_pass=False), content=_content(coverage=1.0))[0] == "needs_review"  # nor does a covered one
    # benign comes from the verified authentication; the content result is not what supports it
    assert _verdict(_auth(), content=unsupported)[0] == "legit"


def test_the_reason_lists_every_gap_at_once():
    auth = _auth(trusted=False, dkim_pass=False, findings=[_f("auth_check", "low", "x")])
    out = run_scoring([auth, ModuleResult(module="enrichment", status="error", findings=[], raw_data={}), _content(coverage=0.25)])
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")
    for part in ("no trusted receiver", "finding(s) above info", "coverage is too low"):
        assert part in reason
    assert "not evidence of safety" in reason


# ---- flagged and floor-protected verdicts are untouched --------------------------------------------------

def test_a_floor_based_suspicious_is_never_turned_inconclusive_by_this_rule():
    auth = _auth(findings=[_f("auth_check", "high", "Possible display-name spoofing of 'x'", 25)])
    verdict, rules = _verdict(auth)
    assert verdict == "suspicious" and "no_positive_evidence_for_benign" not in rules


def test_a_malicious_verdict_is_untouched():
    auth = _auth(findings=[_f("auth_check", "high", "x", 100)])
    enr = _enrichment([_f("enrichment", "critical", "Suspicious host: x", 100)])
    assert run_scoring([auth, enr, _content()]).verdict == "malicious"


def test_an_errored_module_does_not_hide_or_contribute_findings():
    auth = _auth()
    broken = ModuleResult(module="enrichment", status="error", findings=[_f("enrichment", "critical", "ignored", 999)], raw_data={})
    gaps = benign_evidence_gaps({"auth_check": auth, "enrichment": broken}, 1.0, ScoringConfig())
    assert gaps == []  # findings of an errored module are ignored everywhere in scoring
