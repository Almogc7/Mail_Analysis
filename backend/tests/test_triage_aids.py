"""Inconclusive sub-reason and queue priority (docs/DETECTION_DESIGN.md)."""
from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring
from app.scoring.aggregate import inconclusive_reason, priority_score
from app.scoring.config import ScoringConfig


def _f(module, severity="low", weight=0.0, family=None, signal="X"):
    ev = {"structural": True, "family": family, "signal": signal} if family else {}
    return Finding(module=module, severity=severity, title="t", description="d", evidence=ev, weight=weight)


def _mods(auth=(), enr=(), content=(), enr_status="ok"):
    return {
        "auth_check": ModuleResult(module="auth_check", status="ok", findings=list(auth), raw_data={"auth_headers": {"header_present": False}, "identity": {}}),
        "enrichment": ModuleResult(module="enrichment", status=enr_status, findings=list(enr), raw_data={}),
        "content_analysis": ModuleResult(module="content_analysis", status="ok", findings=list(content), raw_data={"script_coverage": 1.0}),
    }


def _run(mods):
    return run_scoring(list(mods.values()), ScoringConfig(known_sender_domains=frozenset()))


def test_nothing_fired_is_inconclusive_for_lack_of_evidence():
    out = _run(_mods())
    assert out.verdict == "inconclusive" and out.breakdown.inconclusive_reason == "no_signals_insufficient_evidence"


def test_a_signal_that_was_not_enough_is_inconclusive_with_signals_present():
    out = _run(_mods(auth=[_f("auth_check", weight=6, family="sender", signal="S2")]))
    assert out.verdict == "inconclusive" and out.breakdown.inconclusive_reason == "signals_present"


def test_info_findings_are_not_signals():
    out = _run(_mods(auth=[_f("auth_check", severity="info")]))
    assert out.breakdown.inconclusive_reason == "no_signals_insufficient_evidence"


def test_the_reason_exists_only_for_inconclusive_verdicts():
    flagged = _run(_mods(auth=[_f("auth_check", weight=6, family="sender"), _f("content_analysis", weight=8, family="link")]))
    assert flagged.verdict == "suspicious" and flagged.breakdown.inconclusive_reason is None
    assert inconclusive_reason("benign", _mods()) is None and inconclusive_reason("malicious", _mods()) is None


def test_findings_of_an_errored_module_do_not_count_as_signals():
    mods = _mods(enr=[_f("enrichment", severity="critical", weight=99)], enr_status="error")
    assert inconclusive_reason("inconclusive", mods) == "no_signals_insufficient_evidence"
    assert priority_score(0.0, mods) == 0.0


def test_priority_formula_is_the_documented_one():
    assert priority_score(0.0, _mods()) == 0.0
    mods = _mods(auth=[_f("auth_check", family="sender")], content=[_f("content_analysis", family="link"), _f("content_analysis", family="link")])
    # 10 (score) + 5 * 2 families + 2 * 3 findings above info
    assert priority_score(10.0, mods) == 26.0


def test_priority_counts_a_family_once_and_caps_findings_and_total():
    many = _mods(auth=[_f("auth_check", family="sender") for _ in range(30)])
    assert priority_score(0.0, many) == 5.0 + 2.0 * 10  # one family, ten findings counted
    assert priority_score(95.0, many) == 100.0


def test_corroboration_ranks_above_a_single_signal_with_the_same_score():
    one = _mods(auth=[_f("auth_check", weight=6, family="sender")])
    two = _mods(auth=[_f("auth_check", weight=3, family="sender")], content=[_f("content_analysis", weight=3, family="link")])
    assert _run(two).breakdown.priority > _run(one).breakdown.priority


def test_the_priority_is_on_every_breakdown_not_only_inconclusive_ones():
    out = _run(_mods(auth=[_f("auth_check", weight=6, family="sender"), _f("content_analysis", weight=8, family="link")]))
    assert out.verdict == "suspicious" and out.breakdown.priority > 0
