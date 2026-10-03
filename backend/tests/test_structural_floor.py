"""The structural corroboration floor (docs/DETECTION_DESIGN.md): >= 2 DIFFERENT families, one family counts once."""
import tempfile
from pathlib import Path

import pytest

from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring
from app.scoring.config import ScoringConfig
from tests.eval import analyze


def _sig(family, signal, module="auth_check", weight=6.0, severity="low", structural=True):
    evidence = {"family": family, "signal": signal}
    if structural:
        evidence["structural"] = True
    return Finding(module=module, severity=severity, title=f"signal {signal}", description="d", evidence=evidence, weight=weight)


def _run(*findings, content_cov=1.0, config=None, enrichment_status="ok"):
    auth = ModuleResult(module="auth_check", status="ok", findings=[f for f in findings if f.module == "auth_check"],
                        raw_data={"auth_headers": {"header_present": False}, "identity": {}})
    content = ModuleResult(module="content_analysis", status="ok", findings=[f for f in findings if f.module == "content_analysis"],
                           raw_data={"script_coverage": content_cov})
    enrichment = ModuleResult(module="enrichment", status=enrichment_status, findings=[], raw_data={})
    return run_scoring([auth, enrichment, content], config)


def _rules(outcome):
    return [o.rule for o in outcome.breakdown.applied_overrides]


# ---- the rule ---------------------------------------------------------------------------------------

def test_two_different_families_floor_to_suspicious_and_say_which_and_why():
    out = _run(_sig("sender", "S2"), _sig("link", "L1", module="content_analysis"))
    assert out.verdict == "suspicious" and "structural_corroboration_floor" in _rules(out)
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "structural_corroboration_floor")
    assert "2 different families (link, sender)" in reason and "L1" in reason and "S2" in reason
    assert "No single family would have been enough" in reason


def test_three_families_also_floor():
    out = _run(_sig("sender", "S2"), _sig("link", "L2", module="content_analysis"), _sig("claim", "C3", module="content_analysis"))
    assert out.verdict == "suspicious" and "3 different families" in out.breakdown.applied_overrides[0].reason


def test_many_signals_in_ONE_family_never_floor():
    out = _run(_sig("sender", "S1", weight=15), _sig("sender", "S2"), _sig("sender", "S3", weight=10))
    assert out.verdict != "suspicious" and "structural_corroboration_floor" not in _rules(out)


def test_findings_without_the_structural_tag_or_a_family_do_not_count():
    out = _run(_sig("sender", "S2"), _sig("link", "L1", module="content_analysis", structural=False))
    assert "structural_corroboration_floor" not in _rules(out)
    untagged = Finding(module="content_analysis", severity="medium", title="x", description="d", evidence={"structural": True}, weight=8)
    assert "structural_corroboration_floor" not in _rules(_run(_sig("sender", "S2"), untagged))


def test_findings_of_an_errored_module_are_ignored():
    auth = ModuleResult(module="auth_check", status="ok", findings=[_sig("sender", "S2")], raw_data={"auth_headers": {}, "identity": {}})
    broken = ModuleResult(module="content_analysis", status="error", findings=[_sig("link", "L1", module="content_analysis")], raw_data={"error": "x"})
    out = run_scoring([auth, ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}), broken])
    assert "structural_corroboration_floor" not in _rules(out)


def test_the_minimum_number_of_families_is_a_config_value():
    cfg = ScoringConfig(structural_floor_min_families=3)
    assert "structural_corroboration_floor" not in _rules(_run(_sig("sender", "S2"), _sig("link", "L1", module="content_analysis"), config=cfg))
    assert _run(_sig("sender", "S2"), _sig("link", "L1", module="content_analysis"), _sig("claim", "C3", module="content_analysis"), config=cfg).verdict == "suspicious"
    assert ScoringConfig().structural_floor_min_families == 2  # the pre-registered value


def test_weak_signals_still_add_to_the_score_without_flagging():
    out = _run(_sig("link", "L2", module="content_analysis", weight=5), _sig("link", "L3", module="content_analysis", weight=5))
    content = next(c for c in out.breakdown.categories if c.category == "content_analysis")
    assert content.subscore == 10.0 and out.verdict != "suspicious"


# ---- interaction with the rest of the verdict model -------------------------------------------------------

def test_the_structural_floor_cannot_be_downgraded_by_low_coverage():
    out = _run(_sig("sender", "S2"), _sig("link", "L1", module="content_analysis"), content_cov=0.25, enrichment_status="error")
    assert out.confidence < 0.6 and out.verdict == "suspicious"
    assert "floor_protects_verdict" in _rules(out) or "structural_corroboration_floor" in _rules(out)
    assert "low_confidence_inconclusive" not in _rules(out)


def test_structural_findings_above_info_block_a_benign_verdict():
    out = _run(_sig("sender", "S2"))  # one family: not flagged, but a finding above info exists
    assert out.verdict == "inconclusive"


def test_a_floor_when_the_score_is_already_suspicious_still_protects_the_verdict():
    out = _run(_sig("sender", "S1", weight=100), _sig("link", "L1", module="content_analysis", weight=100), content_cov=0.25)
    assert out.verdict in ("suspicious", "malicious")


# ---- through the real pipeline ---------------------------------------------------------------------------

def _analyze(from_header, subject="Notice", body="hello"):
    raw = (f"From: {from_header}\r\nTo: t@example.com\r\nSubject: {subject}\r\nDate: Mon, 21 Sep 2026 10:00:00 +0000\r\n"
           f"Message-ID: <sf@x.example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").encode()
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.eml"
        path.write_bytes(raw)
        return analyze(path, "clean")


def test_apple_valley_dental_is_a_medium_finding_only_and_never_flagged():
    # a business literally named like a brand, sending from its own domain: one family (claim), MEDIUM, no floor
    result = _analyze('"Apple Valley Dental" <office@applevalleydental.example.org>', subject="Your appointment reminder")
    claim = next(f for f in result.findings if f.title.startswith("Possible display-name spoofing of 'apple'"))
    assert claim.severity == "medium" and claim.weight == 12.0
    assert claim.evidence["family"] == "claim" and claim.evidence["signal"] == "C1" and claim.evidence["structural"] is True
    assert result.verdict == "inconclusive"
    assert not any(o.rule.endswith("_floor") for o in result.scoring.applied_overrides)


def test_a_claim_plus_a_machine_provisioned_sender_is_two_families_and_floors():
    result = _analyze("PayPal Support <vnz73mailr@vh319.hosting.example.net>")
    assert result.verdict == "suspicious"
    floor = next(o for o in result.scoring.applied_overrides if o.rule == "structural_corroboration_floor")
    assert "claim" in floor.reason and "sender" in floor.reason and "C1" in floor.reason and "S1" in floor.reason


def test_the_fuzzy_lookalike_finding_is_not_a_structural_signal():
    result = _analyze("Paypall Billing <b@mailer.example.org>")
    fuzzy = next(f for f in result.findings if f.title.startswith("Display name resembles brand"))
    assert not fuzzy.evidence.get("structural") and result.verdict == "inconclusive"
