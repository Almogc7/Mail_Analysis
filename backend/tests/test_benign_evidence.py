"""'Benign' requires POSITIVE evidence; 'no findings' is not evidence of safety. Everything else not flagged is
inconclusive (inconclusive until the literal rename)."""
import pytest

from app.contracts.findings import Finding, ModuleResult
from app.scoring import run_scoring
from app.scoring.config import ScoringConfig
from app.scoring.overrides import benign_evidence_gaps

KNOWN = ScoringConfig(known_sender_domains=frozenset({"sender.example"}))  # a deployment with this sender configured


def _auth(*, trusted=True, dkim_pass=True, dkim_aligned=True, dmarc_pass=False, findings=(), status="ok"):
    headers = {
        "header_present": True,
        "trusted_receivers_configured": trusted,
        "dkim": {"evaluated": dkim_pass, "result": "pass" if dkim_pass else "not_evaluated"},
        "dmarc": {"evaluated": dmarc_pass, "result": "pass" if dmarc_pass else "not_evaluated"},
    }
    raw = {"auth_headers": headers, "identity": {"display_name_spoofing": {"actual_registrable_domain": "sender.example"}}, "alignment": {"dkim": {"aligned": dkim_aligned if dkim_pass else None}}}
    return ModuleResult(module="auth_check", status=status, findings=list(findings), raw_data=raw)


def _enrichment(findings=()):
    return ModuleResult(module="enrichment", status="ok", findings=list(findings), raw_data={})


def _content(findings=(), coverage=1.0):
    return ModuleResult(module="content_analysis", status="ok", findings=list(findings), raw_data={"script_coverage": coverage})


def _f(module, severity, title="finding", weight=0.0):
    return Finding(module=module, severity=severity, title=title, description="d", evidence={}, weight=weight)


def _verdict(auth, enrichment=None, content=None, config=KNOWN):
    out = run_scoring([auth, enrichment or _enrichment(), content or _content()], config)
    return out.verdict, [o.rule for o in out.breakdown.applied_overrides]


# ---- what makes benign ------------------------------------------------------------------------------

def test_a_verified_aligned_dkim_pass_with_nothing_else_is_benign():
    assert _verdict(_auth()) == ("benign", [])


def test_a_trusted_dmarc_pass_alone_also_counts_as_positive_evidence():
    assert _verdict(_auth(dkim_pass=False, dmarc_pass=True)) == ("benign", [])


def test_info_findings_do_not_block_benign():
    auth = _auth(findings=[_f("auth_check", "info", "SPF not evaluated")])
    assert _verdict(auth, _enrichment([_f("enrichment", "info", "Enrichment incomplete for x")]))[0] == "benign"


# ---- each way it fails -------------------------------------------------------------------------------

def test_no_trusted_receiver_means_benign_is_unreachable():
    verdict, rules = _verdict(_auth(trusted=False, dkim_pass=False))
    assert verdict == "inconclusive" and rules == ["no_positive_evidence_for_benign"]
    gaps = benign_evidence_gaps({"auth_check": _auth(trusted=False, dkim_pass=False), "enrichment": _enrichment()}, 1.0, KNOWN)
    assert "no trusted receiver is configured" in gaps[0]


def test_a_dkim_pass_that_is_not_aligned_with_the_from_domain_is_not_enough():
    verdict, _ = _verdict(_auth(dkim_aligned=False))
    assert verdict == "inconclusive"  # signed by a third party (the ESP): says nothing about the From identity


def test_a_trusted_receiver_without_a_dkim_or_dmarc_pass_is_not_enough():
    verdict, rules = _verdict(_auth(dkim_pass=False, dmarc_pass=False))
    assert verdict == "inconclusive" and rules == ["no_positive_evidence_for_benign"]
    gaps = benign_evidence_gaps({"auth_check": _auth(dkim_pass=False), "enrichment": _enrichment()}, 1.0, KNOWN)
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
    assert verdict == "inconclusive" and "no_positive_evidence_for_benign" in rules


def test_low_coverage_blocks_benign_even_with_a_dkim_pass():
    # content in an unsupported language (0.25) and enrichment gone: confidence falls below the threshold
    out = run_scoring([_auth(), ModuleResult(module="enrichment", status="error", findings=[], raw_data={}), _content(coverage=0.25)], KNOWN)
    assert out.confidence < 0.6 and out.verdict == "inconclusive"
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")
    assert "coverage is too low" in reason


def test_content_in_an_unsupported_language_is_never_the_reason_for_benign():
    unsupported = _content(coverage=0.25)
    # without authentication evidence, a quiet content result in a language we cannot read supports nothing
    assert _verdict(_auth(trusted=False, dkim_pass=False), content=unsupported)[0] == "inconclusive"
    assert _verdict(_auth(trusted=False, dkim_pass=False), content=_content(coverage=1.0))[0] == "inconclusive"  # nor does a covered one
    # benign comes from the verified authentication; the content result is not what supports it
    assert _verdict(_auth(), content=unsupported)[0] == "benign"


def test_the_reason_lists_every_gap_at_once():
    auth = _auth(trusted=False, dkim_pass=False, findings=[_f("auth_check", "low", "x")])
    out = run_scoring([auth, ModuleResult(module="enrichment", status="error", findings=[], raw_data={}), _content(coverage=0.25)], KNOWN)
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")
    for part in ("no trusted receiver", "finding(s) above info", "coverage is too low"):
        assert part in reason
    assert "not evidence of safety" in reason


# ---- the wording must match what actually happened -------------------------------------------------------

def _reason(auth, enrichment=None, content=None):
    out = run_scoring([auth, enrichment or _enrichment(), content or _content()], KNOWN)
    return next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")


def test_the_reason_says_nothing_was_flagged_only_when_nothing_above_info_exists():
    quiet = _reason(_auth(trusted=False, dkim_pass=False, findings=[_f("auth_check", "info", "SPF not evaluated")]))
    assert quiet.startswith("Nothing was flagged, but 'no findings' is not evidence of safety.") and "above info severity" not in quiet


@pytest.mark.parametrize(
    "build",
    [
        lambda: (_auth(findings=[_f("auth_check", "low", "From header parse ambiguity")]), None, None),
        lambda: (_auth(), _enrichment([_f("enrichment", "low", "Suspicious host: x.example")]), None),
        lambda: (_auth(), None, _content([_f("content_analysis", "medium", "Urgency language", 10)])),
    ],
    ids=["low-auth", "low-enrichment", "medium-content"],
)
def test_the_reason_never_claims_nothing_was_flagged_when_a_finding_above_info_exists(build):
    auth, enrichment, content = build()
    reason = _reason(auth, enrichment, content)
    assert "Nothing was flagged" not in reason
    assert reason.startswith("Something was flagged, but not enough to call it suspicious")
    assert "not evidence of safety" in reason and "finding(s) above info severity" in reason  # the gap list still names the finding


def test_a_finding_from_a_module_that_errored_does_not_count_as_flagged():
    auth = _auth(trusted=False, dkim_pass=False)
    errored = ModuleResult(module="enrichment", status="error", findings=[_f("enrichment", "high", "x")], raw_data={})
    out = run_scoring([auth, errored, _content()], KNOWN)
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "no_positive_evidence_for_benign")
    assert reason.startswith("Nothing was flagged")


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
    gaps = benign_evidence_gaps({"auth_check": auth, "enrichment": broken}, 1.0, KNOWN)
    # findings of an errored module are ignored everywhere in scoring; the module not having run is itself a gap
    assert gaps == ["enrichment did not run"]


# ---- iteration 1: authentication is not legitimacy ---------------------------------------------------------------

def test_authenticated_mail_from_an_unknown_sender_is_inconclusive():
    """The 11/75 tuning phish that reached benign had verified, aligned authentication on the attacker's own domain."""
    other = ScoringConfig(known_sender_domains=frozenset({"someone-else.example"}))
    verdict, rules = _verdict(_auth(), config=other)
    assert verdict == "inconclusive" and rules == ["no_positive_evidence_for_benign"]
    assert benign_evidence_gaps({"auth_check": _auth(), "enrichment": _enrichment()}, 1.0, other) == [
        "the sender's domain is not on the known-sender list"]


def test_with_no_known_sender_list_nothing_is_ever_benign():
    verdict, rules = _verdict(_auth(), config=ScoringConfig(known_sender_domains=frozenset()))
    assert verdict == "inconclusive"
    gaps = benign_evidence_gaps({"auth_check": _auth(), "enrichment": _enrichment()}, 1.0, ScoringConfig(known_sender_domains=frozenset()))
    assert "no known-sender list is configured" in gaps[0]


def test_the_default_list_is_the_untracked_one_and_is_empty_in_a_clean_checkout(monkeypatch):
    monkeypatch.setattr("app.config.KNOWN_SENDER_DOMAINS", frozenset())
    assert _verdict(_auth(), config=ScoringConfig())[0] == "inconclusive"
    monkeypatch.setattr("app.config.KNOWN_SENDER_DOMAINS", frozenset({"sender.example"}))
    assert _verdict(_auth(), config=ScoringConfig())[0] == "benign"


def test_a_known_sender_is_matched_on_the_registrable_domain_not_a_lookalike():
    cfg = ScoringConfig(known_sender_domains=frozenset({"sender.example"}))
    lookalike = _auth()
    lookalike.raw_data["identity"]["display_name_spoofing"]["actual_registrable_domain"] = "sender.example.evil.test"
    assert _verdict(lookalike, config=cfg)[0] == "inconclusive"
    padded = ScoringConfig(known_sender_domains=frozenset({" Sender.Example. "}))
    assert _verdict(_auth(), config=padded)[0] == "benign"


def test_a_missing_sender_domain_is_not_known():
    auth = _auth()
    auth.raw_data["identity"] = {}
    assert _verdict(auth)[0] == "inconclusive"


@pytest.mark.parametrize(
    "enrichment",
    [
        ModuleResult(module="enrichment", status="ok",
                     findings=[Finding(module="enrichment", severity="info", title="Enrichment incomplete for http://a.example",
                                       description="d", evidence={"ioc_value": "http://a.example"}, weight=0.0)],
                     raw_data={"http://a.example": {}}),
        ModuleResult(module="enrichment", status="ok", findings=[_f("enrichment", "info", "Not enriched: per-email limit reached")],
                     raw_data={}),
        ModuleResult(module="enrichment", status="skipped", findings=[], raw_data={}),
    ],
    ids=["unknown-indicator", "dropped-by-cap", "skipped"],
)
def test_incomplete_enrichment_is_inadequate_coverage_for_benign(enrichment):
    # info-severity findings do not block benign on their own; the coverage they describe does
    verdict, rules = _verdict(_auth(), enrichment)
    assert verdict == "inconclusive" and "no_positive_evidence_for_benign" in rules


def test_the_known_sender_gate_can_be_switched_off_only_for_diagnostics():
    off = ScoringConfig(known_sender_domains=frozenset(), require_known_sender_for_benign=False)
    assert _verdict(_auth(), config=off)[0] == "benign"
    assert ScoringConfig().require_known_sender_for_benign is True


def test_a_known_sender_with_a_finding_above_info_is_still_inconclusive():
    verdict, _ = _verdict(_auth(findings=[_f("auth_check", "low", "x")]))
    assert verdict == "inconclusive"  # being known does not excuse a signal
