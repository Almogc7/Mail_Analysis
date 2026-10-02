"""Trusted-receiver semantics: who may vouch for SPF/DKIM/DMARC, and what a pass is worth."""
import pytest

from app.auth_check import run_auth_check
from app.auth_check.spf_dkim_dmarc import NOT_EVALUATED, evaluate_authentication
from app.contracts.email import EmailAddress, ParsedEmail, ReceivedHop, ReceivedSpf
from app.contracts.findings import ModuleResult
from app.parser import parse_email_file
from app.scoring import run_scoring
from tests.eval import FIXTURES

ESA = r"^esa1\.gateway\.example\.net$"
MX = r"^mx\.example\.org$"
PASS_AR = "mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
FAIL_AR = "mx.example.org; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail header.from=evil.example"
EVIL_PASS_AR = "evil.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"


def _hop(by):
    return ReceivedHop(raw=f"from x by {by} with ESMTPS", from_host="x", by_host=by)


def _email(**kw):
    base = dict(source_format="eml", from_=EmailAddress(display_name="Alice", address="a@example.com", domain="example.com"), raw_size_bytes=1)
    base.update(kw)
    return ParsedEmail(**base)


def _kvish():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    return parse_email_file(path.read_bytes(), path.name)


def _score(auth_result):
    """Score like the real pipeline: all three categories present (scoring the auth module alone
    makes overall confidence artificially low and trips the needs_review rule)."""
    quiet = [ModuleResult(module=m, status="ok", findings=[], raw_data={}) for m in ("enrichment", "content_analysis")]
    return run_scoring([auth_result, *quiet])


def _titles(result):
    return [f.title for f in result.findings]


# ---- default: nothing trusted ------------------------------------------------------------

def test_default_nothing_is_trusted_and_every_method_is_not_evaluated(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    parsed = _email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")])
    auth = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain)
    for m in ("spf", "dkim", "dmarc"):
        assert auth[m]["result"] == NOT_EVALUATED and not auth[m]["evaluated"]
        assert auth[m]["reason"] == "no_trusted_receivers_configured"
    assert auth["header_present"] is False and auth["trusted_receivers_configured"] is False
    assert all(c["trusted"] is False for c in auth["claims"])  # claims are kept, never hidden


def test_findings_say_not_evaluated_and_why_and_list_ignored_claims(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    result = run_auth_check(_email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")]))
    titles = _titles(result)
    assert {"SPF not evaluated", "DKIM not evaluated", "DMARC not evaluated"} <= set(titles)
    spf = next(f for f in result.findings if f.title == "SPF not evaluated")
    assert "TRUSTED_RECEIVER_PATTERNS is empty" in spf.description and spf.weight == 0.0
    assert "Authentication claims from untrusted sources were ignored" in titles
    assert "SPF/DKIM/DMARC all passed" not in titles


# ---- who counts as trusted ---------------------------------------------------------------

def test_trusted_authentication_results_are_used(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    auth = evaluate_authentication([PASS_AR], [], [_hop("mx.example.org")])
    assert [auth[m]["result"] for m in ("spf", "dkim", "dmarc")] == ["pass"] * 3
    assert auth["spf"]["trust_basis"]["hop_index"] == 0 and auth["header_present"] is True


def test_pattern_match_alone_is_not_enough_the_host_must_be_a_hop_in_the_chain(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    auth = evaluate_authentication([PASS_AR], [], [_hop("some.other.host")])
    assert auth["spf"]["result"] == NOT_EVALUATED and auth["spf"]["reason"] == "claim_from_untrusted_source"
    assert auth["spf"]["trust_basis"] is None


def test_headers_naming_an_untrusted_host_are_ignored_even_when_a_trusted_one_exists(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    chain = [_hop("mx.example.org"), _hop("evil.example.net")]
    # The attacker's forged all-pass header sits FIRST; the trusted receiver's fail must still win.
    auth = evaluate_authentication([EVIL_PASS_AR, FAIL_AR], [], chain)
    assert auth["spf"]["result"] == "fail" and auth["dmarc"]["result"] == "fail"
    assert [c["trusted"] for c in auth["claims"]][:3] == [False, False, False]


def test_short_hostname_matches_fqdn_hop(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [r"^mx"])
    auth = evaluate_authentication(["mx; spf=pass smtp.mailfrom=example.com"], [], [_hop("mx.example.org")])
    assert auth["spf"]["result"] == "pass"


def test_invalid_pattern_fails_safe_trusts_nothing_and_reports_a_warning(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", ["(unclosed"])
    auth = evaluate_authentication([PASS_AR], [], [_hop("mx.example.org")])
    assert auth["spf"]["result"] == NOT_EVALUATED and any("invalid" in w for w in auth["warnings"])


def test_authserv_less_header_is_trusted_only_by_explicit_placeholder_opt_in(monkeypatch):
    header = "spf=softfail smtp.mailfrom=example.org; dmarc=fail header.from=example.org"
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    assert evaluate_authentication([header], [], [_hop("mx.example.org")])["dmarc"]["result"] == NOT_EVALUATED
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [r"^unknown-authserv$"])
    auth = evaluate_authentication([header], [], [_hop("mx.example.org")])
    assert auth["dmarc"]["result"] == "fail"
    assert auth["dmarc"]["trust_basis"]["hop_index"] is None
    assert "could not be verified" in auth["dmarc"]["trust_basis"]["note"]


# ---- Received-SPF ------------------------------------------------------------------------

def test_kvish6_received_spf_is_ignored_unless_the_gateway_is_trusted(monkeypatch):
    parsed = _kvish()
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    auth = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain)
    assert auth["spf"]["result"] == NOT_EVALUATED
    assert any(c["source"] == "received-spf" and c["result"] == "pass" and not c["trusted"] for c in auth["claims"])


def test_kvish6_trusted_gateway_spf_pass_is_recorded_and_dkim_dmarc_stay_not_evaluated(monkeypatch):
    parsed = _kvish()
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    auth = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain)
    assert auth["spf"]["result"] == "pass" and auth["spf"]["source"] == "received-spf"
    assert auth["spf"]["domain"] == "vh319.sweb.ru"
    assert auth["dkim"]["result"] == NOT_EVALUATED and auth["dkim"]["reason"] == "receiver_evaluated_spf_only"
    assert auth["dmarc"]["reason"] == "receiver_evaluated_spf_only"
    result = run_auth_check(parsed)
    assert "SPF/DKIM/DMARC all passed" not in _titles(result)
    assert "DKIM not evaluated" in _titles(result)


def test_forged_received_spf_naming_a_trusted_host_not_in_the_chain_is_ignored(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    forged = ReceivedSpf(result="pass", raw="Pass", header_index=0, receiver="esa1.gateway.example.net")
    auth = evaluate_authentication([], [forged], [_hop("unrelated.example.com")])
    assert auth["spf"]["result"] == NOT_EVALUATED


# ---- a pass is worth nothing; floors survive ---------------------------------------------

def test_trusted_spf_pass_changes_no_score_and_no_finding_has_negative_weight(monkeypatch):
    parsed = _kvish()
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    untrusted = run_auth_check(parsed)
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    trusted = run_auth_check(parsed)
    assert sum(f.weight for f in trusted.findings) == sum(f.weight for f in untrusted.findings)
    assert all(f.weight >= 0 for f in trusted.findings + untrusted.findings)
    s_untrusted, s_trusted = _score(untrusted), _score(trusted)
    assert s_untrusted.score == s_trusted.score and s_untrusted.verdict == s_trusted.verdict == "suspicious"


def _spoof_email(**kw):
    return _email(from_=EmailAddress(display_name="PayPal Support", address="security@totally-legit-mailer.ru", domain="totally-legit-mailer.ru"), **kw)


@pytest.mark.parametrize("patterns", [[], [MX]])
def test_display_name_floor_survives_with_and_without_trusted_receivers(monkeypatch, patterns):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", patterns)
    result = run_auth_check(_spoof_email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")]))
    outcome = _score(result)  # a "pass" in the headers must not talk the floor away
    assert outcome.verdict == "suspicious"
    assert any(o.rule == "auth_check_floor" for o in outcome.breakdown.applied_overrides)


def test_trusted_spf_fail_still_floors_but_an_untrusted_fail_does_not(monkeypatch):
    parsed = _email(authentication_results_raw=[FAIL_AR], received_chain=[_hop("mx.example.org")])
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    trusted = run_auth_check(parsed)
    assert "SPF check failed" in _titles(trusted)
    assert any(o.rule == "auth_check_floor" for o in _score(trusted).breakdown.applied_overrides)
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    untrusted = run_auth_check(parsed)
    assert "SPF check failed" not in _titles(untrusted)
    assert not _score(untrusted).breakdown.applied_overrides
    # ...but the claim stays visible to the analyst
    ignored = next(f for f in untrusted.findings if f.title.startswith("Authentication claims from untrusted"))
    assert any(c["result"] == "fail" for c in ignored.evidence["claims"])


def test_all_passed_finding_requires_all_three_methods_from_a_trusted_receiver(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    parsed = _email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")])
    assert "SPF/DKIM/DMARC all passed" in _titles(run_auth_check(parsed))
    partial = _email(authentication_results_raw=["mx.example.org; spf=pass smtp.mailfrom=example.com"], received_chain=[_hop("mx.example.org")])
    assert "SPF/DKIM/DMARC all passed" not in _titles(run_auth_check(partial))


def test_spf_only_gateway_does_not_claim_full_auth_coverage(monkeypatch):
    # Regression found by the eval: SPF-only evaluation set header_present, so a 'legit' verdict
    # carried confidence 1.0 on one third of the evidence.
    from app.scoring.aggregate import category_coverage

    parsed = _kvish()
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    result = run_auth_check(parsed)
    assert result.raw_data["auth_headers"]["spf"]["evaluated"] is True
    assert result.raw_data["auth_headers"]["header_present"] is False
    assert category_coverage("auth_check", result) == 0.4


# ---- untrusted FAIL is a weak signal; untrusted PASS is nothing ----------------------------------

def test_untrusted_fail_is_a_low_weight_finding_and_untrusted_pass_is_zero(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    fail = run_auth_check(_email(authentication_results_raw=[FAIL_AR], received_chain=[_hop("mx.example.org")]))
    spf = next(f for f in fail.findings if f.title == "SPF failure claimed by an untrusted source")
    assert spf.severity == "low" and spf.weight == 4.0
    assert {"DKIM failure claimed by an untrusted source", "DMARC failure claimed by an untrusted source"} <= set(_titles(fail))
    assert "SPF check failed" not in _titles(fail)  # the established-failure finding stays trusted-only
    ok = run_auth_check(_email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")]))
    assert not [f for f in ok.findings if f.weight > 0]  # an untrusted pass contributes nothing at all


def test_untrusted_fail_alone_cannot_reach_suspicious(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    result = run_auth_check(_email(authentication_results_raw=[FAIL_AR], received_chain=[_hop("mx.example.org")]))
    outcome = _score(result)
    assert outcome.verdict == "legit" and not outcome.breakdown.applied_overrides


def test_a_trusted_fail_replaces_the_weak_untrusted_one(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    titles = _titles(run_auth_check(_email(authentication_results_raw=[FAIL_AR], received_chain=[_hop("mx.example.org")])))
    assert "SPF check failed" in titles and "SPF failure claimed by an untrusted source" not in titles


# ---- positional check: additional signal only ----------------------------------------------------

from app.contracts.email import HeaderField  # noqa: E402


def _headers(*names):
    return [HeaderField(name=n, value="x") for n in names]


def _positional(monkeypatch, order):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    parsed = _email(authentication_results_raw=[PASS_AR], received_chain=[_hop("mx.example.org")], headers=_headers(*order))
    return run_auth_check(parsed)


def test_header_above_its_hops_received_line_is_positionally_ok(monkeypatch):
    result = _positional(monkeypatch, ["Authentication-Results", "Received", "From"])
    basis = result.raw_data["auth_headers"]["spf"]["trust_basis"]
    assert basis["positional_ok"] is True and basis["position"] == "above_hop_received"
    assert not [t for t in _titles(result) if "sits below" in t]


def test_header_below_its_hops_received_line_is_flagged_but_still_trusted(monkeypatch):
    result = _positional(monkeypatch, ["Received", "From", "Authentication-Results"])
    auth = result.raw_data["auth_headers"]
    assert auth["spf"]["result"] == "pass"  # position never overrides the host+hop trust decision
    assert auth["spf"]["trust_basis"]["positional_ok"] is False
    note = next(f for f in result.findings if "sits below" in f.title)
    assert note.weight == 0.0 and "Exchange" in note.description


def test_position_is_unknown_without_header_order(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    auth = evaluate_authentication([PASS_AR], [], [_hop("mx.example.org")])
    assert auth["spf"]["trust_basis"]["positional_ok"] is None


def test_kvish6_exchange_reordering_is_reported_as_below_not_as_untrusted(monkeypatch):
    # Documented limit: this sample's gateway really added the header, yet Exchange left it below every
    # Received line. Validates why position is a signal and not a gate.
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    result = run_auth_check(_kvish())
    basis = result.raw_data["auth_headers"]["spf"]["trust_basis"]
    assert result.raw_data["auth_headers"]["spf"]["result"] == "pass"
    assert basis["position"] == "below_hop_received" and basis["positional_ok"] is False
    assert any("sits below" in t for t in _titles(result))
