"""The verdict v2 input builder and assembler (app/scoring/v2_inputs.py, v2_verdict.py): pure, content-free, built only from data the pipeline already holds."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.contracts.analysis import CoverageItem
from app.contracts.email import Attachment, EmailAddress, ExtractedUrl, ParsedEmail
from app.scoring.config import ScoringConfig
from app.scoring.overrides import benign_evidence_gaps, positive_evidence_flags
from app.scoring.tiers import compute_tier
from app.scoring.v2_inputs import hard_evidence_candidates
from app.scoring.v2_verdict import assemble_verdict_v2, count_checks
from tests import eval as ev

BACKEND = Path(__file__).resolve().parents[1]
SHA = "a" * 64


def _parsed(urls=(), attachments=()):
    return ParsedEmail(source_format="eml", from_=EmailAddress(address="sender@sender.example", domain="sender.example"), raw_size_bytes=1,
                       urls=[ExtractedUrl(url=u, source="body_html") for u in urls],
                       attachments=[Attachment(filename="a.bin", content_type="x/y", size_bytes=1, sha256=h, sha1="0" * 40, md5="0" * 32) for h in attachments])


def _enrichment(raw):
    return SimpleNamespace(status="ok", raw_data=raw, findings=[], module="enrichment")


def _host_entry(vt=12, tf=None, sent="domain"):
    value = {"vt": {"status": "ok", "malicious": vt}, "urlscan": {"status": "ok"}, "threatfox": {"status": "ok", "matched": False},
             "sent": {"virustotal": {"type": sent, "value": "x"}, "urlscan": {"type": sent, "value": "x"}, "threatfox": {"type": sent, "value": "x"}}}
    if tf is not None:
        value["threatfox"] = {"status": "ok", "matched": True, "confidence_level": tf}
    return value


# ---- hard-evidence candidates -------------------------------------------------------------------------------------------------------------------------------------------------

def test_a_virustotal_answer_on_a_link_host_becomes_a_defanged_link_host_candidate():
    (c,) = hard_evidence_candidates(_parsed(urls=["https://evil.example/login"]), _enrichment({"evil.example": _host_entry(vt=12)}), frozenset())
    assert (c["source"], c["engine_count"], c["indicator_type"], c["indicator"]) == ("virustotal", 12, "link_host", "evil[.]example")
    assert (c["is_ip"], c["is_shared_platform"], c["path_optin_on"], c["exact_url_match"], c["is_known_sender_or_own_domain"]) == (False, False, False, False, False)


def test_a_threatfox_match_carries_its_confidence_and_a_clean_answer_makes_no_candidate():
    (c,) = hard_evidence_candidates(_parsed(urls=["https://evil.example/"]), _enrichment({"evil.example": _host_entry(vt=0, tf=74)}), frozenset())
    assert (c["source"], c["confidence"]) == ("threatfox", 74)
    assert hard_evidence_candidates(_parsed(urls=["https://ok.example/"]), _enrichment({"ok.example": _host_entry(vt=0)}), frozenset()) == []


def test_a_url_key_is_a_link_url_candidate_only_for_a_provider_that_was_sent_the_full_url():
    url = "https://evil.example/path?x=1"
    entry = _host_entry(vt=12, tf=90)
    entry["sent"]["virustotal"]["type"] = "url"  # only VirusTotal opted in; ThreatFox was sent the host
    out = hard_evidence_candidates(_parsed(urls=[url]), _enrichment({url: entry}), frozenset())
    by_source = {c["source"]: c for c in out}
    assert (by_source["virustotal"]["indicator_type"], by_source["virustotal"]["exact_url_match"], by_source["virustotal"]["path_optin_on"]) == ("link_url", True, True)
    assert (by_source["threatfox"]["indicator_type"], by_source["threatfox"]["exact_url_match"], by_source["threatfox"]["path_optin_on"]) == ("link_host", False, False)
    assert by_source["virustotal"]["indicator"].startswith("hxxps://evil[.]example")


def test_an_ip_host_and_a_shared_platform_host_are_flagged_as_such():
    (ip,) = hard_evidence_candidates(_parsed(urls=["http://203.0.113.7/x"]), _enrichment({"203.0.113.7": _host_entry(vt=30, sent="ip")}), frozenset())
    assert ip["is_ip"] is True
    from app.enrichment.policy import platform_of

    assert platform_of("docs.google.com") is not None  # the existing list
    (shared,) = hard_evidence_candidates(_parsed(urls=["https://docs.google.com/x"]), _enrichment({"docs.google.com": _host_entry(vt=30)}), frozenset())
    assert shared["is_shared_platform"] is True


def test_a_host_on_the_known_sender_or_own_domain_list_is_flagged_by_registrable_domain_including_a_subdomain():
    entry = {"mail.example.com": _host_entry(vt=15), "login.example.org": _host_entry(vt=15), "other.example.net": _host_entry(vt=15)}
    urls = [f"https://{h}/" for h in entry]
    out = {c["indicator"]: c for c in hard_evidence_candidates(_parsed(urls=urls), _enrichment(entry), frozenset({"example.com", "example.org"}))}
    assert out["mail[.]example[.]com"]["is_known_sender_or_own_domain"] is True  # a subdomain of a listed registrable domain
    assert out["login[.]example[.]org"]["is_known_sender_or_own_domain"] is True
    assert out["other[.]example[.]net"]["is_known_sender_or_own_domain"] is False


def test_an_attachment_hash_is_a_candidate_with_the_hash_as_its_indicator():
    raw = {SHA: {"vt": {"status": "ok", "malicious": 0}, "threatfox": {"status": "ok", "matched": False}, "malwarebazaar": {"status": "ok", "matched": True}}}
    (c,) = hard_evidence_candidates(_parsed(attachments=[SHA]), _enrichment(raw), frozenset())
    assert (c["source"], c["indicator_type"], c["indicator"], c["is_known_sender_or_own_domain"]) == ("malwarebazaar", "attachment_hash", SHA, False)


def test_only_keys_that_a_link_or_an_attachment_names_can_be_candidates():
    """A Received-hop address, the sender domain and an image host are never keys a link names: even if a provider answered for them they are skipped."""
    raw = {"203.0.113.9": _host_entry(vt=40, sent="ip"), "sender.example": _host_entry(vt=40), "img.example": _host_entry(vt=40), "b" * 64: {"vt": {"status": "ok", "malicious": 40}}}
    assert hard_evidence_candidates(_parsed(urls=["https://link.example/"]), _enrichment(raw), frozenset()) == []


def test_internal_shared_and_failed_answers_make_no_candidate():
    raw = {"corp.internal": {"internal_host_not_sent": True}, "docs.google.com": {"uninformative": {"platform": "x", "kind": "y"}},
           "broken.example": {"vt": {"status": "failed"}, "threatfox": {"status": "rate_limited"}, "sent": {}}}
    parsed = _parsed(urls=["https://corp.internal/", "https://docs.google.com/", "https://broken.example/"])
    assert hard_evidence_candidates(parsed, _enrichment(raw), frozenset()) == []
    assert hard_evidence_candidates(parsed, None, frozenset()) == []
    assert hard_evidence_candidates(parsed, SimpleNamespace(status="error", raw_data={}), frozenset()) == []


# ---- the candidates reach the tier function correctly ----------------------------------------------------------------------------------------------------------------------

def _tier_for(candidates):
    return compute_tier({"hard_evidence_candidates": candidates})


def test_the_candidates_give_t1_at_the_thresholds_and_t2_r6_on_a_listed_domain():
    parsed = _parsed(urls=["https://evil.example/"])
    assert _tier_for(hard_evidence_candidates(parsed, _enrichment({"evil.example": _host_entry(vt=0, tf=75)}), frozenset()))["tier"] == "T1"
    assert _tier_for(hard_evidence_candidates(parsed, _enrichment({"evil.example": _host_entry(vt=0, tf=74)}), frozenset()))["tier"] == "T3"
    assert _tier_for(hard_evidence_candidates(parsed, _enrichment({"evil.example": _host_entry(vt=10)}), frozenset()))["tier"] == "T1"
    assert _tier_for(hard_evidence_candidates(parsed, _enrichment({"evil.example": _host_entry(vt=9)}), frozenset()))["tier"] == "T3"
    listed = _parsed(urls=["https://evil.example.com/"])
    out = _tier_for(hard_evidence_candidates(listed, _enrichment({"evil.example.com": _host_entry(vt=30)}), frozenset({"example.com"})))
    assert (out["tier"], out["route_id"]) == ("T2", "R6")


# ---- the checks count ---------------------------------------------------------------------------------------------------------------------------------------------------------------

def _item(status, by_design=False):
    return CoverageItem(area="x", status=status, by_design=by_design)


def test_the_counting_rule_m_excludes_by_design_n_is_checked_and_k_is_the_rest():
    items = [_item("checked"), _item("checked"), _item("partly"), _item("not_checked"), _item("not_checked", by_design=True), _item("not_checked", by_design=True)]
    c = count_checks(items)
    assert (c.completed, c.total, c.not_checked, c.by_design) == (2, 4, 2, 2)
    assert count_checks([]).model_dump() == {"completed": 0, "total": 0, "not_checked": 0, "by_design": 0}


# ---- the assembler ----------------------------------------------------------------------------------------------------------------------------------------------------------------

def _result(findings, priority=41.5):
    return SimpleNamespace(findings=findings, scoring=SimpleNamespace(priority=priority))


def _finding(code, severity):
    return SimpleNamespace(code=code, severity=severity)


def test_a_finding_reason_uses_the_registry_template_and_points_at_the_finding_by_index():
    from app.finding_codes import BY_CODE

    out = {"tier": "T2", "route_id": "R1", "hard_evidence": [], "blockers": [], "needs_analyst_reason": [],
           "reasons": [{"code": "AUTH_CLAIM_DECOY_LINKS", "class": "claim", "severity": "medium", "routes": ["R1"]}]}
    verdict = assemble_verdict_v2(out, _result([_finding("AUTH_IDENTITY_FREE_MAILBOX_BRAND", "medium"), _finding("AUTH_CLAIM_DECOY_LINKS", "medium")]), [])
    (reason,) = verdict.reasons
    assert (reason.kind, reason.code, reason.evidence_ref, reason.text) == ("finding", "AUTH_CLAIM_DECOY_LINKS", "1", BY_CODE["AUTH_CLAIM_DECOY_LINKS"].description)
    assert (verdict.tier, verdict.label, verdict.route, verdict.priority) == ("suspicious", "Suspicious", "R1", None)


def test_a_needs_analyst_result_carries_its_sub_reason_gaps_blockers_and_priority():
    out = {"tier": "T3", "route_id": "DEFAULT", "hard_evidence": [], "needs_analyst_reason": ["signals_present", "low_confidence"], "blockers": ["no_trusted_receiver_hop", "unknown_finding_code"],
           "reasons": [{"code": "signals_present", "class": "gap", "severity": "info", "routes": []}, {"code": "low_confidence", "class": "gap", "severity": "info", "routes": []},
                       {"code": "no_trusted_receiver_hop", "class": "gap", "severity": "info", "routes": []}]}
    items = [{"code": "no_trusted_receiver_hop", "detail": "not_configured"}]
    verdict = assemble_verdict_v2(out, _result([]), items)
    assert verdict.tier == "needs_analyst" and verdict.label == "Needs analyst" and verdict.needs_analyst_reason == "signals_present" and verdict.priority == 41.5
    assert [r.kind for r in verdict.reasons] == ["gap", "gap", "gap"]
    assert [(b.code, b.detail) for b in verdict.blockers] == [("no_trusted_receiver_hop", "not_configured"), ("unknown_finding_code", None)]
    assert all(b.text and b.how_to_clear for b in verdict.blockers)


def test_hard_evidence_and_the_conflict_reason_are_carried():
    out = {"tier": "T1", "route_id": "HARD_EVIDENCE", "needs_analyst_reason": [], "blockers": [], "hard_evidence": [{"indicator": "evil[.]example", "source": "threatfox", "rule": "H2"}],
           "reasons": [{"code": "evidence_conflict", "class": "hard_evidence", "severity": "high", "routes": ["R6"], "sources": ["virustotal"]}]}
    verdict = assemble_verdict_v2(out, _result([]), [])
    assert [(h.code, h.indicator, h.source) for h in verdict.hard_evidence] == [("H2", "evil[.]example", "threatfox")]
    assert [(r.kind, r.code) for r in verdict.reasons] == [("evidence_conflict", "evidence_conflict")] and verdict.label == "Confirmed malicious"


# ---- the shared positive-evidence logic ---------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.slow
def test_the_positive_flags_agree_with_the_v1_gap_list_on_every_fixture_and_tuning_message_in_both_modes():
    mismatches = 0
    checked = 0
    items = ev.collect(None)
    for mode in ev.MODES:
        ev.apply_mode(mode)
        for path, _label, _source in items:
            result = ev.analyze(path, "clean")
            by_name = {m.module: m for m in result.module_results}
            gaps = benign_evidence_gaps(by_name, result.confidence, ScoringConfig())
            aligned, known = positive_evidence_flags(by_name, ScoringConfig())
            no_auth_gap = not any(g.startswith(("no trusted receiver is configured", "no verified, aligned")) for g in gaps)
            no_known_gap = not any(g.startswith(("no known-sender list", "the sender's domain is not on")) for g in gaps)
            mismatches += (aligned, known) != (no_auth_gap, no_known_gap)
            checked += 1
    ev.apply_mode("configured")
    assert checked >= 2 * 7 and mismatches == 0


# ---- pure ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("module", ["v2_inputs.py", "v2_verdict.py"])
def test_the_v2_builders_import_no_io_network_logging_time_or_randomness(module):
    tree = ast.parse((BACKEND / "app" / "scoring" / module).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= {"__future__", "typing", "app"}, names
    calls = {getattr(n.func, "id", getattr(n.func, "attr", "")) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"open", "print", "getLogger", "urlopen", "now", "random"}, calls
