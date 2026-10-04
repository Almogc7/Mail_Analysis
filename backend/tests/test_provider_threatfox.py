"""First-party ThreatFox client: an exact-match query, never a submission."""
import pytest

from app.enrichment.providers.threatfox import ThreatFoxClient
from tests.provider_fakes import FakeResponse, fake_http  # noqa: F401  (fixture)

MATCH = {"query_status": "ok", "data": [
    {"malware_printable": "Fam A", "threat_type": "botnet_cc", "tags": ["t1", "t2"], "confidence_level": 75, "first_seen": "2026-01-01"},
    {"malware": "fam_b", "threat_type": "botnet_cc", "tags": ["t2", "t3"], "confidence_level": 100},
    {"malware_printable": "Fam A", "confidence_level": None},
]}


def test_no_key_means_disabled_and_no_request(fake_http):
    assert ThreatFoxClient("").enrich("example.org", "domain") == {"enabled": False, "status": "disabled"}
    assert fake_http.calls == []


@pytest.mark.parametrize("ioc_type", ["ip", "domain", "url", "md5", "sha1", "sha256"])
def test_every_supported_type_sends_one_exact_match_question(fake_http, ioc_type):
    fake_http.respond(FakeResponse(200, {"query_status": "no_result"}))
    ThreatFoxClient("k").enrich("v", ioc_type)
    call = fake_http.calls[0]
    assert call["method"] == "POST" and call["url"] == "https://threatfox-api.abuse.ch/api/v1/"
    assert call["json"] == {"query": "search_ioc", "search_term": "v", "exact_match": True} and call["headers"] == {"Auth-Key": "k"}


def test_the_only_query_ever_sent_is_a_search(fake_http):
    fake_http.respond(FakeResponse(200, {"query_status": "no_result"}))
    client = ThreatFoxClient("k")
    for ioc_type in ThreatFoxClient.SUPPORTED_TYPES:
        client.enrich("v", ioc_type)
    assert {c["json"]["query"] for c in fake_http.calls} == {"search_ioc"}  # never submit/add: nothing is reported to abuse.ch


def test_no_result_is_a_clean_ok_with_zero_matches(fake_http):
    fake_http.respond(FakeResponse(200, {"query_status": "no_result"}))
    assert ThreatFoxClient("k").enrich("example.org", "domain") == {"enabled": True, "status": "ok", "matched": False, "match_count": 0}


def test_matches_are_summarised_deduplicated_and_capped(fake_http):
    fake_http.respond(FakeResponse(200, MATCH))
    assert ThreatFoxClient("k").enrich("example.org", "domain") == {
        "enabled": True, "status": "ok", "matched": True, "match_count": 3, "malware_families": ["Fam A", "fam_b"],
        "threat_types": ["botnet_cc"], "tags": ["t1", "t2", "t3"], "confidence_level": 100, "first_seen": "2026-01-01"}


def test_lists_are_truncated_to_the_documented_limits(fake_http):
    many = {"query_status": "ok", "data": [{"malware": f"m{i}", "threat_type": f"t{i}", "tags": [f"g{i}"], "confidence_level": 1} for i in range(12)]}
    fake_http.respond(FakeResponse(200, many))
    result = ThreatFoxClient("k").enrich("example.org", "domain")
    assert len(result["malware_families"]) == 5 and len(result["threat_types"]) == 5 and len(result["tags"]) == 8


def test_an_unexpected_query_status_is_a_failure_never_a_clean_answer(fake_http):
    fake_http.respond(FakeResponse(200, {"query_status": "illegal_search_term"}))
    assert ThreatFoxClient("k").enrich("v", "domain") == {"enabled": True, "status": "failed", "error": "ThreatFox query_status=illegal_search_term"}


def test_unsupported_types_are_not_applicable_without_a_request(fake_http):
    assert ThreatFoxClient("k").enrich("x", "email")["status"] == "not_applicable" and fake_http.calls == []


def test_http_errors_are_non_ok(fake_http):
    fake_http.respond(FakeResponse(401, {}))
    result = ThreatFoxClient("k").enrich("v", "domain")
    assert result["status"] == "failed" and result["http_status"] == 401
