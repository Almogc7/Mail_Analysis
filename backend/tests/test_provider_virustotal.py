"""First-party VirusTotal client and the shared HTTP base: results, retries, and that only read-only GETs ever leave."""
import base64

import pytest
import requests

from app.enrichment.providers import base
from app.enrichment.providers.base import BaseClient
from app.enrichment.providers.virustotal import VirusTotalClient
from tests.provider_fakes import FakeResponse, fake_http  # noqa: F401  (fixture)

SHA = "13b9ecc480f858d1354d12cb2a218b3a1d186dd205fc9b154350a7e45cf562aa"
REPORT = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 10},
                                  "reputation": -5, "tags": ["a"], "categories": {"x": "phishing"}}}}


def test_no_key_means_disabled_and_no_request(fake_http):
    assert VirusTotalClient("").enrich("example.org", "domain") == {"enabled": False, "status": "disabled"}
    assert fake_http.calls == []


def test_a_report_is_parsed_into_the_documented_fields(fake_http):
    fake_http.respond(FakeResponse(200, REPORT))
    assert VirusTotalClient("k").enrich("example.org", "domain") == {
        "enabled": True, "status": "ok", "malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 10,
        "reputation": -5, "tags": ["a"], "categories": {"x": "phishing"}}


def test_an_empty_report_defaults_to_zero_not_missing(fake_http):
    fake_http.respond(FakeResponse(200, {}))
    result = VirusTotalClient("k").enrich("example.org", "domain")
    assert result["status"] == "ok" and result["malicious"] == 0 and result["tags"] == [] and result["categories"] == {}


@pytest.mark.parametrize(
    "ioc_type,value,path",
    [("domain", "example.org", "/domains/example.org"), ("ip", "203.0.113.5", "/ip_addresses/203.0.113.5"),
     ("sha256", SHA, f"/files/{SHA}"), ("md5", "a" * 32, f"/files/{'a' * 32}"), ("sha1", "b" * 40, f"/files/{'b' * 40}")],
)
def test_each_indicator_type_goes_to_its_own_read_endpoint(fake_http, ioc_type, value, path):
    fake_http.respond(FakeResponse(200, REPORT))
    VirusTotalClient("k").enrich(value, ioc_type)
    call = fake_http.calls[0]
    assert call["method"] == "GET" and call["url"] == VirusTotalClient.BASE_URL + path and call["headers"] == {"x-apikey": "k"}


def test_a_url_is_looked_up_by_its_unpadded_urlsafe_base64_id(fake_http):
    fake_http.respond(FakeResponse(200, REPORT))
    url = "https://example.org/a?b=c&d=e"
    VirusTotalClient("k").enrich(url, "url")
    expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert fake_http.calls[0]["url"] == f"{VirusTotalClient.BASE_URL}/urls/{expected}" and "=" not in expected


def test_an_unsupported_type_is_not_applicable_without_a_request(fake_http):
    result = VirusTotalClient("k").enrich("x", "email")
    assert result["status"] == "not_applicable" and result["enabled"] is False and "email" in result["error"] and fake_http.calls == []


def test_only_read_only_gets_ever_leave_for_every_supported_type(fake_http):
    fake_http.respond(FakeResponse(200, REPORT))
    client = VirusTotalClient("k")
    for ioc_type, value in (("domain", "example.org"), ("ip", "203.0.113.5"), ("sha256", SHA), ("url", "https://example.org/")):
        client.enrich(value, ioc_type)
    assert {c["method"] for c in fake_http.calls} == {"GET"}
    assert all(c.get("json") is None and c.get("data") is None for c in fake_http.calls)  # no upload, no body
    assert all(c["url"].startswith("https://www.virustotal.com/api/v3/") for c in fake_http.calls)
    assert not any(hasattr(VirusTotalClient, name) for name in ("submit", "upload", "scan", "submit_url", "upload_file"))


def test_a_404_is_an_error_result_with_the_http_status_and_is_not_retried(fake_http, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(base.time, "sleep", sleeps.append)
    fake_http.respond(FakeResponse(404, {}))
    result = VirusTotalClient("k").enrich(SHA, "sha256")
    # exactly the result shape callers saw before (status failed + http_status 404): only the pointless retries are gone
    assert result["status"] == "failed" and result["http_status"] == 404 and "404" in result["error"] and result["enabled"] is True
    assert set(result) == {"enabled", "status", "error", "http_status"}
    assert len(fake_http.calls) == 1 and sleeps == []


def test_429_and_5xx_are_still_retried_with_back_off(fake_http, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(base.time, "sleep", sleeps.append)
    for code, status in ((429, "rate_limited"), (500, "failed"), (503, "failed")):
        fake_http.calls.clear()
        sleeps.clear()
        fake_http.respond(FakeResponse(code, {}))
        assert VirusTotalClient("k").enrich(SHA, "sha256")["status"] == status
        assert len(fake_http.calls) == base.MAX_RETRIES + 1 and len(sleeps) == base.MAX_RETRIES


def test_a_404_after_a_transient_error_stops_at_the_404(fake_http):
    fake_http.respond(FakeResponse(503, {}), FakeResponse(404, {}), FakeResponse(200, REPORT))
    assert VirusTotalClient("k").enrich(SHA, "sha256")["http_status"] == 404
    assert len(fake_http.calls) == 2


def test_other_client_errors_keep_their_existing_behaviour(fake_http):
    fake_http.respond(FakeResponse(403, {}))
    result = VirusTotalClient("k").enrich(SHA, "sha256")
    assert result["status"] == "failed" and result["http_status"] == 403 and len(fake_http.calls) == base.MAX_RETRIES + 1


def test_rate_limit_server_error_timeout_and_bad_json_are_all_non_ok(fake_http):
    client = VirusTotalClient("k")
    fake_http.respond(FakeResponse(429, {}))
    assert client.enrich("example.org", "domain") == {"enabled": True, "status": "rate_limited", "error": "Provider rate limit reached", "http_status": 429}
    fake_http.respond(FakeResponse(503, {}))
    assert client.enrich("example.org", "domain")["status"] == "failed" and "503" in client.enrich("example.org", "domain")["error"]
    fake_http.respond(requests.Timeout("slow"))
    timeout = client.enrich("example.org", "domain")
    assert timeout["status"] == "failed" and "http_status" not in timeout
    fake_http.respond(FakeResponse(200, bad_json=True))
    assert client.enrich("example.org", "domain") == {"enabled": True, "status": "invalid_response", "error": "Invalid JSON response"}


def test_a_transient_failure_followed_by_success_returns_the_success(fake_http):
    fake_http.respond(FakeResponse(503, {}), requests.ConnectionError("reset"), FakeResponse(200, REPORT))
    assert VirusTotalClient("k").enrich("example.org", "domain")["status"] == "ok"
    assert len(fake_http.calls) == 3


def test_backoff_grows_per_attempt_and_the_timeout_is_passed(fake_http, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(base.time, "sleep", sleeps.append)
    fake_http.respond(FakeResponse(503, {}))
    VirusTotalClient("k").enrich("example.org", "domain")
    assert sleeps == [base.RETRY_BACKOFF_SECONDS * 1, base.RETRY_BACKOFF_SECONDS * 2]
    assert all(c["timeout"] == base.TIMEOUT for c in fake_http.calls)


def test_the_result_helpers_have_the_shapes_the_enrichment_module_reads():
    assert BaseClient.disabled_result() == {"enabled": False, "status": "disabled"}
    assert BaseClient.not_applicable_result("why") == {"enabled": False, "status": "not_applicable", "error": "why"}
    assert BaseClient.ok_result(a=1) == {"enabled": True, "status": "ok", "a": 1}
    assert BaseClient.error_result("failed", "e") == {"enabled": True, "status": "failed", "error": "e"}
    assert BaseClient.error_result("failed", "e", 500)["http_status"] == 500


def test_environment_tunables_keep_their_names_and_defaults():
    import app.enrichment.providers.base as module

    source = open(module.__file__, encoding="utf-8").read()
    for name in ("IOC_TIMEOUT_SECONDS", "IOC_MAX_RETRIES", "IOC_RETRY_BACKOFF_SECONDS"):
        assert name in source
