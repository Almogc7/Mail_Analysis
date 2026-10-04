"""First-party urlscan.io client: read-only search, never a scan submission."""
import inspect

import pytest

from app.enrichment.providers import urlscan
from app.enrichment.providers.urlscan import URLScanClient
from tests.provider_fakes import FakeResponse, fake_http  # noqa: F401  (fixture)

ROWS = {"total": 12, "results": [
    {"page": {"url": "https://a.example.org/x", "domain": "a.example.org", "country": "US"}, "screenshot": "s1"},
    {"page": {"url": "https://b.example.org/y", "domain": "b.example.org"}},
    {"page": {}},
]}


def test_no_key_means_disabled_and_no_request(fake_http):
    assert URLScanClient("").enrich("example.org", "domain") == {"enabled": False, "status": "disabled"}
    assert fake_http.calls == []


@pytest.mark.parametrize("ioc_type,value,query", [("domain", "example.org", "domain:example.org"),
                                                  ("ip", "203.0.113.5", "ip:203.0.113.5"),
                                                  ("url", "https://example.org/p", 'page.url:"https://example.org/p"')])
def test_each_type_becomes_one_search_query(fake_http, ioc_type, value, query):
    fake_http.respond(FakeResponse(200, ROWS))
    URLScanClient("k").enrich(value, ioc_type)
    call = fake_http.calls[0]
    assert call["method"] == "GET" and call["url"] == "https://urlscan.io/api/v1/search/"
    assert call["params"] == {"q": query, "size": 5} and call["headers"] == {"API-Key": "k"}


def test_the_search_result_is_summarised(fake_http):
    fake_http.respond(FakeResponse(200, ROWS))
    assert URLScanClient("k").enrich("example.org", "domain") == {
        "enabled": True, "status": "ok", "query": "domain:example.org", "total_results": 12,
        "sample_urls": ["https://a.example.org/x", "https://b.example.org/y"], "sample_domains": ["a.example.org", "b.example.org"],
        "sample_countries": ["US"], "screenshots": ["s1"]}


def test_a_missing_total_falls_back_to_the_number_of_rows(fake_http):
    fake_http.respond(FakeResponse(200, {"results": [{"page": {"url": "https://x.example.org"}}]}))
    assert URLScanClient("k").enrich("example.org", "domain")["total_results"] == 1


def test_unsupported_types_are_not_applicable_without_a_request(fake_http):
    for ioc_type in ("sha256", "md5", "email"):
        assert URLScanClient("k").enrich("x", ioc_type)["status"] == "not_applicable"
    assert fake_http.calls == []


def test_errors_are_non_ok_results_never_an_empty_ok(fake_http):
    fake_http.respond(FakeResponse(429, {}))
    assert URLScanClient("k").enrich("example.org", "domain")["status"] == "rate_limited"
    fake_http.respond(FakeResponse(500, {}))
    assert URLScanClient("k").enrich("example.org", "domain")["status"] == "failed"


def test_there_is_no_way_to_submit_a_scan_so_visibility_cannot_matter(fake_http):
    fake_http.respond(FakeResponse(200, ROWS))
    client = URLScanClient("k")
    client.enrich("example.org", "domain")
    client.enrich("https://example.org/p", "url")
    assert {c["method"] for c in fake_http.calls} == {"GET"} and all(c.get("json") is None and c.get("data") is None for c in fake_http.calls)
    assert all("/scan" not in c["url"] for c in fake_http.calls)
    source = inspect.getsource(urlscan)
    assert "safe_post" not in source  # the only HTTP verb this client uses is GET
    assert not any(hasattr(URLScanClient, name) for name in ("submit", "scan", "submit_url", "safe_post_scan"))
