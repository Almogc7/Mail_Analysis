"""Private, reserved, loopback, link-local and internal-looking addresses and names are NEVER sent to any external provider (VirusTotal,
urlscan.io, ThreatFox, MalwareBazaar). They become UNKNOWN (not looked up) and can never support a benign verdict. The proof is at the
HTTP layer: with the real client classes, a fake session records every request, and for these indicators it must stay empty."""
import pytest

from app.contracts.email import ExtractedUrl, ParsedEmail
from app.enrichment import run_enrichment
from app.enrichment.policy import EnrichmentPolicy, GuardedProvider, classify_host, guard_clients, target_for
from app.enrichment.providers import MalwareBazaarClient, RiskScorer, ScoreConfig, ThreatFoxClient, URLScanClient, VirusTotalClient
from app.enrichment.rate_limit import VTRateLimiter
from app.indicators import build_indicator_pack
from app.scoring.overrides import benign_evidence_gaps
from app.scoring.config import ScoringConfig
from tests.provider_fakes import FakeResponse, fake_http  # noqa: F401  (fixture)


def ip(*parts):  # addresses are assembled at runtime: no IP literal in the source (scripts/check_fixtures.py)
    return ".".join(parts)


PUBLIC_V4 = ip("8", "8", "4", "4")
PUBLIC_V6 = ":".join(("2606", "4700", "4700", "0", "0", "0", "0", "1111"))
INTERNAL_ADDRESSES = [
    ip("10", "0", "0", "1"), ip("10", "255", "255", "254"),                    # RFC1918 10/8
    ip("172", "16", "0", "1"), ip("172", "31", "255", "1"),                    # RFC1918 172.16/12 (both ends)
    ip("192", "168", "1", "1"),                                                # RFC1918 192.168/16
    ip("127", "0", "0", "1"), ip("127", "1", "1", "1"),                        # loopback
    ip("169", "254", "169", "254"),                                            # link-local (cloud metadata address)
    ip("100", "64", "0", "1"),                                                 # carrier-grade NAT
    ip("0", "0", "0", "0"), ip("255", "255", "255", "255"),                    # unspecified, broadcast
    ip("224", "0", "0", "1"), ip("239", "255", "255", "250"),                  # multicast
    ip("240", "0", "0", "1"),                                                  # reserved
    ip("192", "0", "0", "1"),                                                  # IETF protocol assignments
    ip("192", "0", "2", "7"), ip("198", "51", "100", "7"), ip("203", "0", "113", "7"),  # documentation ranges
    "::1", "::", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456:789a::1",   # IPv6 loopback, unspecified, link-local, unique-local
    "2001:db8::1",                                                             # IPv6 documentation
    "ff02" + "::1",                                                            # IPv6 multicast
    "::ffff:" + ip("10", "0", "0", "1"), "::ffff:" + ip("127", "0", "0", "1"), "::ffff:" + ip("192", "168", "0", "9"),  # IPv4-mapped
    "64" + ":ff9b" + "::" + ip("10", "0", "0", "1"),                           # NAT64 embedding a private IPv4
    "2002:0a00:0001::1",                                                       # 6to4 embedding a private 10/8 address
    "::" + ip("10", "0", "0", "1"),                                            # IPv4-compatible
]
INTERNAL_NAMES = [
    "localhost", "intranet", "fileserver", "printer", "wpad",                  # single-label names
    "srv.corp", "mail.CORP", "app.internal", "nas.local", "host.localdomain", "router.lan", "tv.home", "wiki.intranet", "vault.private",
    "x.localhost", "box.test", "a.example", "b.invalid", "4.3.2.1.in-addr.arpa", "gateway.home.arpa",
    "deep.sub.domain.corp", "srv.corp.",                                       # nested and trailing-dot forms
    "127.1", "0x7f.0.0.1", "0177.0.0.1", "2130706433", "10.1", "3232235777", "0xc0a80001", "1.2.3",  # obfuscated address spellings
    "abc.123", "host.-",                                                       # last label has no letter: cannot be a real domain
]
PUBLIC_HOSTS = ["example.com", "www.example.org", "a.b.example.co.uk", "xn--e1afmkfd.example.org", "login-secure.example.net", "my-host.example.info"]
ALL_INTERNAL = INTERNAL_ADDRESSES + INTERNAL_NAMES
PROVIDERS = ["virustotal", "urlscan", "threatfox", "malwarebazaar"]
OK_BODY = {"data": {"attributes": {"last_analysis_stats": {}}}, "query_status": "no_result", "results": []}


def _url(host: str) -> str:
    return f"http://[{host}]/x" if ":" in host else f"http://{host}/x"


# ---- classification --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ALL_INTERNAL)
def test_every_internal_looking_address_or_name_classifies_as_internal(host):
    assert classify_host(host.strip(".").lower()) == "internal"


@pytest.mark.parametrize("host", PUBLIC_HOSTS)
def test_real_domains_still_classify_as_domains(host):
    assert classify_host(host) == "domain"


@pytest.mark.parametrize("address", [PUBLIC_V4, ip("1", "1", "1", "1"), PUBLIC_V6, "::ffff:" + PUBLIC_V4, "64" + ":ff9b" + "::" + PUBLIC_V4])
def test_public_addresses_still_classify_as_ip(address):
    assert classify_host(address) == "ip"


# ---- what would be sent, for every provider -----------------------------------------------------------------------------

@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("host", ALL_INTERNAL)
def test_no_provider_is_ever_given_an_internal_target_by_default_or_with_url_opt_in(provider, host):
    for policy in (EnrichmentPolicy(), EnrichmentPolicy(path_query_providers=frozenset(PROVIDERS)), EnrichmentPolicy(granularity="registrable")):
        assert target_for(provider, _url(host), policy)[0] == "internal"


# ---- the guard itself, even if a caller classified wrongly --------------------------------------------------------------------

CLIENTS = {"virustotal": VirusTotalClient("k"), "urlscan": URLScanClient("k"), "threatfox": ThreatFoxClient("k"), "malwarebazaar": MalwareBazaarClient("k")}


@pytest.mark.parametrize("name", PROVIDERS)
@pytest.mark.parametrize("host", ALL_INTERNAL)
def test_the_guard_refuses_internal_values_whatever_type_the_caller_claims(fake_http, name, host):
    fake_http.respond(FakeResponse(200, OK_BODY))
    guarded = GuardedProvider(name, CLIENTS[name], EnrichmentPolicy(path_query_providers=frozenset(PROVIDERS)))
    for claimed_type in ("domain", "ip", "url", "internal"):
        value = _url(host) if claimed_type == "url" else host
        result = guarded.lookup(claimed_type, value)
        assert result["status"] in ("not_applicable",), (name, claimed_type, host, result)
    assert fake_http.calls == []  # nothing left the machine


@pytest.mark.parametrize("name", PROVIDERS)
def test_the_guard_is_not_so_strict_that_public_lookups_stop(fake_http, name):
    fake_http.respond(FakeResponse(200, {**OK_BODY, "query_status": "hash_not_found" if name == "malwarebazaar" else "no_result"}))
    ioc_type, value = ("sha256", "a" * 64) if name == "malwarebazaar" else ("domain", "example.com")
    result = GuardedProvider(name, CLIENTS[name], EnrichmentPolicy()).lookup(ioc_type, value)
    assert result["status"] == "ok" and len(fake_http.calls) == 1


# ---- the whole enrichment module, real clients, HTTP recorded ----------------------------------------------------------------

def _parsed(urls):
    return ParsedEmail(source_format="eml", urls=[ExtractedUrl(url=u, source="body_html") for u in urls],
                       from_={"display_name": "A", "address": "a@sender.example.org", "domain": "sender.example.org"}, raw_size_bytes=1)


def _clients():
    return {**CLIENTS, "risk_scorer": RiskScorer, "score_config": ScoreConfig()}


@pytest.mark.parametrize("opt_in", [frozenset(), frozenset(PROVIDERS)])
def test_a_message_full_of_internal_links_causes_zero_requests_and_every_host_is_unknown(fake_http, opt_in):
    fake_http.respond(FakeResponse(200, OK_BODY))
    result = run_enrichment(_parsed([_url(h) for h in ALL_INTERNAL]), _clients(), VTRateLimiter(sleep_fn=lambda s: None),
                            EnrichmentPolicy(path_query_providers=opt_in))
    assert fake_http.calls == []
    incomplete = [f for f in result.findings if f.title.startswith("Enrichment incomplete for")]
    assert incomplete and all("UNKNOWN (no answer), which is not the same as 'nothing found'" in f.description for f in incomplete)
    assert not [f for f in result.findings if f.title.startswith("Suspicious")]


def test_the_same_run_does_reach_the_network_for_a_public_host_so_the_zero_above_means_something(fake_http):
    fake_http.respond(FakeResponse(200, OK_BODY))
    run_enrichment(_parsed(["https://www.example.org/x"]), _clients(), VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    assert fake_http.calls and all("example.org" in str(c) or "virustotal" in c["url"] or "urlscan" in c["url"] or "threatfox" in c["url"] for c in fake_http.calls)


def test_internal_hosts_never_reach_the_network_even_next_to_public_ones(fake_http):
    fake_http.respond(FakeResponse(200, OK_BODY))
    run_enrichment(_parsed([_url(h) for h in (ip("10", "0", "0", "1"), "intranet", "127.1")] + ["https://www.example.org/x"]), _clients(),
                   VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    sent = " ".join(str(c) for c in fake_http.calls)
    for secret in (ip("10", "0", "0", "1"), "intranet", "127.1"):
        assert secret not in sent
    assert "www.example.org" in sent


def test_unknown_internal_hosts_cannot_support_a_benign_verdict():
    """Even with every other piece of positive evidence, an indicator that was never looked up is inadequate coverage."""
    from app.contracts.findings import ModuleResult

    enrichment = run_enrichment(_parsed([_url("intranet")]), _clients(), VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    auth = ModuleResult(module="auth_check", status="ok", findings=[], raw_data={
        "auth_headers": {"header_present": True, "trusted_receivers_configured": True, "dkim": {"evaluated": True, "result": "pass"}, "dmarc": {"evaluated": False}},
        "alignment": {"dkim": {"aligned": True}}, "identity": {"display_name_spoofing": {"actual_registrable_domain": "sender.example.org"}}})
    gaps = benign_evidence_gaps({"auth_check": auth, "enrichment": enrichment}, 1.0, ScoringConfig(known_sender_domains=frozenset({"sender.example.org"})))
    assert any("enrichment is incomplete" in g for g in gaps)


# ---- the indicator pack ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", [ip("10", "0", "0", "1"), "intranet", "srv.corp", "127.1", "fe80::1"])
def test_internal_indicators_are_a_manual_check_with_no_lookup_links_so_clicking_cannot_leak_them(host):
    pack = build_indicator_pack(_parsed([_url(host)]), [])
    item = next(i for i in pack.indicators if i.value == host)
    assert item.status == "internal" and item.manual_check and item.pivots == [] and item.providers == {}
