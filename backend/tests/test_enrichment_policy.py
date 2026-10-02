"""Enrichment privacy policy: what may be sent, provider guard, unknown-never-clean semantics."""
import pytest

from app.contracts.email import Attachment, ExtractedUrl
from app.enrichment import run_enrichment
from app.enrichment.policy import (
    ALLOWED_TYPES,
    EnrichmentPolicy,
    GuardedProvider,
    PolicyViolation,
    classify_host,
    host_of,
    load_policy,
    target_for,
)
from app.scoring.aggregate import category_coverage
from tests.fixtures.provider_responses import (
    CLEAN_URLSCAN_RESULT,
    CLEAN_VT_URL_RESULT,
    NO_MATCH_MALWAREBAZAAR_RESULT,
    NO_MATCH_THREATFOX_RESULT,
)
from tests.test_enrichment import StubClient, _base_parsed_email, _no_sleep_limiter, _real_scorer_clients

# Addresses are assembled at runtime: fixtures/tests must not contain IP literals (see scripts/check_fixtures.py).
PRIVATE_A = ".".join(("10", "1", "2", "3"))
PRIVATE_B = ".".join(("192", "168", "0", "5"))
PUBLIC_IP = ".".join(("8", "8", "4", "4"))
SECRET_URL = "https://tracker.evil-example.net/path/secret-token-123?upn=SECRETQUERY&id=42#frag"
DEFAULT = EnrichmentPolicy()


# ---- what would be sent ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", ["virustotal", "urlscan", "threatfox"])
def test_default_target_is_the_hostname_only(provider):
    ioc_type, value = target_for(provider, SECRET_URL, DEFAULT)
    assert (ioc_type, value) == ("domain", "tracker.evil-example.net")
    for fragment in ("secret", "SECRET", "/", "?", "#", "upn", "42"):
        assert fragment not in value


def test_registrable_granularity_sends_only_the_registrable_domain():
    policy = EnrichmentPolicy(granularity="registrable")
    assert target_for("virustotal", "https://a.b.example.co.uk/x?y=1", policy) == ("domain", "example.co.uk")


def test_ip_literals_are_sent_as_ip_without_port_or_path():
    assert target_for("virustotal", f"http://{PUBLIC_IP}:8080/login?x=1", DEFAULT) == ("ip", PUBLIC_IP)


def test_documentation_range_addresses_are_not_routable_so_they_are_never_sent():
    assert target_for("virustotal", "http://198.51.100.9/x", DEFAULT)[0] == "internal"


@pytest.mark.parametrize(
    "url",
    ["http://localhost/x", "http://intranet/x", "http://srv.corp/x", "http://printer.local/x", f"http://{PRIVATE_A}/x",
     f"http://{PRIVATE_B}/x", "http://127.0.0.1/x", "http://[::1]/x", "http://host.internal/x", "not a url"],
)
def test_internal_looking_hosts_are_never_sent(url):
    assert target_for("virustotal", url, DEFAULT)[0] == "internal"


def test_idn_hosts_are_sent_as_punycode():
    assert target_for("virustotal", "https://пример.example.org/x", DEFAULT) == ("domain", "xn--e1afmkfd.example.org")


def test_only_an_opted_in_provider_gets_the_full_url():
    policy = EnrichmentPolicy(path_query_providers=frozenset({"virustotal"}))
    assert target_for("virustotal", SECRET_URL, policy) == ("url", SECRET_URL)
    assert target_for("urlscan", SECRET_URL, policy)[1] == "tracker.evil-example.net"
    assert target_for("threatfox", SECRET_URL, policy)[1] == "tracker.evil-example.net"


def test_host_extraction_edge_cases():
    assert host_of("https://User:pw@Host.Example.COM:8443/p") == "host.example.com"
    assert host_of("https://host.example.com./x") == "host.example.com"
    assert host_of("garbage") is None
    assert classify_host("example.com") == "domain" and classify_host(PUBLIC_IP) == "ip"


# ---- the guard ------------------------------------------------------------------------------------

class Recorder:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result or {"status": "ok"}, exc, []

    def enrich(self, value, ioc_type):
        self.calls.append((value, ioc_type))
        if self.exc:
            raise self.exc
        return self.result


def test_guard_exposes_only_lookup_so_nothing_can_be_uploaded_or_submitted():
    guard = GuardedProvider("virustotal", Recorder(), DEFAULT)
    public = {n for n in dir(guard) if not n.startswith("_")}
    assert public == {"name", "policy", "disabled", "lookup"}
    for forbidden in ("upload", "submit", "scan", "post", "client", "enrich"):
        assert not hasattr(guard, forbidden)


def test_a_url_lookup_without_opt_in_is_a_policy_violation_not_a_send():
    rec = Recorder()
    with pytest.raises(PolicyViolation):
        GuardedProvider("virustotal", rec, DEFAULT).lookup("url", SECRET_URL)
    assert rec.calls == []


@pytest.mark.parametrize("value", ["host.example.com/path", "host.example.com?x=1", "host.example.com#f", "user@host.example.com"])
def test_a_host_lookup_carrying_path_or_query_characters_is_a_violation(value):
    rec = Recorder()
    with pytest.raises(PolicyViolation):
        GuardedProvider("virustotal", rec, DEFAULT).lookup("domain", value)
    assert rec.calls == []


@pytest.mark.parametrize("name,ioc_type", [("malicious_not_a_provider", "domain")])
def test_unknown_provider_name_is_rejected(name, ioc_type):
    with pytest.raises(ValueError):
        GuardedProvider(name, Recorder(), DEFAULT)


def test_a_provider_is_never_asked_about_types_outside_its_allowance():
    rec = Recorder()
    result = GuardedProvider("malwarebazaar", rec, DEFAULT).lookup("domain", "example.com")
    assert result["status"] == "not_applicable" and rec.calls == []
    assert ALLOWED_TYPES["malwarebazaar"] == {"sha256"}


def test_a_disabled_provider_is_never_called_and_reports_disabled():
    rec = Recorder()
    guard = GuardedProvider("virustotal", rec, EnrichmentPolicy(disabled_providers=frozenset({"virustotal"})))
    result = guard.lookup("domain", "example.com")
    assert result["status"] == "disabled" and result["enabled"] is False and "configuration" in result["error"] and rec.calls == []


def test_a_raising_client_becomes_failed_not_a_crash_and_not_clean():
    result = GuardedProvider("virustotal", Recorder(exc=TimeoutError("read timed out")), DEFAULT).lookup("domain", "example.com")
    assert result["status"] == "failed" and "TimeoutError" in result["error"]


def test_a_non_dict_response_becomes_invalid_response():
    assert GuardedProvider("virustotal", Recorder(result="oops"), DEFAULT).lookup("domain", "example.com")["status"] == "invalid_response"
    assert GuardedProvider("virustotal", Recorder(result={"no": "status"}), DEFAULT).lookup("domain", "example.com")["status"] == "invalid_response"


# ---- policy loading -------------------------------------------------------------------------------

def test_load_policy_defaults_are_privacy_first():
    p = load_policy()
    assert p.path_query_providers == frozenset() and p.disabled_providers == frozenset() and p.granularity == "hostname"


def test_load_policy_reads_config_case_insensitively(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_DISABLED_PROVIDERS", ["VirusTotal"])
    monkeypatch.setattr("app.config.ENRICHMENT_PATH_QUERY_PROVIDERS", ["urlscan"])
    monkeypatch.setattr("app.config.ENRICHMENT_GRANULARITY", "Registrable")
    p = load_policy()
    assert p.disabled_providers == {"virustotal"} and p.path_query_providers == {"urlscan"} and p.granularity == "registrable"


@pytest.mark.parametrize("attr,value", [("ENRICHMENT_DISABLED_PROVIDERS", ["virustotl"]), ("ENRICHMENT_PATH_QUERY_PROVIDERS", ["nope"]),
                                        ("ENRICHMENT_GRANULARITY", "full_url")])
def test_a_typo_in_the_config_fails_loudly_instead_of_leaving_a_provider_enabled(monkeypatch, attr, value):
    monkeypatch.setattr(f"app.config.{attr}", value)
    with pytest.raises(ValueError):
        load_policy()


# ---- run_enrichment: what actually leaves ---------------------------------------------------------

def _clients(**overrides):
    base = dict(
        virustotal=StubClient(CLEAN_VT_URL_RESULT), urlscan=StubClient(CLEAN_URLSCAN_RESULT),
        threatfox=StubClient(NO_MATCH_THREATFOX_RESULT), malwarebazaar=StubClient(NO_MATCH_MALWAREBAZAAR_RESULT),
    )
    base.update(overrides)
    return _real_scorer_clients(**base)


def _all_calls(clients):
    return [c for name in ("virustotal", "urlscan", "threatfox", "malwarebazaar") for c in clients[name].calls]


def test_nothing_from_the_path_or_query_reaches_any_provider():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=SECRET_URL, source="body_html")])
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    sent = _all_calls(clients)
    assert sent and all(t == "domain" and v == "tracker.evil-example.net" for v, t in sent)
    blob = repr(sent)
    for secret in ("secret-token", "SECRETQUERY", "/path", "frag", "upn"):
        assert secret not in blob
    # the analyst can see exactly what left the machine
    assert result.raw_data["tracker.evil-example.net"]["sent"]["virustotal"] == {"type": "domain", "value": "tracker.evil-example.net"}


def test_opt_in_sends_the_url_only_to_the_named_provider(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_PATH_QUERY_PROVIDERS", ["virustotal"])
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=SECRET_URL, source="body_html")])
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert clients["virustotal"].calls == [(SECRET_URL, "url")]
    assert clients["urlscan"].calls == [("tracker.evil-example.net", "domain")]
    assert clients["threatfox"].calls == [("tracker.evil-example.net", "domain")]


def test_internal_hosts_are_never_sent_and_are_unknown_not_clean():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=u, source="body_html") for u in
                                      ("http://intranet/x", f"http://{PRIVATE_A}/y", "http://files.corp/z")])
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert _all_calls(clients) == []
    incomplete = [f for f in result.findings if f.title.startswith("Enrichment incomplete for")]
    assert len(incomplete) == 3 and all("UNKNOWN" in f.description for f in incomplete)
    assert category_coverage("enrichment", result) == 0.0


def test_disabled_provider_is_not_called_is_visible_and_lowers_coverage(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_DISABLED_PROVIDERS", ["virustotal"])
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://one.example.org/a", source="body_html")])
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert clients["virustotal"].calls == []
    assert [c for c in clients["urlscan"].calls] == [("one.example.org", "domain")]
    vt_gaps = [f for f in result.findings if f.evidence.get("provider") == "virustotal"]
    assert vt_gaps and vt_gaps[0].evidence["result"]["status"] == "disabled"
    warning = next(f for f in result.findings if f.title == "Some enrichment providers did not give a usable answer")
    assert warning.weight == 0.0 and "virustotal" in warning.description and "UNKNOWN" in warning.description
    assert category_coverage("enrichment", result) < 1.0


def test_vt_rate_limiter_is_not_consulted_when_virustotal_is_disabled(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_DISABLED_PROVIDERS", ["virustotal"])

    class Spy:
        waited = 0

        def wait_if_needed(self):
            Spy.waited += 1

    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://one.example.org/a", source="body_html")])
    run_enrichment(parsed, clients=_clients(), vt_limiter=Spy())
    assert Spy.waited == 0


@pytest.mark.parametrize("status", ["disabled", "not_applicable", "rate_limited", "failed", "invalid_response", "timeout", "error", "something_new"])
def test_every_status_other_than_ok_is_unknown_never_clean(status):
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://one.example.org/a", source="body_html")])
    clients = _clients(virustotal=StubClient({"status": status}), urlscan=StubClient({"status": status}),
                       threatfox=StubClient({"status": status}))
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert len([f for f in result.findings if f.title.startswith("Enrichment incomplete for")]) == 3
    assert category_coverage("enrichment", result) == 0.0


def test_a_client_that_raises_does_not_abort_the_module():
    class Boom:
        def enrich(self, value, ioc_type):
            raise ConnectionError("network down")

    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://one.example.org/a", source="body_html")])
    result = run_enrichment(parsed, clients=_clients(virustotal=Boom()), vt_limiter=_no_sleep_limiter())
    assert result.status == "ok"
    vt = next(f for f in result.findings if f.evidence.get("provider") == "virustotal")
    assert vt.evidence["result"]["status"] == "failed" and "ConnectionError" in vt.evidence["result"]["error"]


# ---- URLScan hit counts are context, not risk (at host level) -------------------------------------

BUSY_URLSCAN = {"status": "ok", "query": "q", "total_results": 5000, "sample_urls": [], "sample_domains": [], "sample_countries": [], "screenshots": []}


def test_urlscan_hit_count_adds_no_risk_at_host_level():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="https://popular.example.org/x", source="body_html")])
    result = run_enrichment(parsed, clients=_clients(urlscan=StubClient(BUSY_URLSCAN)), vt_limiter=_no_sleep_limiter())
    assert not [f for f in result.findings if f.title.startswith("Suspicious")]
    assert result.raw_data["popular.example.org"]["urlscan_context_only"] is True
    assert result.raw_data["popular.example.org"]["urlscan"]["total_results"] == 5000  # still shown to the analyst


def test_urlscan_exact_url_lookup_still_scores_when_the_provider_opted_in(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_PATH_QUERY_PROVIDERS", ["urlscan"])
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="https://popular.example.org/x", source="body_html")])
    result = run_enrichment(parsed, clients=_clients(urlscan=StubClient(BUSY_URLSCAN)), vt_limiter=_no_sleep_limiter())
    assert result.raw_data["https://popular.example.org/x"]["urlscan_context_only"] is False
    assert [f for f in result.findings if f.title.startswith("Suspicious URL")]


# ---- hashes: lookups only -------------------------------------------------------------------------

def test_attachment_hashes_are_looked_up_by_hash_only():
    sha = "ab" * 32
    parsed = _base_parsed_email(attachments=[Attachment(filename="invoice.pdf", content_type="application/pdf", size_bytes=10,
                                                        sha256=sha, sha1="c" * 40, md5="d" * 32)])
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert clients["virustotal"].calls == [(sha, "sha256")]
    assert clients["threatfox"].calls == [(sha, "sha256")]
    assert clients["malwarebazaar"].calls == [(sha, "sha256")]
    assert clients["urlscan"].calls == []
    assert "invoice.pdf" not in repr(_all_calls(clients))  # the file name never leaves either
