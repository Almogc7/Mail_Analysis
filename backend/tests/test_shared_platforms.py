"""Shared-platform list (config file, not hardcoded) and the 'uninformative' enrichment state."""
import json

import pytest

from app.contracts.email import ExtractedUrl
from app.enrichment import run_enrichment
from app.enrichment import policy
from app.enrichment.policy import DEFAULT_PLATFORMS_FILE, load_platforms, platform_of
from app.scoring.aggregate import category_coverage
from tests.test_enrichment import StubClient, _base_parsed_email, _no_sleep_limiter, _real_scorer_clients
from tests.test_enrichment_policy import _all_calls, _clients

KINDS = {"esp_tracker", "link_wrapper", "shortener", "cloud_content", "site_builder"}


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("SHARED_PLATFORMS_EXTRA_FILE", raising=False)
    policy._load_platforms.cache_clear()
    yield
    policy._load_platforms.cache_clear()


# ---- the list itself ------------------------------------------------------------------------------

def test_the_default_list_is_a_json_config_file_with_valid_entries():
    data = json.loads(DEFAULT_PLATFORMS_FILE.read_text(encoding="utf-8"))
    assert data["version"] == 1 and len(data["platforms"]) >= 30
    seen: dict[str, str] = {}
    for entry in data["platforms"]:
        assert entry["kind"] in KINDS, entry["name"]
        for domain in entry["domains"]:
            assert domain == domain.lower().strip(".") and "/" not in domain and " " not in domain, domain
            assert domain not in seen, f"{domain} listed under both {seen.get(domain)} and {entry['name']}"
            seen[domain] = entry["name"]
    # the ones the owner named explicitly
    for required in ("sendgrid.net", "mailchimp.com", "sharepoint.com", "1drv.ms", "forms.gle", "docs.google.com", "dropbox.com"):
        assert required in seen, required


@pytest.mark.parametrize(
    "host,name_contains,kind",
    [
        ("u108122857.ct.sendgrid.net", "SendGrid", "esp_tracker"),
        ("sendgrid.net", "SendGrid", "esp_tracker"),
        ("list-manage.com", "Mailchimp", "esp_tracker"),
        ("contoso.sharepoint.com", "SharePoint", "cloud_content"),
        ("forms.gle", "Google", "cloud_content"),
        ("docs.google.com", "Google", "cloud_content"),
        ("www.dropbox.com", "Dropbox", "cloud_content"),
        ("x.blob.core.windows.net", "Azure", "cloud_content"),
        ("eur01.safelinks.protection.outlook.com", "Safe Links", "link_wrapper"),
        ("bit.ly", "Bitly", "shortener"),
        ("someone.github.io", "Code", "site_builder"),
    ],
)
def test_platform_matching_by_host_suffix(host, name_contains, kind):
    p = platform_of(host)
    assert p is not None and name_contains in p.name and p.kind == kind


@pytest.mark.parametrize("host", ["notsendgrid.net", "sendgrid.net.evil-example.net", "evil-sendgrid.net", "example.com",
                                  "service.kvish6.co.il", "vh319.sweb.ru", "windows.net", "", None])
def test_lookalike_and_ordinary_hosts_do_not_match(host):
    assert platform_of(host) is None


def test_the_longest_matching_domain_wins(tmp_path, monkeypatch):
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"platforms": [{"name": "Contoso tenant", "kind": "cloud_content", "domains": ["files.contoso.example"]}]}))
    monkeypatch.setenv("SHARED_PLATFORMS_EXTRA_FILE", str(extra))
    assert platform_of("a.files.contoso.example").name == "Contoso tenant"
    assert platform_of("a.sharepoint.com").name.startswith("Microsoft SharePoint")


def test_an_untracked_extra_file_adds_organisation_specific_platforms(tmp_path, monkeypatch):
    assert platform_of("docs.contoso.example") is None
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"platforms": [{"name": "Contoso portal", "kind": "cloud_content", "domains": ["contoso.example"]}]}))
    monkeypatch.setenv("SHARED_PLATFORMS_EXTRA_FILE", str(extra))
    assert platform_of("docs.contoso.example").name == "Contoso portal"
    assert platform_of("u1.ct.sendgrid.net") is not None  # the default list still applies


@pytest.mark.parametrize("content", ["not json", "[]", '{"platforms": "x"}', '{"platforms": [{"name": "x"}]}',
                                     '{"platforms": [{"name": "x", "kind": "k", "domains": []}]}',
                                     '{"platforms": [{"name": "x", "kind": "k", "domains": [1]}]}'])
def test_a_malformed_extra_file_fails_loudly(tmp_path, monkeypatch, content):
    extra = tmp_path / "extra.json"
    extra.write_text(content)
    monkeypatch.setenv("SHARED_PLATFORMS_EXTRA_FILE", str(extra))
    with pytest.raises(ValueError):
        load_platforms()


def test_a_missing_extra_file_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv("SHARED_PLATFORMS_EXTRA_FILE", str(tmp_path / "nope.json"))
    with pytest.raises(ValueError):
        load_platforms()


# ---- enrichment: uninformative, never clean -------------------------------------------------------

TRACKER = "https://u4412345.ct.sendgrid.net/ls/click?upn=u001.SECRETTOKEN"


def test_a_link_on_a_shared_platform_is_not_looked_up_and_is_uninformative_not_clean():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=TRACKER, source="body_html")])
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert _all_calls(clients) == []  # nothing is sent: the lookup could not be informative
    assert result.raw_data["u4412345.ct.sendgrid.net"] == {"uninformative": {"platform": "SendGrid", "kind": "esp_tracker"}}
    gap = next(f for f in result.findings if f.title.startswith("Enrichment incomplete for"))
    assert gap.evidence["state"] == "uninformative" and gap.evidence["platform"] == "SendGrid" and gap.weight == 0.0
    assert "UNINFORMATIVE" in gap.description and "unknown on reputation, which is not the same as 'nothing found'" in gap.description
    assert not [f for f in result.findings if f.title.startswith("Suspicious")]
    assert category_coverage("enrichment", result) == 0.0  # no reputation evidence exists


def test_platform_links_do_not_consume_the_per_email_cap(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    urls = [f"https://u{i}.ct.sendgrid.net/ls/click?upn=t{i}" for i in range(5)] + ["https://real-host.example.org/x"]
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=u, source="body_html") for u in urls])
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert ("real-host.example.org", "domain") in clients["virustotal"].calls
    assert not [f for f in result.findings if "per-email limit" in f.title]


def test_a_real_host_next_to_a_platform_host_is_still_looked_up():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=TRACKER, source="body_html"),
                                      ExtractedUrl(url="https://payments.evil-example.net/pay", source="body_html")])
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert clients["virustotal"].calls == [("payments.evil-example.net", "domain")]


def test_platform_detection_is_host_based_so_opt_in_url_mode_does_not_leak_platform_links(monkeypatch):
    monkeypatch.setattr("app.config.ENRICHMENT_PATH_QUERY_PROVIDERS", ["virustotal"])
    parsed = _base_parsed_email(urls=[ExtractedUrl(url=TRACKER, source="body_html")])
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert _all_calls(clients) == []


def test_a_malicious_url_on_a_lookalike_of_a_platform_is_still_looked_up():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="https://sendgrid.net.evil-example.net/ls/click", source="body_html")])
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert clients["virustotal"].calls == [("sendgrid.net.evil-example.net", "domain")]
