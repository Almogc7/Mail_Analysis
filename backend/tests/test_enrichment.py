from app.contracts.email import Attachment, EmailAddress, ExtractedUrl, ParsedEmail
from app.enrichment import run_enrichment
from app.enrichment.ioc_bridge import get_clients
from app.enrichment.rate_limit import VTRateLimiter
from app.scoring.aggregate import category_coverage
from tests.fixtures.provider_responses import (
    CLEAN_URLSCAN_RESULT,
    CLEAN_VT_URL_RESULT,
    DISABLED_RESULT,
    EICAR_SHA256,
    MALICIOUS_VT_URL_RESULT,
    MATCHED_MALWAREBAZAAR_RESULT,
    MATCHED_THREATFOX_RESULT,
    NO_MATCH_MALWAREBAZAAR_RESULT,
    NO_MATCH_THREATFOX_RESULT,
    NOT_APPLICABLE_RESULT,
    RATE_LIMITED_RESULT,
)


class StubClient:
    """Duck-typed stand-in for an IOC_Enricher provider client. Records calls so tests
    can assert caching/dedup behavior, and returns a fixed canned result regardless of
    input (or a per-value override via `responses`)."""

    def __init__(self, default_result, responses: dict[str, dict] | None = None):
        self.default_result = default_result
        self.responses = responses or {}
        self.calls: list[tuple[str, str]] = []

    def enrich(self, ioc_value: str, ioc_type: str):
        self.calls.append((ioc_value, ioc_type))
        return self.responses.get(ioc_value, self.default_result)


def _no_sleep_limiter() -> VTRateLimiter:
    return VTRateLimiter(sleep_fn=lambda seconds: None)


def _real_scorer_clients(**overrides) -> dict:
    """Uses IOC_Enricher's real RiskScorer/ScoreConfig (pure logic, no network) alongside
    stub provider clients, so the mapping from provider dict shapes to Findings is
    exercised against real scoring behavior without ever calling the network."""
    real = get_clients()
    clients = {
        "virustotal": StubClient(CLEAN_VT_URL_RESULT),
        "urlscan": StubClient(CLEAN_URLSCAN_RESULT),
        "threatfox": StubClient(NO_MATCH_THREATFOX_RESULT),
        "malwarebazaar": StubClient(NO_MATCH_MALWAREBAZAAR_RESULT),
        "risk_scorer": real["risk_scorer"],
        "score_config": real["score_config"],
    }
    clients.update(overrides)
    return clients


def _base_parsed_email(**overrides) -> ParsedEmail:
    defaults = dict(
        source_format="eml",
        from_=EmailAddress(address="alice@example.com", domain="example.com"),
        raw_size_bytes=100,
    )
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def test_clean_url_produces_no_finding():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://benign.example.com", source="body_text")])
    clients = _real_scorer_clients()

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert result.findings == []
    assert "benign.example.com" in result.raw_data  # the IOC is the HOST, not the full URL


def test_malicious_url_produces_finding_with_both_provider_components():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://evil.example.com", source="body_text")])
    clients = _real_scorer_clients(
        virustotal=StubClient(MALICIOUS_VT_URL_RESULT),
        threatfox=StubClient(MATCHED_THREATFOX_RESULT),
    )

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert "evil.example.com" in finding.title
    assert finding.severity in {"medium", "high", "critical"}
    sources = {c["source"] for c in finding.evidence["components"]}
    assert "virustotal" in sources
    assert "threatfox" in sources


def test_known_malware_hash_via_malwarebazaar():
    parsed = _base_parsed_email(
        attachments=[
            Attachment(filename="invoice.exe", size_bytes=1234, sha256=EICAR_SHA256, sha1="a" * 40, md5="b" * 32)
        ]
    )
    clients = _real_scorer_clients(malwarebazaar=StubClient(MATCHED_MALWAREBAZAAR_RESULT))

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert len(result.findings) == 1
    assert "invoice.exe" in result.findings[0].title


def test_rate_limited_provider_produces_incomplete_finding_not_clean():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://unknown.example.com", source="body_text")])
    clients = _real_scorer_clients(virustotal=StubClient(RATE_LIMITED_RESULT))

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    titles = [f.title for f in result.findings]
    assert any("Enrichment incomplete" in t for t in titles)


def test_many_links_on_one_host_cost_a_single_lookup():
    # same URL in text and html, plus other paths on the same host: one lookup per provider
    parsed = _base_parsed_email(
        urls=[
            ExtractedUrl(url="http://example.com/a", source="body_text"),
            ExtractedUrl(url="http://example.com/a", source="body_html", anchor_text="click here"),
            ExtractedUrl(url="http://example.com/other?x=1", source="body_html"),
        ]
    )
    vt_stub = StubClient(CLEAN_VT_URL_RESULT)
    clients = _real_scorer_clients(virustotal=vt_stub)

    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert vt_stub.calls == [("example.com", "domain")]


def test_per_email_url_cap_emits_skip_finding(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    parsed = _base_parsed_email(
        urls=[
            ExtractedUrl(url="http://example.com/a", source="body_text"),
            ExtractedUrl(url="http://other.example.org/b", source="body_text"),
        ]
    )
    clients = _real_scorer_clients()

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    skip_titles = [f.title for f in result.findings if "per-email limit" in f.title]
    assert len(skip_titles) == 1
    assert "example.com" not in result.raw_data or "other.example.org" not in result.raw_data


def test_not_applicable_provider_result_is_unknown_not_clean():
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://noscore.example.com", source="body_text")])
    clients = _real_scorer_clients(
        virustotal=StubClient(NOT_APPLICABLE_RESULT),
        urlscan=StubClient(NOT_APPLICABLE_RESULT),
        threatfox=StubClient(NOT_APPLICABLE_RESULT),
    )

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    # No risk finding (nothing was detected), but a visible "incomplete" warning per provider.
    assert not any(f.title.startswith("Suspicious URL") for f in result.findings)
    incomplete = [f for f in result.findings if f.title.startswith("Enrichment incomplete")]
    assert {f.evidence["provider"] for f in incomplete} == {"virustotal", "urlscan", "threatfox"}


def test_disabled_providers_are_unknown_not_clean_and_drop_coverage():
    # Providers return status="disabled" when no API key is configured.
    parsed = _base_parsed_email(urls=[ExtractedUrl(url="http://noscore.example.com", source="body_text")])
    clients = _real_scorer_clients(
        virustotal=StubClient(DISABLED_RESULT),
        urlscan=StubClient(DISABLED_RESULT),
        threatfox=StubClient(DISABLED_RESULT),
    )

    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    assert len([f for f in result.findings if f.title.startswith("Enrichment incomplete")]) == 3
    assert category_coverage("enrichment", result) == 0.0
