"""Logging is configured once at startup, reaches the console, and the enrichment guards' unknown/disabled outcomes show both there (counts
only, never an indicator) and in the API response."""
import logging
import time

import pytest
import requests
from fastapi.testclient import TestClient

from app.contracts.email import ExtractedUrl, ParsedEmail
from app.enrichment import run_enrichment
from app.enrichment.policy import EnrichmentPolicy
from app.enrichment.providers import RiskScorer, ScoreConfig, VirusTotalClient
from app.enrichment.rate_limit import VTRateLimiter
from app.logging_config import FORMAT, LOGGER_NAME, configure_logging
from tests.provider_fakes import FakeResponse, fake_http  # noqa: F401  (fixture)


def _ours(logger):
    """Our handlers only: pytest attaches its own capture handlers to loggers during a run."""
    return [h for h in logger.handlers if getattr(h, "_mail_analysis", False)]


@pytest.fixture
def clean_logger():
    logger = logging.getLogger(LOGGER_NAME)
    saved = (list(logger.handlers), logger.level, logger.propagate)
    logger.handlers = []
    yield logger
    logger.handlers, logger.level, logger.propagate = saved[0], saved[1], saved[2]


# ---- configuration ------------------------------------------------------------------------------------------------------

def test_configure_is_idempotent_one_handler_however_often_it_is_called(clean_logger):
    for _ in range(5):
        configure_logging()
    assert len(_ours(clean_logger)) == 1 and clean_logger.propagate is False


def test_level_comes_from_log_level_with_a_safe_default(clean_logger, monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    assert configure_logging().level == logging.INFO
    monkeypatch.setenv("LOG_LEVEL", "warning")
    assert configure_logging().level == logging.WARNING
    monkeypatch.setenv("LOG_LEVEL", "nonsense")
    assert configure_logging().level == logging.INFO
    assert configure_logging("DEBUG").level == logging.DEBUG and configure_logging(logging.ERROR).level == logging.ERROR
    assert len(_ours(clean_logger)) == 1  # changing the level never adds a handler


def test_other_loggers_are_left_alone(clean_logger):
    root_before = list(logging.getLogger().handlers)
    uvicorn_before = list(logging.getLogger("uvicorn").handlers)
    configure_logging()
    assert logging.getLogger().handlers == root_before and logging.getLogger("uvicorn").handlers == uvicorn_before


def test_starting_the_app_configures_logging_once():
    import app.main  # noqa: F401

    handlers = [h for h in logging.getLogger(LOGGER_NAME).handlers if getattr(h, "_mail_analysis", False)]
    assert len(handlers) == 1 and logging.getLogger("app.enrichment.providers.base").getEffectiveLevel() <= logging.INFO


def test_the_format_names_the_module_so_a_line_can_be_traced():
    assert "%(name)s" in FORMAT and "%(levelname)s" in FORMAT and "%(asctime)s" in FORMAT


# ---- the console ----------------------------------------------------------------------------------------------------------

def test_a_provider_warning_reaches_stderr(fake_http, capsys):
    configure_logging()
    fake_http.respond(FakeResponse(429, {}))
    VirusTotalClient("k").enrich("example.org", "domain")
    err = capsys.readouterr().err
    assert "WARNING app.enrichment.providers.base VirusTotalClient rate limited" in err


def test_a_provider_failure_after_all_retries_is_visible_too(fake_http, capsys):
    configure_logging()
    fake_http.respond(requests.ConnectionError("down"))
    VirusTotalClient("k").enrich("example.org", "domain")
    assert "network error attempt=3" in capsys.readouterr().err


class _Down:
    def __init__(self, status):
        self.status = status

    def enrich(self, value, ioc_type):
        return {"enabled": False, "status": self.status}


def _parsed(urls):
    return ParsedEmail(source_format="eml", urls=[ExtractedUrl(url=u, source="body_html") for u in urls],
                       from_={"display_name": "A", "address": "a@sender.example.org", "domain": "sender.example.org"}, raw_size_bytes=1)


def _clients(status="disabled"):
    stub = _Down(status)
    return {"virustotal": stub, "urlscan": stub, "threatfox": stub, "malwarebazaar": stub, "risk_scorer": RiskScorer, "score_config": ScoreConfig()}


def test_unknown_and_disabled_outcomes_are_one_console_warning_with_counts_and_no_indicators(capsys):
    configure_logging()
    result = run_enrichment(_parsed(["https://secret-host.example.org/a", "http://intranet/x", "http://srv.corp/y"]), _clients("disabled"),
                            VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    err = capsys.readouterr().err
    assert "WARNING app.enrichment enrichment: 1 indicator(s) looked up; the rest is UNKNOWN (no answer), which is not the same as 'nothing found'" in err
    assert "virustotal: disabled x1" in err and "urlscan: disabled x1" in err and "threatfox: disabled x1" in err
    assert "2 internal-looking host(s) never sent (not looked up)" in err
    for private in ("secret-host", "intranet", "srv.corp", "example.org"):
        assert private not in err
    # the same facts are in the module result the API returns
    titles = [f.title for f in result.findings]
    assert "Some enrichment providers did not give a usable answer" in titles
    assert sum(t.startswith("Enrichment incomplete for") for t in titles) >= 2


def test_rate_limited_providers_are_named_in_the_summary(capsys):
    configure_logging()
    run_enrichment(_parsed(["https://a.example.org/"]), _clients("rate_limited"), VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    assert "virustotal: rate_limited x1" in capsys.readouterr().err


def test_an_all_answered_analysis_logs_info_not_a_warning(capsys):
    configure_logging()

    class Ok:
        def enrich(self, value, ioc_type):
            return {"enabled": True, "status": "ok", "matched": False, "total_results": 0, "malicious": 0, "suspicious": 0}

    clients = {**_clients(), "virustotal": Ok(), "urlscan": Ok(), "threatfox": Ok(), "malwarebazaar": Ok()}
    run_enrichment(_parsed(["https://a.example.org/"]), clients, VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    err = capsys.readouterr().err
    assert "INFO app.enrichment enrichment: 1 indicator(s) looked up, every provider answered" in err and "WARNING app.enrichment" not in err


def test_shared_platform_hosts_and_skipped_indicators_are_counted(capsys, monkeypatch):
    configure_logging()
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    urls = ["https://docs.google.com/d/x", "https://one.example.org/", "https://two.example.org/", "https://three.example.org/"]
    run_enrichment(_parsed(urls), _clients("disabled"), VTRateLimiter(sleep_fn=lambda s: None), EnrichmentPolicy())
    err = capsys.readouterr().err
    assert "1 shared-platform host(s) not looked up" in err and "2 indicator(s) skipped by the per-email limit" in err


# ---- through the API --------------------------------------------------------------------------------------------------------

def test_the_api_response_and_the_console_tell_the_same_story(monkeypatch, capsys):
    from app.main import app

    monkeypatch.setattr("app.enrichment.providers.get_clients", lambda: _clients("disabled"))
    monkeypatch.setattr("app.llm.gemini_client.get_client", lambda: (lambda prompt: '{"narrative": "n", "flags": []}'))
    raw = (b"From: A <a@sender.example.org>\r\nTo: t@example.com\r\nSubject: hi\r\nMessage-ID: <1@x.example.org>\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: text/html\r\n\r\n<html><a href=\"https://one.example.org/x\">go</a> <a href=\"http://intranet/y\">in</a></html>\r\n")
    client = TestClient(app)
    job_id = client.post("/analyze", files={"file": ("m.eml", raw, "message/rfc822")}).json()["job_id"]
    body = {}
    for _ in range(100):
        body = client.get(f"/analyze/{job_id}").json()
        if body["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert body["status"] == "done"
    titles = [f["title"] for f in body["result"]["findings"]]
    assert "Some enrichment providers did not give a usable answer" in titles
    assert any(t == "Enrichment incomplete for intranet" for t in titles)
    err = capsys.readouterr().err
    assert "UNKNOWN (no answer), which is not the same as 'nothing found'" in err and "internal-looking host(s) never sent" in err and "intranet" not in err
