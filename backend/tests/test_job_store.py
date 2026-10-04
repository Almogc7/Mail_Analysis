"""The job store (and the message body text in it) is memory-only and finished jobs expire (D5 in docs/DESIGN_V2.md). The body text is
never logged, persisted, exported, or sent to a provider or the LLM."""
import time

import pytest
from fastapi.testclient import TestClient

from app import feedback
from app.api import pipeline, routes
from app.contracts.findings import ModuleResult
from app.enrichment.providers import RiskScorer, ScoreConfig
from app.llm import run_llm_opinion
from app.main import app
from tests.eval import apply_mode

MARKER = "SECRET-BODY-MARKER-9f3a"
RAW = (f"From: A <a@sender.example.org>\r\nTo: t@example.com\r\nSubject: hello\r\nMessage-ID: <1@x.example.org>\r\nMIME-Version: 1.0\r\n"
       f"Content-Type: text/html; charset=utf-8\r\n\r\n<html><p>{MARKER}</p><a href=\"https://one.example.org/x\">go</a></html>\r\n").encode()


class Recorder:
    """A provider client that records every value it is asked about."""

    def __init__(self):
        self.seen: list[tuple[str, str]] = []

    def enrich(self, value, ioc_type):
        self.seen.append((ioc_type, value))
        return {"enabled": True, "status": "ok", "matched": False, "total_results": 0, "malicious": 0, "suspicious": 0}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(routes, "_jobs", {})
    monkeypatch.setattr(routes, "_job_created", {})
    return TestClient(app)


@pytest.fixture
def clock(monkeypatch):
    state = {"t": 1000.0}
    monkeypatch.setattr(routes, "_now", lambda: state["t"])
    return state


def _stub_pipeline(monkeypatch, recorder=None, prompts=None):
    apply_mode("strict")
    recorder = recorder or Recorder()
    monkeypatch.setattr("app.enrichment.providers.get_clients", lambda: {
        "virustotal": recorder, "urlscan": recorder, "threatfox": recorder, "malwarebazaar": recorder, "risk_scorer": RiskScorer, "score_config": ScoreConfig()})

    def llm(result):
        captured = prompts if prompts is not None else []
        return run_llm_opinion(result, chat_client=lambda prompt: captured.append(prompt) or '{"narrative": "n", "flags": []}')

    monkeypatch.setattr(pipeline, "run_llm_opinion", llm)
    return recorder


def _submit_and_wait(client, name="m.eml"):
    job_id = client.post("/analyze", files={"file": (name, RAW, "message/rfc822")}).json()["job_id"]
    for _ in range(200):
        body = client.get(f"/analyze/{job_id}").json()
        if body["status"] in ("done", "error"):
            return job_id, body
        time.sleep(0.02)
    raise AssertionError("job did not finish")


# ---- expiry -------------------------------------------------------------------------------------------------------------------

def test_a_finished_job_is_available_until_its_ttl_and_gone_after(client, clock, monkeypatch):
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(routes, "JOB_TTL_SECONDS", 1800)
    job_id, body = _submit_and_wait(client)
    assert body["status"] == "done" and MARKER in body["result"]["parsed_email"]["body_html"]
    clock["t"] += 1799
    assert client.get(f"/analyze/{job_id}").status_code == 200
    clock["t"] += 2
    gone = client.get(f"/analyze/{job_id}")
    assert gone.status_code == 404 and MARKER not in gone.text
    assert job_id not in routes._jobs and job_id not in routes._job_created  # nothing is left behind


def test_expiry_also_applies_when_a_new_job_is_submitted_and_to_feedback(client, clock, monkeypatch, tmp_path):
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(routes, "JOB_TTL_SECONDS", 60)
    monkeypatch.setattr(feedback, "FEEDBACK_DB", tmp_path / "f.sqlite")
    first, _ = _submit_and_wait(client)
    clock["t"] += 61
    second, _ = _submit_and_wait(client)  # submitting purges the first
    assert first not in routes._jobs and second in routes._jobs
    assert client.post(f"/analyze/{first}/feedback", json={"agree": True}).status_code == 404


def test_a_job_that_is_still_running_is_never_expired_under_its_own_thread(clock, monkeypatch):
    monkeypatch.setattr(routes, "_jobs", {"j": routes.AnalysisJob(job_id="j", status="running")})
    monkeypatch.setattr(routes, "_job_created", {"j": 0.0})
    monkeypatch.setattr(routes, "JOB_TTL_SECONDS", 10)
    clock["t"] = 10_000.0
    routes._purge_expired()
    assert "j" in routes._jobs
    routes._jobs["j"] = routes.AnalysisJob(job_id="j", status="done")
    routes._purge_expired()
    assert "j" not in routes._jobs


def test_a_ttl_of_zero_means_never(client, clock, monkeypatch):
    _stub_pipeline(monkeypatch)
    monkeypatch.setattr(routes, "JOB_TTL_SECONDS", 0)
    job_id, _ = _submit_and_wait(client)
    clock["t"] += 10**7
    assert client.get(f"/analyze/{job_id}").status_code == 200


def test_the_default_ttl_is_thirty_minutes_and_comes_from_the_environment():
    from app import config

    source = open(config.__file__, encoding="utf-8").read()
    assert 'JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "1800"))' in source


# ---- where the body text may and may not go -------------------------------------------------------------------------------------

def test_the_body_text_is_in_the_live_response_but_never_logged(client, monkeypatch, capsys):
    from app.logging_config import configure_logging

    configure_logging("DEBUG")
    _stub_pipeline(monkeypatch)
    _, body = _submit_and_wait(client)
    assert MARKER in body["result"]["parsed_email"]["body_html"]  # D5: it stays in the live response
    captured = capsys.readouterr()
    assert MARKER not in captured.err and MARKER not in captured.out


def test_the_body_text_is_never_sent_to_a_provider_or_the_llm(client, monkeypatch):
    recorder, prompts = Recorder(), []
    _stub_pipeline(monkeypatch, recorder, prompts)
    _submit_and_wait(client)
    assert recorder.seen  # the providers were reached (the link host), so an empty list below would mean something
    assert MARKER not in repr(recorder.seen) and all(MARKER not in p for p in prompts)
    assert prompts, "the LLM stub was reached"


def test_the_body_text_is_never_persisted_or_exported_by_the_feedback_log(client, monkeypatch, tmp_path):
    db = tmp_path / "f.sqlite"
    monkeypatch.setattr(feedback, "FEEDBACK_DB", db)
    _stub_pipeline(monkeypatch)
    job_id, _ = _submit_and_wait(client)
    assert client.post(f"/analyze/{job_id}/feedback", json={"agree": False}).status_code == 200
    assert MARKER.encode() not in db.read_bytes()
    import io

    out = io.StringIO()
    feedback.export_csv(out, db)
    assert MARKER not in out.getvalue() and MARKER not in str(feedback.summary(db))


def test_nothing_in_the_new_blocks_carries_the_body_text(client, monkeypatch):
    _stub_pipeline(monkeypatch)
    _, body = _submit_and_wait(client)
    result = body["result"]
    for block in ("evidence", "coverage_report", "indicators"):
        assert MARKER not in str(result[block])
