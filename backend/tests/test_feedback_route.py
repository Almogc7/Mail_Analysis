"""POST /analyze/{job_id}/feedback and GET /feedback/summary."""
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app import feedback
from app.main import app
from tests.eval import FIXTURES
from tests.test_analyze_route import _poll_until_done, _stub_enrichment_clients

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(feedback, "FEEDBACK_DB", tmp_path / "fb.sqlite")
    monkeypatch.setattr("app.enrichment.ioc_bridge.get_clients", _stub_enrichment_clients)
    # The Kvish fixture has 7 URLs; the real VT rate limiter (4/min) would really sleep between stub lookups.
    monkeypatch.setattr("app.enrichment.rate_limit.VTRateLimiter.wait_if_needed", lambda self: None)
    monkeypatch.setattr("app.llm.gemini_bridge.get_client", lambda: (lambda prompt: '{"narrative": "n", "flags": []}'))
    return tmp_path / "fb.sqlite"


def _analyzed_job(name="malicious/kvish6_invoice_phish.eml") -> str:
    raw = (FIXTURES / name).read_bytes()
    job = client.post("/analyze", files={"file": ("sample.eml", raw, "message/rfc822")}).json()["job_id"]
    assert _poll_until_done(job)["status"] == "done"
    return job


def test_feedback_is_recorded_for_a_finished_analysis(isolated):
    job = _analyzed_job()
    resp = client.post(f"/analyze/{job}/feedback", json={"agree": False, "note": "looks like a newsletter"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["agree"] is False and body["verdict"] == "suspicious" and len(body["raw_sha256"]) == 64
    with sqlite3.connect(isolated) as conn:
        assert conn.execute("SELECT agree, note FROM feedback").fetchall() == [(0, "looks like a newsletter")]


def test_unknown_job_is_404(isolated):
    assert client.post("/analyze/nope/feedback", json={"agree": True}).status_code == 404
    assert not isolated.exists()


def test_a_job_that_is_not_done_is_409(isolated, monkeypatch):
    from app.api import routes
    from app.api.routes import AnalysisJob

    routes._jobs["pending-job"] = AnalysisJob(job_id="pending-job", status="running")
    try:
        assert client.post("/analyze/pending-job/feedback", json={"agree": True}).status_code == 409
    finally:
        routes._jobs.pop("pending-job", None)
    assert not isolated.exists()


def test_a_note_over_the_cap_is_rejected_not_silently_truncated(isolated):
    job = _analyzed_job()
    resp = client.post(f"/analyze/{job}/feedback", json={"agree": True, "note": "x" * 501})
    assert resp.status_code == 422 and not isolated.exists()


def test_agree_is_required(isolated):
    job = _analyzed_job()
    assert client.post(f"/analyze/{job}/feedback", json={"note": "hm"}).status_code == 422


def test_feedback_can_be_changed_and_summarised(isolated):
    job = _analyzed_job()
    client.post(f"/analyze/{job}/feedback", json={"agree": False})
    client.post(f"/analyze/{job}/feedback", json={"agree": True})
    summary = client.get("/feedback/summary").json()
    assert summary["total"] == 1 and summary["agree"] == 1 and summary["disagree"] == 0
    assert "self-selected" in summary["caveat"]


def test_the_response_and_the_stored_row_contain_no_email_content(isolated):
    job = _analyzed_job()
    text = client.post(f"/analyze/{job}/feedback", json={"agree": True}).text
    for marker in ("sweb", "kvish6", "sendgrid", "printernet", "vnz73mailr"):
        assert marker not in text and marker.encode() not in isolated.read_bytes()
