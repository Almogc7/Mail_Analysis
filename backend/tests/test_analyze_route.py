import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).parent / "fixtures" / "samples"

client = TestClient(app)


class StubProviderClient:
    def enrich(self, ioc_value: str, ioc_type: str) -> dict:
        return {"status": "ok"}


def _stub_enrichment_clients():
    # Import RiskScorer/ScoreConfig directly rather than via providers.get_clients() --
    # tests monkeypatch that function to *be* this one, so calling it here would recurse.
    from app.enrichment.providers.scoring import RiskScorer, ScoreConfig

    stub = StubProviderClient()
    return {
        "virustotal": stub,
        "urlscan": stub,
        "threatfox": stub,
        "malwarebazaar": stub,
        "risk_scorer": RiskScorer,
        "score_config": ScoreConfig.from_env(),
    }


def _poll_until_done(job_id: str, timeout: float = 5.0) -> dict:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        resp = client.get(f"/analyze/{job_id}")
        assert resp.status_code == 200
        body = resp.json()
        if body["status"] in ("done", "error"):
            return body
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def _upload(filename: str, content: bytes, monkeypatch=None):
    return client.post("/analyze", files={"file": (filename, content, "message/rfc822")})


def test_happy_path_completes_with_full_analysis_result(monkeypatch):
    monkeypatch.setattr("app.enrichment.providers.get_clients", _stub_enrichment_clients)
    monkeypatch.setattr(
        "app.llm.gemini_client.get_client",
        lambda: (lambda prompt: '{"narrative": "stubbed narrative", "flags": []}'),
    )

    raw = (FIXTURES / "spoofed_display_name.eml").read_bytes()
    resp = _upload("spoofed_display_name.eml", raw)
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    body = _poll_until_done(job_id)

    assert body["status"] == "done"
    result = body["result"]
    # a display-name brand claim alone is ONE family: inconclusive, with the claim finding visible
    assert result["verdict"] == "inconclusive"
    assert any(f["title"].startswith("Possible display-name spoofing") for f in result["findings"])
    assert len(result["findings"]) > 0
    assert result["scoring"] is not None
    assert result["llm_opinion"]["status"] == "ok"
    assert result["llm_opinion"]["narrative"] == "stubbed narrative"


def test_wrong_extension_rejected():
    resp = _upload("notes.txt", b"hello world")
    assert resp.status_code == 400


def test_empty_file_rejected():
    resp = _upload("empty.eml", b"")
    assert resp.status_code == 400


def test_oversized_file_rejected(monkeypatch):
    monkeypatch.setattr("app.api.routes.MAX_UPLOAD_SIZE_BYTES", 10)
    resp = _upload("big.eml", b"x" * 100)
    assert resp.status_code == 413


def test_unparseable_bytes_resolve_to_error_job(monkeypatch):
    # A real, non-stubbed get_clients() would pick up real keys from backend/.env and make this test hit
    # live services -- always stub both the providers and the LLM client, never rely on a test happening
    # to fail before reaching them.
    monkeypatch.setattr("app.enrichment.providers.get_clients", _stub_enrichment_clients)
    monkeypatch.setattr(
        "app.llm.gemini_client.get_client",
        lambda: (lambda prompt: '{"narrative": "n", "flags": []}'),
    )

    resp = _upload("garbage.eml", b"\x00\x01\x02not an email")
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    body = _poll_until_done(job_id)

    # email.message_from_bytes is lenient and rarely raises, but if it or anything else in
    # the pipeline does, the job must resolve to a clean error rather than hang or crash the
    # server -- this test documents that contract regardless of whether this exact input
    # happens to raise today.
    assert body["status"] in ("done", "error")


def test_enrichment_failure_does_not_sink_the_whole_job(monkeypatch):
    def raising_get_clients():
        raise RuntimeError("a provider client could not be constructed")

    monkeypatch.setattr("app.enrichment.providers.get_clients", raising_get_clients)
    monkeypatch.setattr(
        "app.llm.gemini_client.get_client",
        lambda: (lambda prompt: '{"narrative": "n", "flags": []}'),
    )

    raw = (FIXTURES / "clean_legit.eml").read_bytes()
    resp = _upload("clean_legit.eml", raw)
    job_id = resp.json()["job_id"]

    body = _poll_until_done(job_id)

    assert body["status"] == "done"
    result = body["result"]
    enrichment_result = next(m for m in result["module_results"] if m["module"] == "enrichment")
    assert enrichment_result["status"] == "error"
    auth_result = next(m for m in result["module_results"] if m["module"] == "auth_check")
    assert auth_result["status"] == "ok"
    assert result["scoring"] is not None
    assert result["llm_opinion"]["status"] == "ok"


def test_llm_unavailable_does_not_sink_the_whole_job(monkeypatch):
    monkeypatch.setattr("app.enrichment.providers.get_clients", _stub_enrichment_clients)

    def raising_get_client():
        raise RuntimeError("GOOGLE_API_KEY is not configured")

    monkeypatch.setattr("app.llm.gemini_client.get_client", raising_get_client)

    raw = (FIXTURES / "clean_legit.eml").read_bytes()
    resp = _upload("clean_legit.eml", raw)
    job_id = resp.json()["job_id"]

    body = _poll_until_done(job_id)

    assert body["status"] == "done"
    assert body["result"]["llm_opinion"]["status"] == "unavailable"
    assert body["result"]["verdict"] is not None


def test_unknown_job_id_returns_404():
    resp = client.get("/analyze/does-not-exist")
    assert resp.status_code == 404
