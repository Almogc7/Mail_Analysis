"""Attachment.first_bytes (contracts/email.py): at most 16 bytes taken in parser/normalize.py::_hash_attachment, metadata for blocker detection, and NEVER output.

The marker test uses distinctive bytes and proves they appear nowhere a user, a log, the feedback log or the language model could see them."""
import base64
import json
import logging
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import feedback
from app.contracts.email import Attachment
from app.llm.prompting import build_prompt
from app.main import app
from app.parser import parse_email_file
from tests import eval as ev

MARKER = b"ZQXMARKER1ZQXMAR"  # exactly 16 distinctive bytes
assert len(MARKER) == 16


def _eml(payload: bytes, filename="note.dat") -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = "first bytes test"
    msg.set_content("see attached")
    msg.add_attachment(payload, maintype="application", subtype="octet-stream", filename=filename)
    return bytes(msg)


def _forms(marker: bytes) -> list[str]:
    """Every way the marker could be written out: text, hex, base64 (padded and not), and its repr."""
    return [marker.decode("latin-1"), marker.hex(), marker.hex().upper(), base64.b64encode(marker).decode(), base64.b64encode(marker).decode().rstrip("="), repr(marker)]


def _assert_absent(text: str, where: str):
    for form in _forms(MARKER):
        assert form not in text, f"the first bytes leaked into {where} as {form!r}"


# ---- what the field is ------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_first_bytes_are_the_first_16_bytes_of_the_payload_and_never_more():
    parsed = parse_email_file(_eml(MARKER + b"x" * 5000), "m.eml")
    assert parsed.attachments[0].first_bytes == MARKER and len(parsed.attachments[0].first_bytes) == 16


def test_a_short_attachment_keeps_all_its_bytes_and_an_empty_one_keeps_none():
    assert parse_email_file(_eml(b"abc"), "m.eml").attachments[0].first_bytes == b"abc"
    assert parse_email_file(_eml(b""), "m.eml").attachments[0].first_bytes == b""


def test_the_field_is_additive_an_attachment_built_without_it_still_works():
    attachment = Attachment(filename="a", content_type="x/y", size_bytes=1, sha256="0" * 64, sha1="0" * 40, md5="0" * 32)
    assert attachment.first_bytes == b"" and "first_bytes" not in attachment.model_dump()


def test_the_other_attachment_fields_are_unchanged_by_the_addition():
    parsed = parse_email_file(_eml(MARKER + b"y" * 10), "m.eml")
    assert set(parsed.attachments[0].model_dump()) == {"filename", "content_type", "size_bytes", "sha256", "sha1", "md5", "is_inline"}


# ---- never output ------------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_the_marker_is_absent_from_every_serialisation_of_the_parsed_email_and_the_analysis(caplog):
    caplog.set_level(logging.DEBUG)
    parsed = parse_email_file(_eml(MARKER + b"z" * 100), "m.eml")
    assert parsed.attachments[0].first_bytes == MARKER  # it is there in memory ...
    for where, text in (("model_dump", json.dumps(parsed.model_dump(), default=str)), ("model_dump_json", parsed.model_dump_json()), ("repr", repr(parsed)), ("str", str(parsed)),
                        ("attachment repr", repr(parsed.attachments[0])), ("attachment json", parsed.attachments[0].model_dump_json())):
        _assert_absent(text, where)  # ... and nowhere in what is written out
    result = ev.analyze_parsed(parsed, "clean")
    ev.apply_mode("configured")
    _assert_absent(result.model_dump_json(), "the analysis result JSON")
    _assert_absent(json.dumps(result.model_dump(), default=str), "the analysis result dict")
    _assert_absent(build_prompt(result), "the LLM prompt")
    _assert_absent(caplog.text, "the logs")


def test_the_marker_is_absent_from_the_feedback_log(tmp_path):
    parsed = parse_email_file(_eml(MARKER + b"z" * 100), "m.eml")
    result = ev.analyze_parsed(parsed, "clean")
    ev.apply_mode("configured")
    db = tmp_path / "feedback.db"
    feedback.record_feedback(result, agree=True, note="a note", db_path=db)
    text = " ".join(str(cell) for row in sqlite3.connect(db).execute("select * from feedback") for cell in row)
    _assert_absent(text, "the feedback record")
    _assert_absent(db.read_bytes().decode("latin-1"), "the feedback database file")


def test_the_marker_is_absent_from_the_api_response_the_job_store_and_the_logs(monkeypatch, caplog):
    from app.enrichment.providers.scoring import RiskScorer, ScoreConfig

    class Stub:
        def enrich(self, ioc_value, ioc_type):
            return {"status": "ok"}

    monkeypatch.setattr("app.enrichment.providers.get_clients", lambda: {"virustotal": Stub(), "urlscan": Stub(), "threatfox": Stub(), "malwarebazaar": Stub(),
                                                                         "risk_scorer": RiskScorer, "score_config": ScoreConfig.from_env()})
    monkeypatch.setattr("app.llm.gemini_client.get_client", lambda: (lambda prompt: '{"narrative": "stub", "flags": []}'))
    caplog.set_level(logging.DEBUG)
    client = TestClient(app)
    posted = client.post("/analyze", files={"file": ("m.eml", _eml(MARKER + b"z" * 100), "message/rfc822")})
    assert posted.status_code == 202
    job_id = posted.json()["job_id"]
    started = time.monotonic()
    body = {}
    while time.monotonic() - started < 10:
        body = client.get(f"/analyze/{job_id}").json()
        if body["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert body["status"] == "done"
    assert body["result"]["parsed_email"]["attachments"][0]["sha256"]  # the hash is still there
    assert "first_bytes" not in body["result"]["parsed_email"]["attachments"][0]
    _assert_absent(json.dumps(body), "the API response")
    _assert_absent(client.get(f"/analyze/{job_id}").text, "the job store response")
    _assert_absent(caplog.text, "the logs of the whole request")


def test_the_openapi_schema_does_not_advertise_the_field():
    schema = json.dumps(TestClient(app).get("/openapi.json").json())
    assert "first_bytes" not in schema


def test_the_marker_is_not_in_the_parsed_body_or_subject():
    parsed = parse_email_file(_eml(MARKER + b"q" * 50), "m.eml")
    assert all(MARKER.decode() not in (value or "") for value in (parsed.body_text, parsed.body_html, parsed.subject))
