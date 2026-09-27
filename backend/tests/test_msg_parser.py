from pathlib import Path

import pytest

from app.api.pipeline import run_pipeline
from app.parser.msg_parser import parse_msg
from app.parser.normalize import to_parsed_email

FIXTURES = Path(__file__).parent / "fixtures" / "samples"
SAMPLE_MSG = FIXTURES / "sample.msg"

pytestmark = pytest.mark.skipif(
    not SAMPLE_MSG.exists(),
    reason=(
        "No .msg fixture present. .msg files can't be easily synthesized in pure Python "
        "(OLE compound-file format) -- drop a real, sanitized sample at "
        "backend/tests/fixtures/samples/sample.msg (strip real PII/body content first) "
        "to exercise this test."
    ),
)


def _parse():
    raw_bytes = SAMPLE_MSG.read_bytes()
    return to_parsed_email(parse_msg(raw_bytes))


def test_msg_header_and_address_fields_extracted_correctly():
    parsed = _parse()

    assert parsed.source_format == "msg"
    assert parsed.subject == "Testing MSG"
    assert parsed.from_.address == "test.sender@example.org"
    assert parsed.from_.domain == "example.org"
    assert parsed.to[0].address == "test.recipient@example.com"
    # Return-Path extraction was a genuine .msg-specific gap (msg_parser.py hardcoded
    # return_path=None) found and fixed while closing out this fixture gap -- the raw
    # header is present and parseable, so it must come through like it does for .eml.
    assert parsed.return_path is not None
    assert parsed.return_path.address == "test.sender@example.org"


def test_msg_authentication_results_header_captured_raw():
    parsed = _parse()

    assert len(parsed.authentication_results_raw) == 1
    assert "dmarc=fail" in parsed.authentication_results_raw[0]


def test_msg_html_body_decoded_as_text_not_left_as_bytes():
    # Genuine .msg-specific bug found and fixed: extract_msg's htmlBody property is
    # always `bytes` (confirmed via its own source), never `str` -- the original
    # `isinstance(..., str)` check silently discarded it every time, on every .msg file.
    parsed = _parse()

    assert parsed.body_html is not None
    assert isinstance(parsed.body_html, str)
    assert "CAUTION" in parsed.body_html


def test_msg_no_attachments_or_urls_in_this_sample():
    # This particular real sample happens to carry no links or attachments -- documents
    # that fact rather than silently assuming it, since it's a real limit on what this
    # fixture alone can prove about the (format-agnostic, already .eml-tested) URL/
    # attachment-hashing paths in normalize.py.
    parsed = _parse()

    assert parsed.urls == []
    assert parsed.attachments == []


def test_msg_full_pipeline_produces_expected_verdict_and_findings(monkeypatch):
    """Same rigor as the .eml fixtures: confirms this sample produces a specific,
    expected verdict/finding set through the real /analyze pipeline, not just "doesn't
    crash". This is a genuine (if unintentional) SPF softfail + DMARC fail per the raw
    Microsoft-generated header -- auth_check correctly flags it regardless of whether the
    sample's original intent was benign.

    Stubs the LLM bridge explicitly: whether GOOGLE_API_KEY is "configured" depends on
    whether an earlier test in the same pytest session already imported the real
    IOC_Enricher module (its own load_dotenv() populates os.environ process-wide for the
    rest of the run) -- without stubbing, this test silently made a real Gemini call and
    took 13s+ when run as part of the full suite, the same class of bug fixed once already
    in test_analyze_route.py. Never rely on session ordering to avoid live calls."""
    monkeypatch.setattr(
        "app.llm.gemini_bridge.get_client",
        lambda: (lambda prompt: '{"narrative": "n", "flags": []}'),
    )

    raw_bytes = SAMPLE_MSG.read_bytes()
    result = run_pipeline(raw_bytes, "sample.msg")

    assert result.verdict == "suspicious"

    auth_result = next(m for m in result.module_results if m.module == "auth_check")
    assert auth_result.status == "ok"
    titles = {f.title for f in auth_result.findings}
    assert "DMARC check failed" in titles

    assert any(o.rule == "auth_check_floor" for o in result.scoring.applied_overrides)
