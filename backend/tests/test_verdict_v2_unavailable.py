"""Fail-safe visibility: if verdict_v2 cannot be built, the result SAYS so (verdict_v2_status = unavailable and a coverage item with the reason code verdict_v2_unavailable) instead of silently showing only v1.

The v1 fields stay exactly as they are, only the exception's class is logged, and the new strings are content-free and V1-clean."""
import json
import logging
import re
from pathlib import Path

import pytest

from app.contracts.analysis import AnalysisResult
from app.coverage import HOW_TO_CLEAR
from tests import eval as ev
from tests import pipeline_identity as pi

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ev.FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
BANNED = re.compile(r"\b(safe|clean|legit|benign|harmless)\b", re.IGNORECASE)
V1_SECTIONS = ("verdict", "score", "confidence", "scoring", "findings", "module_results", "llm_opinion", "indicators", "parsed_email", "evidence")


def _v1(result):
    dump = result.model_dump(mode="json")
    return {section: dump[section] for section in V1_SECTIONS}


def _run(monkeypatch=None, *, break_tier=False, break_coverage=False):
    if break_tier:
        def boom(inputs):
            raise RuntimeError("a secret message-derived detail that must not be logged")

        monkeypatch.setattr("app.api.pipeline.compute_tier", boom)
    if break_coverage:
        def boom_coverage(*args, **kwargs):
            raise ValueError("another secret detail")

        monkeypatch.setattr("app.api.pipeline.build_coverage_report", boom_coverage)
    return pi.run(FIXTURE, "configured")


def _unavailable_items(result):
    return [i for i in (result.coverage_report or []) if i.reason == "verdict_v2_unavailable"]


# ---- the normal case ------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_a_normal_result_says_ok_and_has_no_unavailable_item():
    result = _run()
    assert result.verdict_v2_status == "ok" and result.verdict_v2 is not None and result.checks_completed is not None
    assert _unavailable_items(result) == []


@pytest.mark.slow
def test_every_fixture_in_both_modes_says_ok():
    statuses = {pi.run(path, mode).verdict_v2_status for mode in ev.MODES for path, _label, _source in ev.collect(None)}
    assert statuses == {"ok"}


# ---- an injected failure --------------------------------------------------------------------------------------------------------------------------------------------------------

def test_a_failure_while_building_verdict_v2_is_visible_and_leaves_the_v1_fields_unchanged(monkeypatch, caplog):
    normal = _run()
    caplog.set_level(logging.DEBUG, logger="app")
    broken = _run(monkeypatch, break_tier=True)
    assert broken.verdict_v2 is None and broken.checks_completed is None
    assert broken.verdict_v2_status == "unavailable"
    (item,) = _unavailable_items(broken)
    assert (item.area, item.status, item.by_design, item.blocks_no_indicators, item.subject, item.detail) == ("Verdict v2", "not_checked", False, False, None, "")
    assert item.how_to_clear == HOW_TO_CLEAR["verdict_v2_unavailable"]
    assert _v1(broken) == _v1(normal), "a failure of verdict v2 must not touch any v1 field"
    # the coverage report is the normal one plus exactly that item
    assert [c.model_dump() for c in broken.coverage_report if c.reason != "verdict_v2_unavailable"] == [c.model_dump() for c in normal.coverage_report]
    assert broken.schema_version == 2


def test_only_the_exception_class_is_logged_never_its_text(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="app")
    _run(monkeypatch, break_tier=True)
    assert "verdict v2 could not be built (RuntimeError)" in caplog.text
    assert "secret" not in caplog.text.lower()


def test_a_missing_coverage_report_is_visible_too_and_the_v1_fields_are_unchanged(monkeypatch, caplog):
    normal = _run()
    caplog.set_level(logging.DEBUG, logger="app")
    broken = _run(monkeypatch, break_coverage=True)
    assert broken.verdict_v2 is None and broken.verdict_v2_status == "unavailable"
    assert [(i.area, i.reason) for i in broken.coverage_report] == [("Verdict v2", "verdict_v2_unavailable")]  # the report that could not be built is replaced by the one item that says so
    assert _v1(broken) == _v1(normal)
    assert "another secret" not in caplog.text and "(ValueError)" in caplog.text
    assert "verdict v2 is unavailable (no coverage report)" in caplog.text


# ---- the contract and the wording -------------------------------------------------------------------------------------------------------------------------------------------

def test_the_status_field_is_optional_additive_and_closed():
    from app.contracts.email import EmailAddress, ParsedEmail

    old = AnalysisResult(parsed_email=ParsedEmail(source_format="eml", from_=EmailAddress(), raw_size_bytes=1))
    assert old.verdict_v2_status is None  # a result made before the field existed still parses
    with pytest.raises(Exception):
        AnalysisResult(parsed_email=old.parsed_email, verdict_v2_status="broken")
    types = (ROOT / "frontend" / "src" / "types.ts").read_text(encoding="utf-8")
    assert "verdict_v2_status?: 'ok' | 'unavailable' | null" in types


def test_the_unavailable_wording_is_content_free_and_passes_the_v1_word_ban():
    text = HOW_TO_CLEAR["verdict_v2_unavailable"]
    assert text.strip() and BANNED.search(text) is None
    assert not re.search(r"<[^>]+>|https?://|@", text)
    assert "verdict_v2_unavailable" not in json.dumps([c.model_dump() for c in _run().coverage_report if c.reason != "verdict_v2_unavailable"])
