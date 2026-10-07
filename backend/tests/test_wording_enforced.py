"""V1 is ENFORCED: the word-ban lint (scripts/check_wording.py) must find nothing, and a banned word planted in a label, a reason or a finding title must make it fail.

Failure messages print the path, the field kind and the banned word only: never a string produced from a message. The hold-out is never read (tests.eval.collect does not collect it,
and a test below pins that). The committed fixtures are always scanned; the local tuning corpus is scanned when it exists and the test SKIPS cleanly when it does not."""
import importlib.util
import io
import sys
from pathlib import Path

import pytest

from tests import eval as ev

ROOT = Path(__file__).resolve().parents[2]


def _load_lint():
    if "check_wording" in sys.modules:
        return sys.modules["check_wording"]
    spec = importlib.util.spec_from_file_location("check_wording", ROOT / "scripts" / "check_wording.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_wording"] = module
    spec.loader.exec_module(module)
    return module


cw = _load_lint()
TUNING = ev.FIXTURES / "_local_corpus" / "tuning"


def _where(hits):
    """What a failure may show: where, what kind of field, which word. Never the string."""
    return [(h.path, h.kind, h.word) for h in hits]


# ---- the gate ---------------------------------------------------------------------------------------------------------------------

def test_the_strict_static_scan_of_the_backend_and_the_frontend_finds_nothing(capsys):
    code = cw.main(["--static", "--no-tests", "--strict"])
    out = capsys.readouterr().out
    assert code == 0, out  # the report lists the application's own strings with their file and line


def test_the_runtime_scan_over_the_committed_fixtures_finds_nothing(tmp_path):
    """The pipeline over the fixtures, STRICT and CONFIGURED, clean and unknown enrichment (an empty folder replaces the local corpus)."""
    assert _where(cw.runtime_hits(cw.load_allowlist(), corpus_dir=tmp_path)) == []


@pytest.mark.slow
@pytest.mark.skipif(not (TUNING.is_dir() and any(TUNING.glob("*.eml"))), reason="the local tuning corpus is not present on this machine")
def test_the_runtime_scan_over_the_local_tuning_corpus_finds_nothing():
    assert _where(cw.runtime_hits(cw.load_allowlist(), only_sources=frozenset({"tuning_corpus"}))) == []


def test_the_scan_can_never_read_the_hold_out():
    paths = [p for p, _label, _source in ev.collect(None)]
    assert paths and not any("holdout" in part.lower() for p in paths for part in p.parts)


# ---- the V18 idea as a mutation test on a REAL analysis ---------------------------------------------------------------------------------

def _real_payload():
    ev.apply_mode("configured")
    for path in sorted((ev.FIXTURES / "benign" / "synthetic").glob("*.eml")):
        payload, _prompt = cw.analysis_payload(path, "clean")
        enrichment = [m for m in payload["module_results"] if m["module"] == "enrichment"]
        if payload["findings"] and payload["scoring"]["applied_overrides"] and payload["coverage_report"] and enrichment:
            return payload
    raise AssertionError("no fixture produced findings, an applied override, coverage items and an enrichment module")


def test_the_unmutated_real_analysis_is_clean():
    assert cw.scan_payload(_real_payload(), frozenset()) == []


@pytest.mark.parametrize("target, word, plant", [
    ("a label", "clean", lambda p: p["coverage_report"][0].__setitem__("area", p["coverage_report"][0]["area"] + " is clean")),
    ("a reason text", "safe", lambda p: p["scoring"]["applied_overrides"][0].__setitem__("reason", p["scoring"]["applied_overrides"][0]["reason"] + " It is safe.")),
    ("a finding title", "benign", lambda p: p["findings"][0].__setitem__("title", p["findings"][0]["title"] + " (benign)")),
    ("an indicator note", "legit", lambda p: p["indicators"]["indicators"][0].__setitem__("note", "A legit host.")),
])
def test_a_banned_word_planted_in_a_label_a_reason_a_finding_title_or_a_note_makes_the_lint_fail(target, word, plant):
    payload = _real_payload()
    plant(payload)
    hits = cw.scan_payload(payload, frozenset())
    assert [h.word for h in hits] == [word], target


def test_the_same_word_as_a_provider_field_name_inside_the_raw_data_block_passes_but_outside_it_fails():
    payload = _real_payload()
    enrichment = next(m for m in payload["module_results"] if m["module"] == "enrichment")
    enrichment["raw_data"]["mutation.example"] = {"virustotal": {"harmless": 3, "malicious": 0}}
    assert cw.scan_payload(payload, frozenset()) == []  # a provider's own field name, in the raw-data block
    payload["coverage_report"][0]["harmless"] = 3  # the same word as a field outside the block
    assert [(h.kind, h.word) for h in cw.scan_payload(payload, frozenset())] == [("field name", "harmless")]


# ---- the output never carries message content ------------------------------------------------------------------------------------------

MARKER = "SECRETMARKERQSEVEN"  # letters only: the lint's digit masking must not be what hides it
EML = (f"From: {MARKER} Safe Sender <a@sender.example.org>\r\nTo: t@example.com\r\nSubject: {MARKER} clean safe benign legit harmless\r\n"
       f"Message-ID: <1@sender.example.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
       f"{MARKER} please verify your account, this is safe and clean: https://safe.example.org/clean-offer\r\n")


def test_message_text_is_never_a_hit_and_never_printed(tmp_path):
    path = tmp_path / "m.eml"
    path.write_text(EML, encoding="utf-8")
    ev.apply_mode("configured")
    payload, prompt = cw.analysis_payload(path, "clean")
    assert cw.scan_payload(payload, frozenset()) == [] and cw.scan_prompt(prompt, frozenset()) == []  # the banned words in the message are the sender's, not ours


def test_a_runtime_hit_is_printed_as_the_applications_own_template_or_not_at_all_never_as_the_runtime_sentence(tmp_path):
    path = tmp_path / "m.eml"
    path.write_text(EML, encoding="utf-8")
    ev.apply_mode("configured")
    payload, _ = cw.analysis_payload(path, "clean")
    # plant a banned word in an application field, next to message text that is NOT quoted (so masking by quotes alone would leak it)
    payload["findings"][0]["description"] = f"Seen {MARKER} and the result is clean."
    hits = cw.scan_payload(payload, frozenset())
    assert hits and MARKER in hits[0].text  # the internal masked sentence still holds the unquoted marker ...
    for static in ([], [cw.Hit("static", "backend/app/x.py:1", "api text", "clean", "Seen the result and the result is clean.", "p", "rule")]):
        runtime = cw.runtime_to_hits(hits, static)
        out = io.StringIO()
        cw.print_report([], runtime, [], [], [], [], out=out)
        assert MARKER not in out.getvalue() and all(MARKER not in h.text and MARKER not in h.where for h in runtime)  # ... but the report never carries it
    shown = cw.runtime_to_hits(hits, [cw.Hit("static", "backend/app/x.py:1", "api text", "clean", "Seen the result and the result is clean.", "p", "rule")])
    assert shown[0].text == "Seen the result and the result is clean." and shown[0].also_static and "template at backend/app/x.py:1" in shown[0].where
    assert cw.runtime_to_hits(hits, [])[0].text == "" and not cw.runtime_to_hits(hits, [])[0].also_static


def test_the_json_output_of_the_report_has_no_runtime_sentence(tmp_path):
    hits = [cw.PayloadHit("findings[*].description", "api text", "clean", f"Seen {MARKER} and it is clean.")]
    import json
    from dataclasses import asdict

    assert MARKER not in json.dumps([asdict(h) for h in cw.runtime_to_hits(hits, [])])
