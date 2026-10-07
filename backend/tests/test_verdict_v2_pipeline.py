"""Verdict v2 through the REAL pipeline (api/pipeline.py): additive, equal to the pre-registered predictions, correct on synthetic evidence, and content-free.

(a) every v1 field is byte-identical to a snapshot taken before the pipeline computed verdict_v2; (b) all 856 baseline rows give the predicted tier and route; (c) the three worked 'Checks completed'
examples; (d) synthetic messages through the real provider clients over a recording fake HTTP session; (e) the invariants on the live output; (f) a marker test; (g) the V1 wording lint."""
import base64
import hashlib
import json
import logging
import re
import sqlite3
import subprocess
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

from app import feedback
from app.enrichment import run_enrichment
from app.enrichment.rate_limit import VTRateLimiter
from app.llm.prompting import build_prompt
from app.parser import parse_email_file
from app.verdict_v2_text import TIER_KEYS
from tests import eval as ev
from tests import fake_providers as fake
from tests import pipeline_identity as pi
from tests import regression_baseline as rb

ROOT = Path(__file__).resolve().parents[2]
PREDICTED = ROOT / "backend" / "tests" / "fixtures" / "predicted_tiers.json"
BANNED = re.compile(r"\b(safe|clean|legit|benign|harmless)\b", re.IGNORECASE)
TEXT = ("Hello, this is a plain message with enough ordinary English words in it so that the language of the text can be read without any doubt "
        "by the simple heuristics of the tool. ") * 2


def _ip(*parts) -> str:
    return ".".join(str(p) for p in parts)


# ---- (a) the v1 fields are byte-identical ------------------------------------------------------------------------------------------------------------------------------------------

def test_every_existing_section_of_the_real_pipeline_output_is_byte_identical_to_the_snapshot_taken_before_verdict_v2():
    recorded = json.loads(pi.SNAPSHOT.read_text(encoding="utf-8"))["messages"]
    current = pi.compute()
    assert len(current) == len(recorded) and set(current) == set(recorded)
    changed = sorted((key, section) for key, digests in current.items() for section, value in digests.items() if recorded[key][section] != value)
    assert changed == [], "an existing section changed: the v1 verdict, score, confidence, scoring, findings, module results, language-model opinion, indicators, parsed email, evidence or coverage"
    assert set(pi.SECTIONS) >= {"verdict", "score", "confidence", "scoring", "findings", "module_results", "llm_opinion", "indicators", "parsed_email", "evidence"}


def test_the_only_new_fields_of_the_result_are_verdict_v2_checks_completed_and_the_status():
    result = pi.run(ev.FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "configured")
    dump = result.model_dump(mode="json")
    assert dump["verdict_v2"] is not None and dump["checks_completed"] is not None
    assert set(dump) - set(pi.SECTIONS) == {"verdict_v2", "checks_completed", "verdict_v2_status"} and dump["verdict_v2_status"] == "ok"


# ---- (b) the 856 rows through the real pipeline ---------------------------------------------------------------------------------------------------------------------------------

def _script(name):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_as_is_clean_rows_give_the_predicted_tier_and_route_through_the_real_pipeline():
    outcome = _script("check_pipeline_tiers").check(rb.FAST_VARIANTS)
    ev.apply_mode("configured")
    assert outcome["rows"] == 214 and outcome["missing"] == 0
    assert outcome["differing"] == []


@pytest.mark.slow
def test_all_856_rows_give_the_predicted_tier_and_route_through_the_real_pipeline():
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_pipeline_tiers.py")], capture_output=True, text=True, cwd=ROOT, timeout=900)
    assert done.returncode == 0, done.stdout[-3000:]
    assert "checked 856 rows through the real pipeline; verdict_v2 missing: 0; tier or route differs from predicted_tiers.json: 0" in done.stdout


# ---- (c) the three worked examples ------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("fixture, expected", [
    ("malicious/kvish6_invoice_phish.eml", (7, 10, 3, 3)),
    ("benign/synthetic/06_hebrew_newsletter_esp.eml", (9, 9, 0, 2)),
    ("benign/synthetic/02_safelinks_wrapped_internal.eml", (1, 7, 6, 2)),
])
def test_the_worked_checks_completed_examples_come_out_as_pre_registered(fixture, expected):
    result = pi.run(ev.FIXTURES / fixture, "configured")
    c = result.checks_completed
    assert (c.completed, c.total, c.not_checked, c.by_design) == expected
    assert c.completed + c.not_checked == c.total


def test_the_hebrew_newsletter_is_no_indicators_found_with_its_positive_evidence_and_no_blocker():
    v2 = pi.run(ev.FIXTURES / "benign/synthetic/06_hebrew_newsletter_esp.eml", "configured").verdict_v2
    assert (v2.tier, v2.label, v2.route, v2.blockers) == ("no_indicators_found", "No indicators found", "T4_POSITIVE_EVIDENCE", [])
    assert [r.kind for r in v2.reasons] == ["positive_evidence", "positive_evidence"]


# ---- (d) synthetic end-to-end cases over a recording fake HTTP session ---------------------------------------------------------------------------------------------------------------

def _message(*, link=None, image=None, subject="end to end", sender="sender@sender.example.com", attachment=None, received=None) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = subject
    if received:
        msg["Received"] = received
    html = "<p>hello</p>" + (f'<a href="{link}">open it</a>' if link else "") + (f'<img src="{image}">' if image else "")
    msg.set_content(TEXT + (f" {link}" if link else ""))
    msg.add_alternative(html, subtype="html")
    if attachment is not None:
        msg.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="doc.bin")
    return bytes(msg)


def _run_case(monkeypatch, raw, answers, *, optin=(), known=(), own=()):
    import app.config as app_config

    monkeypatch.setattr(app_config, "ENRICHMENT_PATH_QUERY_PROVIDERS", list(optin))
    session = fake.install(monkeypatch, answers)
    result = pi.run_raw(raw, "m.eml", "configured", clients=fake.clients(), known_senders=set(known), own_domains=set(own))
    through_pipeline = sorted(session.requests)
    # the same message through the enrichment module alone (the only thing that makes requests): the pipeline asks for exactly the same things
    session_alone = fake.install(monkeypatch, answers)
    run_enrichment(parse_email_file(raw, "m.eml"), clients=fake.clients(), vt_limiter=VTRateLimiter(sleep_fn=lambda seconds: None))
    assert through_pipeline == sorted(session_alone.requests), "the set of outgoing requests must be the same as without verdict v2"
    assert not [r for r in through_pipeline if r[0] == "unexpected"], "a request went somewhere other than the four providers"
    return result, through_pipeline


HASH_PAYLOAD = b"ZQX-attachment-bytes-for-the-fake-lookup"
HASH = hashlib.sha256(HASH_PAYLOAD).hexdigest()
IP = _ip(203, 0, 113, 7)
HOP_IP = _ip(198, 51, 100, 9)

# id, message kwargs, answers, options, (tier key, route, hard-evidence rules, has evidence_conflict), names that must NEVER be asked about
CASES = [
    ("threatfox_80_on_a_link_host", dict(link="https://flagged-one.example.com/a"), dict(tf={"flagged-one.example.com": 80}), {}, ("confirmed_malicious", "HARD_EVIDENCE", ["H2"], False), []),
    ("threatfox_74_on_a_link_host", dict(link="https://flagged-one.example.com/a"), dict(tf={"flagged-one.example.com": 74}), {}, None, []),
    ("virustotal_12_on_a_link_url_with_the_opt_in", dict(link="https://flagged-url.example.com/payload?x=1"), dict(vt={"https://flagged-url.example.com/payload?x=1": 12}), dict(optin=["virustotal"]),
     ("confirmed_malicious", "HARD_EVIDENCE", ["H3"], False), []),
    ("virustotal_12_on_a_non_shared_domain", dict(link="https://flagged-two.example.com/a"), dict(vt={"flagged-two.example.com": 12}), {}, ("confirmed_malicious", "HARD_EVIDENCE", ["H3"], False), []),
    ("virustotal_on_a_shared_platform_domain", dict(link="https://docs.google.com/document/d/abc"), dict(vt={"docs.google.com": 40}), {}, None, ["docs.google.com"]),
    ("malwarebazaar_matched_attachment_hash", dict(attachment=HASH_PAYLOAD), dict(mb={HASH}), {}, ("confirmed_malicious", "HARD_EVIDENCE", ["H1"], False), []),
    ("flagged_host_on_the_known_sender_list", dict(link="https://mail.example.org/a"), dict(vt={"mail.example.org": 30}), dict(known=["example.org"]), ("suspicious", "R6", [], True), []),
    ("flagged_host_on_the_own_domain_list", dict(link="https://portal.example.net/a"), dict(tf={"portal.example.net": 90}), dict(own=["example.net"]), ("suspicious", "R6", [], True), []),
    ("flagged_ip_alone", dict(link=f"http://{IP}/x"), dict(vt={IP: 30}), {}, None, []),
    ("flagged_received_hop_ip", dict(link="https://clean-link.example.com/a", received=f"from mx.example.org (mx.example.org [{HOP_IP}]) by mail.example.net with ESMTP; Mon, 01 Jan 2024 00:00:00 +0000"),
     dict(vt={HOP_IP: 40}, tf={HOP_IP: 90}), {}, None, [HOP_IP]),
    ("flagged_sender_domain", dict(link="https://link-host.example.com/a", sender="user@sender-flagged.example.com"), dict(vt={"sender-flagged.example.com": 40}, tf={"sender-flagged.example.com": 90}), {}, None,
     ["sender-flagged.example.com"]),
    ("flagged_image_host", dict(link="https://link-host.example.com/a", image="https://img-flagged.example.com/p.png"), dict(vt={"img-flagged.example.com": 40}, tf={"img-flagged.example.com": 90}), {}, None,
     ["img-flagged.example.com"]),
]
RESULTS: dict[str, tuple] = {}


@pytest.mark.parametrize("case_id, message, answers, options, expected, never", CASES, ids=[c[0] for c in CASES])
def test_synthetic_evidence_through_the_real_pipeline_and_the_real_provider_clients(monkeypatch, case_id, message, answers, options, expected, never):
    result, requests = _run_case(monkeypatch, _message(**message), fake.Answers(**{k: (set(v) if k == "mb" else dict(v)) for k, v in answers.items()}), **options)
    v2 = result.verdict_v2
    rules = sorted(h.code for h in v2.hard_evidence)
    conflict = any(r.code == "evidence_conflict" for r in v2.reasons)
    RESULTS[case_id] = (v2.tier, v2.route, rules, conflict)
    if expected is None:
        assert v2.tier != "confirmed_malicious" and v2.hard_evidence == [], case_id  # never T1
    else:
        assert (v2.tier, v2.route, rules, conflict) == expected, case_id
    for name in never:
        assert not [r for r in requests if name in r[2]], f"{name} must never be looked up"
    if expected and expected[0] == "confirmed_malicious":
        assert v2.label == "Confirmed malicious" and all(h.indicator and h.source for h in v2.hard_evidence)


def test_the_hard_evidence_indicators_are_the_defanged_hosts_urls_and_the_hash(monkeypatch):
    for message, answers, options, expected in (
        (dict(link="https://flagged-one.example.com/a"), dict(tf={"flagged-one.example.com": 80}), {}, "flagged-one[.]example[.]com"),
        (dict(link="https://flagged-url.example.com/payload?x=1"), dict(vt={"https://flagged-url.example.com/payload?x=1": 12}), dict(optin=["virustotal"]), "hxxps://flagged-url[.]example[.]com/payload?x=1"),
        (dict(attachment=HASH_PAYLOAD), dict(mb={HASH}), {}, HASH),
    ):
        result, _requests = _run_case(monkeypatch, _message(**message), fake.Answers(**{k: (set(v) if k == "mb" else dict(v)) for k, v in answers.items()}), **options)
        assert [h.indicator for h in result.verdict_v2.hard_evidence] == [expected]


def test_a_flagged_shared_platform_domain_is_never_looked_up_so_it_cannot_be_hard_evidence(monkeypatch):
    """Shared-platform hosts are settled before any lookup, with or without the path opt-in: so rule 4 (an exact URL match on a shared platform with the opt-in on) cannot arise in the pipeline today."""
    result, requests = _run_case(monkeypatch, _message(link="https://docs.google.com/document/d/abc?x=1"), fake.Answers(vt={"https://docs.google.com/document/d/abc?x=1": 40, "docs.google.com": 40}),
                                 optin=["virustotal"])
    assert not [r for r in requests if "docs.google.com" in r[2]]
    assert result.verdict_v2.tier != "confirmed_malicious" and "shared_platform" in {b.code for b in result.verdict_v2.blockers}


def test_print_the_synthetic_cases_expected_and_actual_for_the_report():
    assert set(RESULTS) == {c[0] for c in CASES}  # filled by the parametrized test above
    for case_id, _message, _answers, _options, expected, _never in CASES:
        print(f"CASE {case_id} | expected {expected if expected else 'not confirmed_malicious, no hard evidence'} | actual {RESULTS[case_id]}")


# ---- (e) invariants on the live output across the fixtures and the tuning corpus -----------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def live_results():
    out = []
    for mode in ev.MODES:
        for path, _label, _source in ev.collect(None):
            out.append((mode, pi.run(path, mode)))
    return out


def test_v2_t4_never_comes_with_a_blocker(live_results):
    assert [m for m, r in live_results if r.verdict_v2.tier == "no_indicators_found" and r.verdict_v2.blockers] == []


def test_v3_and_v15_confirmed_malicious_only_with_hard_evidence_each_with_an_indicator_and_a_source(live_results):
    for _mode, r in live_results:
        v2 = r.verdict_v2
        assert (v2.tier == "confirmed_malicious") == bool(v2.hard_evidence)
        assert all(h.indicator and h.source and h.code in ("H1", "H2", "H3") for h in v2.hard_evidence)


def test_v14_every_tier_has_a_non_empty_reasons_list_or_hard_evidence_and_every_reason_has_text(live_results):
    tiers = set()
    for _mode, r in live_results:
        v2 = r.verdict_v2
        tiers.add(v2.tier)
        assert v2.reasons or v2.hard_evidence, v2.tier
        assert all(reason.text.strip() and reason.code for reason in v2.reasons)
        if v2.tier == "needs_analyst":
            assert any(reason.kind == "gap" for reason in v2.reasons) and v2.needs_analyst_reason in ("signals_present", "no_signals_insufficient_evidence")
    assert {"suspicious", "needs_analyst", "no_indicators_found"} <= tiers


def test_the_label_matches_the_tier_and_the_priority_is_set_only_for_needs_analyst(live_results):
    labels = {"confirmed_malicious": "Confirmed malicious", "suspicious": "Suspicious", "needs_analyst": "Needs analyst", "no_indicators_found": "No indicators found"}
    for _mode, r in live_results:
        v2 = r.verdict_v2
        assert v2.label == labels[v2.tier]
        assert (v2.priority is not None) == (v2.tier == "needs_analyst")
        assert r.scoring.priority is not None  # the v1 priority stays in the response for every tier


def test_v16_a_parser_failure_never_gives_no_indicators_found(live_results, monkeypatch):
    assert [m for m, r in live_results if any(b.code == "parse_failure" for b in r.verdict_v2.blockers) and r.verdict_v2.tier == "no_indicators_found"] == []
    lines = ["From: a@example.com", "To: b@example.com", "Subject: s", "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="XX"', "", "--XX", "Content-Type: text/plain", "", TEXT]
    result = pi.run_raw(("\r\n".join(lines) + "\r\n").encode("ascii"), "m.eml", "configured")
    assert any(b.code == "parse_failure" and b.detail == "mime_structure_error" for b in result.verdict_v2.blockers)
    assert result.verdict_v2.tier != "no_indicators_found"


def test_print_the_tier_counts_by_mode_for_the_report(live_results):
    import collections

    counts = {mode: collections.Counter(r.verdict_v2.tier for m, r in live_results if m == mode) for mode in ev.MODES}
    print("\ntier counts over the fixtures and the tuning corpus:", {m: dict(sorted(c.items())) for m, c in counts.items()})
    assert all(sum(c.values()) == len(ev.collect(None)) for c in counts.values())


# ---- (f) nothing from the message leaks into verdict_v2, the checks count, logs, the feedback log or the prompt ---------------------------------------------------------------------

def test_distinctive_message_strings_appear_nowhere_in_verdict_v2_checks_logs_feedback_or_the_prompt(monkeypatch, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    markers = {"subject": "ZQXSUBJECTMARK", "body": "ZQXBODYMARK", "brand": "ZQXBRANDMARK", "address": "zqxaddrmark", "content_type": "zqxctypemark", "unlisted_content_type": "zqxunlistedctype"}
    host = "zqxhostmark.example.com"
    msg = EmailMessage()
    msg["From"] = f"{markers['brand']} Support <{markers['address']}@example.com>"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = markers["subject"]
    msg.set_content(f"{TEXT} {markers['body']} https://{host}/a")
    msg.add_alternative(f'<p>{markers["body"]}</p><a href="https://{host}/a">open</a>', subtype="html")
    msg.add_attachment(b"ZQXPAYLOAD-first-bytes", maintype="application", subtype=markers["content_type"], filename="doc.bin")
    # a part with NO filename: it is not an attachment but an unlisted part, and its content type is attacker-written text that the parser keeps as metadata
    msg.add_attachment(b"ZQXUNLISTED-first-bytes", maintype="application", subtype=markers["unlisted_content_type"])
    answers = fake.Answers(tf={host: 90})
    fake.install(monkeypatch, answers)
    result = pi.run_raw(bytes(msg), "m.eml", "configured", clients=fake.clients(), known_senders=set(), own_domains=set())
    v2 = result.verdict_v2
    assert v2.tier == "confirmed_malicious" and [h.indicator for h in v2.hard_evidence] == ["zqxhostmark[.]example[.]com"]
    # the test is meaningful: the parser did keep the attacker-written content types as metadata, and the unlisted part really blocks (with fixed wording only)
    assert [p.content_type for p in result.parsed_email.unlisted_parts] == ["application/" + markers["unlisted_content_type"]]
    assert {(b.code, b.detail) for b in v2.blockers} >= {("static_analysis_off", "unknown_type")}

    surfaces = {"verdict_v2": v2.model_dump_json(), "checks_completed": result.checks_completed.model_dump_json()}
    for where, text in surfaces.items():
        for kind, marker in markers.items():
            assert marker.lower() not in text.lower(), f"the {kind} marker leaked into {where}"
    stripped = surfaces["verdict_v2"].replace("zqxhostmark[.]example[.]com", "")
    assert host not in stripped and "zqxhostmark" not in stripped.lower(), "the host appears in verdict_v2 only as the defanged hard-evidence indicator"
    assert BANNED.search(surfaces["verdict_v2"]) is None

    other_logs = " ".join(r.getMessage() for r in caplog.records if r.name != "app.enrichment.providers.base")  # the provider client's own request log names what it asked about (existing behaviour)
    db = tmp_path / "feedback.db"
    feedback.record_feedback(result, agree=True, note="n", db_path=db)
    feedback_text = " ".join(str(cell) for row in sqlite3.connect(db).execute("select * from feedback") for cell in row) + db.read_bytes().decode("latin-1")
    for kind, marker in markers.items():
        assert marker.lower() not in other_logs.lower(), f"the {kind} marker leaked into the logs"
        assert marker.lower() not in feedback_text.lower(), f"the {kind} marker leaked into the feedback log"
    assert host not in other_logs and host not in feedback_text

    prompt = build_prompt(result)
    assert build_prompt(result.model_copy(update={"verdict_v2": None, "checks_completed": None})) == prompt, "the prompt must not change because of verdict_v2"
    assert "verdict_v2" not in prompt and "confirmed_malicious" not in prompt
    for kind in ("content_type", "unlisted_content_type"):  # attacker-written content types never reach the language model
        assert markers[kind].lower() not in prompt.lower(), f"the {kind} marker leaked into the prompt"


# ---- (g) the V1 wording lint ----------------------------------------------------------------------------------------------------------------------------------------------------------

def test_every_string_of_verdict_v2_on_the_live_output_passes_the_v1_word_ban(live_results):
    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in value.values():
                yield from strings(v)
        elif isinstance(value, list):
            for v in value:
                yield from strings(v)

    for _mode, r in live_results:
        assert [s for s in strings(r.verdict_v2.model_dump()) if BANNED.search(s)] == []
        assert [s for s in strings(r.checks_completed.model_dump()) if BANNED.search(s)] == []


def test_the_v1_wording_lint_passes_in_strict_mode():
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_wording.py"), "--static", "--no-tests", "--strict"], capture_output=True, text=True, cwd=ROOT, timeout=300)
    assert done.returncode == 0, done.stdout[-2000:]
    assert "0 static hit(s)" in done.stdout
