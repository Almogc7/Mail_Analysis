"""End to end: synthetic messages built here from bytes, through the REAL .eml parser (and a faked extract_msg object for .msg), the real coverage report and the adapter, to the blocker items.

Every payload is a few header bytes plus padding: no real malware, no EICAR, nothing an antivirus would flag. For each message the tests assert the blocker codes and details, and that nothing leaks:
the first bytes appear in no result JSON and no log, an unlisted part is never added to `attachments` and never reaches enrichment."""
import base64
import hashlib
import importlib.util
import json
import logging
import re
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.blockers import blocker_codes
from app.blockers_adapter import derive_message_blockers
from app.coverage import build_coverage_report
from app.parser import msg_parser, parse_email_file
from tests import eval as ev
from tests import test_unlisted_parts as unlisted

ROOT = Path(__file__).resolve().parents[2]
TEXT = ("Hello, this is a plain message with enough ordinary English words in it so that the language of the text can be read without any doubt "
        "by the simple heuristics of the tool. ") * 2
PNG = b"\x89PNG\r\n\x1a\n" + b"ZQXMARKE"  # a PNG signature, then a marker, within the first 16 bytes
MZ = b"MZ" + b"ZQXMARKE" + b"\x00\x00"
HTML = b"<html>" + b"ZQXMARKERHTML"
PDF = b"%PDF-1.7\n" + b"ZQXMARK"
ZIP = b"PK\x03\x04" + b"ZQXMARKE" + b"\x00" * 4
PLAIN = b"Plain ZQXMARKE text, nothing else here."
CAL = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"
RECEIVER = ("no_trusted_receiver_hop", "no_matching_hop")  # the environment: a synthetic message has no trusted receiver result


def _base(subject="end to end", from_value="sender@example.com") -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = from_value
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = subject
    msg.set_content(TEXT)
    return msg


def _run(raw: bytes, name="m.eml", mode="configured"):
    ev.apply_mode(mode)
    try:
        parsed = parse_email_file(raw, name)
        result = ev.analyze_parsed(parsed, "clean")
        coverage = build_coverage_report(parsed, result.module_results)
        items = derive_message_blockers(parsed, result.module_results, coverage)
    finally:
        ev.apply_mode("configured")
    return parsed, result, [(i["code"], i["detail"]) for i in items]


def _own(items):
    """The items of the message itself, without the environment's receiver blocker."""
    return [i for i in items if i != RECEIVER]


def _leak_forms(first_bytes: bytes) -> list[str]:
    forms = [first_bytes.hex(), base64.b64encode(first_bytes).decode(), base64.b64encode(first_bytes).decode().rstrip("=")]
    forms += [run.decode("ascii") for run in re.findall(rb"[ -~]{6,}", first_bytes) if b"ZQXMARK" in run]
    return forms


def _assert_nothing_leaks(parsed, result, caplog, payload: bytes, *, unlisted_only: bool):
    forms = _leak_forms(payload[:16])
    outputs = {"result JSON": result.model_dump_json(), "logs": caplog.text}
    for where, text in outputs.items():
        for form in forms:
            assert form not in text, f"the first bytes leaked into the {where} as {form!r}"
    if unlisted_only:
        digest = hashlib.sha256(payload).hexdigest()
        enrichment = next(m for m in result.module_results if m.module == "enrichment")
        assert parsed.attachments == [], "an unlisted part must never be added to attachments"
        assert digest not in json.dumps(enrichment.raw_data, default=str) and digest not in result.model_dump_json(), "an unlisted part is never hashed or looked up"


def _with_attachment(payload, filename, maintype="application", subtype="octet-stream") -> bytes:
    msg = _base()
    msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return bytes(msg)


# ---- the environment -------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_a_plain_message_has_only_the_environments_receiver_blocker_in_configured_and_not_configured_in_strict():
    _p, _r, items = _run(bytes(_base()))
    assert items == [RECEIVER]
    _p, _r, items = _run(bytes(_base()), mode="strict")
    assert items == [("no_trusted_receiver_hop", "not_configured")]


# ---- one message per case: the codes, the details, and nothing leaks --------------------------------------------------------------------------------------------------------------

CASES = [
    # (id, raw bytes factory, payload for the leak check, expected own items, unlisted only)
    ("png_attachment", lambda: _with_attachment(PNG, "photo.png", "image", "png"), PNG, [("qr_not_decoded", None)], False),
    ("mz_named_pdf", lambda: _with_attachment(MZ, "invoice.pdf", "application", "pdf"), MZ, [("static_analysis_off", "executable")], False),
    ("html_named_txt", lambda: _with_attachment(HTML, "note.txt", "text", "plain"), HTML, [("html_attachment_unanalysed", None)], False),
    ("pdf_named_png", lambda: _with_attachment(PDF, "photo.png", "image", "png"), PDF, [("static_analysis_off", "pdf")], False),
    ("zip_named_docx", lambda: _with_attachment(ZIP, "report.docx"), ZIP, [("archive_contents_unexamined", "archive"), ("static_analysis_off", "office_zip")], False),
    ("plain_text_attachment", lambda: _with_attachment(PLAIN, "notes.txt", "text", "plain"), PLAIN, [("static_analysis_off", "unknown_type")], False),
    ("calendar_attachment", lambda: _with_attachment(CAL, "invite.ics", "text", "calendar"), CAL, [("calendar_invite_unexamined", None)], False),
]


@pytest.mark.parametrize("case_id, build, payload, expected, unlisted_only", CASES, ids=[c[0] for c in CASES])
def test_a_named_attachment_gives_the_expected_blockers_and_nothing_leaks(case_id, build, payload, expected, unlisted_only, caplog):
    caplog.set_level(logging.DEBUG)
    parsed, result, items = _run(build())
    assert sorted(_own(items)) == sorted(expected), case_id
    assert [a.filename for a in parsed.attachments] == [parsed.attachments[0].filename] and len(parsed.attachments) == 1  # exactly the named part, nothing added
    _assert_nothing_leaks(parsed, result, caplog, payload, unlisted_only=unlisted_only)


def test_an_inline_cid_image_without_a_filename_blocks_and_is_not_an_attachment(caplog):
    caplog.set_level(logging.DEBUG)
    parsed, result, items = _run(unlisted._with_cid_image())
    assert _own(items) == [("inline_image_not_decoded", None)]
    assert parsed.attachments == [] and len(parsed.unlisted_parts) == 1
    _assert_nothing_leaks(parsed, result, caplog, unlisted.PNG, unlisted_only=True)


def test_a_data_image_in_the_html_blocks_and_stays_out_of_the_images_list(caplog):
    caplog.set_level(logging.DEBUG)
    msg = _base()
    msg.add_alternative('<p>hello</p><img src="data:image/png;base64,iVBORw0KGgo=">', subtype="html")
    parsed, result, items = _run(bytes(msg))
    assert _own(items) == [("data_uri_image_not_decoded", None)]
    assert parsed.data_image_count == 1 and parsed.images == [] and parsed.attachments == []


def test_a_remote_hot_linked_image_is_not_a_blocker(caplog):
    caplog.set_level(logging.DEBUG)
    msg = _base()
    msg.add_alternative('<p>hello</p><img src="https://img.example/pixel.png"><img src="http://img.example/logo.png">', subtype="html")
    parsed, _result, items = _run(bytes(msg))
    assert len(parsed.images) == 2  # the parser still lists the remote images
    assert _own(items) == []
    assert not {code for code, _d in items} & {"qr_not_decoded", "inline_image_not_decoded", "data_uri_image_not_decoded"}


def test_a_nested_message_attachment_blocks_and_is_not_an_attachment(caplog):
    caplog.set_level(logging.DEBUG)
    msg = _base()
    msg.add_attachment(_base("inner message"))
    parsed, result, items = _run(bytes(msg))
    assert _own(items) == [("nested_message_unexamined", "rfc822")]
    assert parsed.attachments == [] and [p.content_type for p in parsed.unlisted_parts] == ["message/rfc822"]
    assert all("inner message" not in json.dumps(p.model_dump()) for p in parsed.unlisted_parts)


def test_a_nameless_calendar_part_blocks_and_is_not_an_attachment():
    msg = _base()
    msg.add_attachment(CAL, maintype="text", subtype="calendar")
    parsed, _result, items = _run(bytes(msg))
    assert _own(items) == [("calendar_invite_unexamined", None)] and parsed.attachments == []


def test_a_malformed_from_blocks_with_malformed_or_missing():
    for value in ("not an address", "<>"):
        _p, _r, items = _run(bytes(_base(from_value=value)))
        assert _own(items) == [("from_header_unparseable", "malformed")], value


def test_a_deliberately_malformed_mime_sets_a_parse_flag_and_the_parse_failure_blocker():
    lines = ["From: a@example.com", "To: b@example.com", "Subject: s", "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="XX"', "", "--XX", "Content-Type: text/plain", "", TEXT]
    parsed, _result, items = _run("\r\n".join(lines).encode("ascii") + b"\r\n")  # no closing boundary
    assert [(f.code, f.part_id) for f in parsed.parse_flags] == [("mime_structure_error", "part:0")]
    assert ("parse_failure", "mime_structure_error") in items


def test_a_part_whose_read_failed_blocks_with_the_flags_detail(monkeypatch):
    import email.message

    original = email.message.Message.get_payload

    def failing(self, i=None, decode=False):
        if decode and self.get_filename():
            raise RuntimeError("cannot decode")
        return original(self, i, decode)

    monkeypatch.setattr(email.message.Message, "get_payload", failing)
    _p, _r, items = _run(_with_attachment(PNG, "photo.png", "image", "png"))
    assert ("parse_failure", "attachment_read_failed") in items


# ---- .msg through a faked extract_msg object ---------------------------------------------------------------------------------------------------------------------------------------

def _run_msg(monkeypatch, attachments):
    monkeypatch.setattr(msg_parser.extract_msg, "Message", lambda path: unlisted.FakeMsg(attachments))
    return _run(b"not a real msg file", "m.msg")


def test_msg_attachments_give_the_same_blockers_as_eml(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    parsed, result, items = _run_msg(monkeypatch, [unlisted.FakeAttachment(PNG, "photo.png"), unlisted.FakeAttachment(MZ, "invoice.pdf"), unlisted.FakeAttachment(HTML, "note.txt")])
    assert sorted(i for i in items if i[0] not in ("no_trusted_receiver_hop", "language_unsupported", "from_header_unparseable")) == sorted(
        [("qr_not_decoded", None), ("static_analysis_off", "executable"), ("html_attachment_unanalysed", None)])
    _assert_nothing_leaks(parsed, result, caplog, MZ, unlisted_only=False)


def test_a_msg_inline_image_with_a_content_id_is_an_inline_image_blocker(monkeypatch):
    _parsed, _result, items = _run_msg(monkeypatch, [unlisted.FakeAttachment(PNG, "logo.png", cid="logo1")])
    assert ("inline_image_not_decoded", None) in items and ("qr_not_decoded", None) not in items


def test_a_msg_attachment_that_cannot_be_read_blocks_as_a_parse_failure(monkeypatch):
    class Exploding:
        longFilename, shortFilename, cid = "private.bin", None, None

        @property
        def data(self):
            raise OSError("cannot read")

    _parsed, _result, items = _run_msg(monkeypatch, [Exploding()])
    assert ("parse_failure", "attachment_read_failed") in items


# ---- the corpus: the adapter equals the step 9 report, except for the receiver fix -----------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def report_module():
    spec = importlib.util.spec_from_file_location("report_blocker_inputs", ROOT / "scripts" / "report_blocker_inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _corpus_counts(report_module):
    import collections

    out = {}
    items = ev.collect(None)
    for mode in ev.MODES:
        ev.apply_mode(mode)
        codes, any_blocker, any_excluding_receiver, differs, compared = collections.Counter(), 0, 0, 0, 0
        for path, _label, _source in items:
            result = ev.analyze(path, "clean")
            coverage = build_coverage_report(result.parsed_email, result.module_results)
            mine = set(blocker_codes(derive_message_blockers(result.parsed_email, result.module_results, coverage)))
            codes.update(mine)
            any_blocker += bool(mine)
            any_excluding_receiver += bool(mine - {"no_trusted_receiver_hop"})
            today, simulated, flags = report_module.build_inputs(result, path)
            if simulated is not None or not today:  # the script's own first-bytes simulation (an .eml); a .msg is not simulated
                compared += 1
                from app.blockers import derive_blockers

                if set(blocker_codes(derive_blockers(simulated if simulated is not None else today, flags))) != mine:
                    differs += 1
        out[mode] = {"messages": len(items), "any": any_blocker, "any_excluding_receiver": any_excluding_receiver, "codes": dict(sorted(codes.items())), "differs": differs, "compared": compared}
    ev.apply_mode("configured")
    return out


def test_the_adapter_equals_the_report_script_on_every_fixture_and_tuning_message_in_both_modes(report_module):
    counts = _corpus_counts(report_module)
    for mode, c in counts.items():
        print(f"\n{mode}: {c['any']} of {c['messages']} messages have a blocker ({c['any_excluding_receiver']} excluding the receiver blocker); codes {c['codes']}")
        assert c["differs"] == 0 and c["compared"] == c["messages"], mode


def test_the_counts_equal_the_step_9_report_except_for_the_documented_receiver_fix(report_module):
    counts = _corpus_counts(report_module)
    if counts["strict"]["messages"] != 107:
        pytest.skip("the step 9 report was made on 107 messages (the fixtures plus the local tuning corpus); this checkout has a different corpus")
    step9 = {"data_uri_image_not_decoded": 1, "from_header_unparseable": 1, "internal_host_not_sent": 1, "language_unsupported": 40, "no_readable_text": 2, "redirects_not_resolved": 11,
             "shared_platform": 20, "static_analysis_off": 2}
    for mode, receiver in (("strict", 107), ("configured", 8)):
        codes = dict(counts[mode]["codes"])
        assert codes.pop("no_trusted_receiver_hop") == receiver
        assert codes == step9, mode
    # step 9 reported 61 of 107 in STRICT (it emitted no receiver blocker there) and 66 of 107 in CONFIGURED: only the STRICT figure moves, to every message, because nothing is trusted in STRICT
    assert counts["strict"]["any_excluding_receiver"] == 61 and counts["strict"]["any"] == 107
    assert counts["configured"]["any"] == 66
