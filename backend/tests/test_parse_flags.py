"""ParsedEmail.parse_flags (contracts/email.py): structured, content-free parse failures {code, part_id} next to the unchanged free-text parse_warnings.

Codes come from a CLOSED set; part ids are short tokens (body_text, body_html, attachment:N, part:N, header:date, headers), never a name or error text. parse_limit and parse_timeout stay unreachable:
the parser has no limit or timeout today."""
import email.headerregistry
import email.message
import json
import re
import typing
from email.message import EmailMessage

import pytest

from app.contracts.email import ParseFlag, ParseFlagCode
from app.parser import msg_parser, parse_email_file
from tests import eval as ev
from tests import test_unlisted_parts as unlisted

PART_ID = re.compile(r"^[a-z_]+(:[a-z_0-9]+)?$")
CODES = set(typing.get_args(ParseFlagCode))


def _eml(extra_headers: str = "") -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = "flags test"
    msg.set_content("plain body")
    msg.add_alternative("<p>html body</p>", subtype="html")
    raw = bytes(msg)
    return raw if not extra_headers else extra_headers.encode() + raw


def _flags(parsed):
    return [(f.code, f.part_id) for f in parsed.parse_flags]


# ---- the closed set -------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_the_code_set_is_exactly_the_four_failure_codes_and_limit_and_timeout_are_not_in_it():
    assert CODES == {"body_extract_failed", "attachment_read_failed", "header_parse_failed", "mime_structure_error"}
    assert not {"parse_limit", "parse_timeout"} & CODES
    from app.blockers import PARSE_FAILURE_DETAILS

    assert set(PARSE_FAILURE_DETAILS) == CODES  # the blocker module's details are the parser's flag codes
    with pytest.raises(Exception):
        ParseFlag(code="parse_timeout", part_id="x")


def test_a_message_that_parses_cleanly_has_no_flags():
    parsed = parse_email_file(_eml(), "m.eml")
    assert parsed.parse_flags == []


def test_the_field_is_additive_and_defaults_to_empty():
    from app.contracts.email import EmailAddress, ParsedEmail

    assert ParsedEmail(source_format="eml", from_=EmailAddress(), raw_size_bytes=1).parse_flags == []


# ---- the real failure sites (eml) ---------------------------------------------------------------------------------------------------------------------------------------------

def test_a_malformed_mime_structure_sets_mime_structure_error_on_the_affected_part():
    raw = (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="XX"\r\n\r\n'
           b"--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n")  # no closing boundary
    parsed = parse_email_file(raw, "m.eml")
    assert _flags(parsed) == [("mime_structure_error", "part:0")]


def test_a_multipart_without_a_boundary_sets_mime_structure_error():
    raw = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed\r\n\r\nno boundary here\r\n"
    assert ("mime_structure_error", "part:0") in _flags(parse_email_file(raw, "m.eml"))


def test_a_body_extraction_failure_sets_body_extract_failed_for_the_text_and_the_html_body_and_keeps_the_warning(monkeypatch):
    original = email.message.EmailMessage.get_content

    def failing(self, *args, **kwargs):
        if self.get_content_type() in ("text/plain", "text/html"):
            raise RuntimeError("boom with a secret name")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(email.message.EmailMessage, "get_content", failing)
    parsed = parse_email_file(_eml(), "m.eml")
    assert sorted(_flags(parsed)) == [("body_extract_failed", "body_html"), ("body_extract_failed", "body_text")]
    assert any(w.startswith("Failed to extract text body") for w in parsed.parse_warnings)  # the free-text warnings are unchanged
    assert "secret name" not in json.dumps([f.model_dump() for f in parsed.parse_flags])


def test_an_attachment_decode_failure_sets_attachment_read_failed_and_keeps_the_warning(monkeypatch):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg.set_content("body")
    msg.add_attachment(b"abc", maintype="application", subtype="octet-stream", filename="private-name.bin")
    original = email.message.Message.get_payload

    def failing(self, i=None, decode=False):
        if decode and self.get_filename():
            raise RuntimeError("cannot decode")
        return original(self, i, decode)

    monkeypatch.setattr(email.message.Message, "get_payload", failing)
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert _flags(parsed) == [("attachment_read_failed", "attachment:0")]
    assert any(w.startswith("Failed to decode attachment") for w in parsed.parse_warnings)
    assert "private-name" not in json.dumps([f.model_dump() for f in parsed.parse_flags])  # the file name is in the warning, never in the flag


def test_an_unlisted_part_that_cannot_be_decoded_sets_attachment_read_failed(monkeypatch):
    original = email.message.Message.get_payload

    def failing(self, i=None, decode=False):
        if decode and self.get_content_type() == "text/calendar":
            raise RuntimeError("cannot decode")
        return original(self, i, decode)

    msg = unlisted._base()
    msg.add_attachment(unlisted.CAL, maintype="text", subtype="calendar")
    monkeypatch.setattr(email.message.Message, "get_payload", failing)
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert _flags(parsed) == [("attachment_read_failed", "part:0")]


def test_a_date_header_failure_sets_header_parse_failed(monkeypatch):
    def failing(self):
        raise ValueError("bad date")

    monkeypatch.setattr(email.headerregistry.DateHeader, "datetime", property(failing))
    parsed = parse_email_file(_eml("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"), "m.eml")
    assert _flags(parsed) == [("header_parse_failed", "header:date")]
    assert any(w.startswith("Failed to parse Date header") for w in parsed.parse_warnings)


def test_an_encoding_defect_is_not_a_mime_structure_error_and_sets_no_flag():
    """Invalid base64 characters in an attachment (common in real mail; a tuning-corpus message has one) are a data defect: the payload is still read, so no flag and no blocker."""
    lines = [
        "From: a@example.com", "To: b@example.com", "Subject: s", "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="XX"', "",
        "--XX", "Content-Type: text/plain", "", "hello",
        "--XX", "Content-Type: application/pdf; name=a.pdf", "Content-Disposition: attachment; filename=a.pdf", "Content-Transfer-Encoding: base64", "", "JVBERi0x!!!!ZZZZ",
        "--XX--", "",
    ]
    parsed = parse_email_file("\r\n".join(lines).encode("ascii"), "m.eml")
    assert len(parsed.attachments) == 1 and parsed.parse_flags == []


# ---- not every warning is a flag ----------------------------------------------------------------------------------------------------------------------------------------------

def test_an_ambiguous_header_is_a_warning_with_its_own_finding_and_not_a_parse_failure():
    parsed = parse_email_file(_eml("From: first@example.com, second@example.com\r\n"), "m.eml")
    assert any("ambig" in w.lower() for w in parsed.parse_warnings)
    assert parsed.parse_flags == []


# ---- .msg: a faked extract_msg object -------------------------------------------------------------------------------------------------------------------------------------------

def test_a_msg_attachment_that_cannot_be_read_sets_attachment_read_failed(monkeypatch):
    class Exploding:
        longFilename, shortFilename, cid = "private-name.bin", None, None

        @property
        def data(self):
            raise OSError("cannot read")

    monkeypatch.setattr(msg_parser.extract_msg, "Message", lambda path: unlisted.FakeMsg([Exploding()]))
    parsed = parse_email_file(b"not a real msg file", "m.msg")
    assert _flags(parsed) == [("attachment_read_failed", "attachment:0")]
    assert any(w.startswith("Failed to read attachment") for w in parsed.parse_warnings)
    assert "private-name" not in json.dumps([f.model_dump() for f in parsed.parse_flags])


def test_msg_embedded_headers_that_fail_to_parse_set_header_parse_failed(monkeypatch):
    class WithHeaders(unlisted.FakeMsg):
        header = "Subject: x\r\n"

    def failing(*args, **kwargs):
        raise ValueError("bad headers")

    monkeypatch.setattr(msg_parser.extract_msg, "Message", lambda path: WithHeaders([]))
    monkeypatch.setattr(msg_parser.email, "message_from_string", failing)
    parsed = parse_email_file(b"not a real msg file", "m.msg")
    assert ("header_parse_failed", "headers") in _flags(parsed)


def test_informational_msg_notes_about_missing_headers_are_not_failures(monkeypatch):
    monkeypatch.setattr(msg_parser.extract_msg, "Message", lambda path: unlisted.FakeMsg([]))
    parsed = parse_email_file(b"not a real msg file", "m.msg")
    assert any("No raw internet headers" in w for w in parsed.parse_warnings)
    assert parsed.parse_flags == []


# ---- content-free and the corpus ----------------------------------------------------------------------------------------------------------------------------------------------

def test_every_flag_is_a_closed_code_and_a_content_free_part_id():
    raw = (b'From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="XX"\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n')
    for flag in parse_email_file(raw, "m.eml").parse_flags:
        assert flag.code in CODES and PART_ID.match(flag.part_id), flag
        assert set(flag.model_dump()) == {"code", "part_id"}


def test_over_every_fixture_and_the_tuning_corpus_the_parser_sets_no_flag_so_no_corpus_result_changes():
    total = 0
    for path, _label, _source in ev.collect(None):
        total += len(parse_email_file(path.read_bytes(), path.name).parse_flags)
    assert total == 0
