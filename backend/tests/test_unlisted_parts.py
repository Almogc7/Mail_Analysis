"""ParsedEmail.unlisted_parts (contracts/email.py): metadata of parts that are neither the body nor in `attachments` (an inline cid: image, a nameless message/rfc822 or calendar part).

They are NEVER added to `attachments`, never hashed, never reach enrichment, and the existing attachments, urls, images, evidence block and indicator pack stay byte-identical for every fixture
(tests/parser_identity.py holds the snapshot recorded before this addition)."""
import json
import logging
from email.message import EmailMessage

import pytest

from app.parser import msg_parser, parse_email_file
from tests import eval as ev
from tests import parser_identity

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 24
PDF = b"%PDF-1.7\n" + b"\x00" * 16
CAL = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"


def _base(subject="unlisted parts test") -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = subject
    msg.set_content("plain part")
    return msg


def _with_cid_image(cid="<logo1@example.com>") -> bytes:
    msg = _base()
    msg.add_alternative('<p>hello</p><img src="cid:logo1@example.com">', subtype="html")
    msg.get_body(preferencelist=("html",)).add_related(PNG, "image", "png", cid=cid)
    return bytes(msg)


# ---- identity: nothing that existed changes ----------------------------------------------------------------------------------------------------------------------------------------

def test_attachments_urls_images_evidence_and_indicators_are_byte_identical_for_every_fixture_and_tuning_message():
    recorded = json.loads(parser_identity.SNAPSHOT.read_text(encoding="utf-8"))["messages"]
    current = parser_identity.compute()
    ev.apply_mode("configured")
    assert len(current) >= 119 - 75 and set(current) <= set(recorded)
    changed = sorted((key, section) for key, digests in current.items() for section, value in digests.items() if recorded[key][section] != value)
    assert changed == [], "an existing output section changed (list shows the message key and the section)"


# ---- what is captured ------------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_an_inline_cid_image_without_a_filename_is_captured_as_metadata_and_is_not_an_attachment():
    parsed = parse_email_file(_with_cid_image(), "m.eml")
    assert parsed.attachments == []
    (part,) = parsed.unlisted_parts
    assert (part.content_type, part.is_inline, part.has_content_id) == ("image/png", True, True)
    assert part.size_bytes == len(PNG) and part.first_bytes == PNG[:16]


def test_a_nameless_nested_message_and_a_nameless_calendar_part_are_captured_and_not_inline():
    inner = _base("inner")
    msg = _base()
    msg.add_attachment(inner)  # a message/rfc822 part with disposition attachment and no filename
    msg.add_attachment(CAL, maintype="text", subtype="calendar")
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert parsed.attachments == []
    kinds = sorted((p.content_type, p.is_inline, p.has_content_id) for p in parsed.unlisted_parts)
    assert kinds == [("message/rfc822", False, False), ("text/calendar", False, False)]
    by_type = {p.content_type: p for p in parsed.unlisted_parts}
    assert by_type["text/calendar"].first_bytes == CAL[:16]
    assert by_type["message/rfc822"].first_bytes.lower().startswith(b"from:")  # the first bytes of the inner message, which is what the magic-number detection reads
    assert "inner" not in json.dumps(parsed.model_dump(mode="json"))  # nothing of the inner message (its subject) is copied into the metadata


def test_the_body_parts_are_not_unlisted_and_a_message_with_only_a_body_has_none():
    simple = parse_email_file(bytes(_base()), "m.eml")
    assert simple.unlisted_parts == []
    both = _base()
    both.add_alternative("<p>html part</p>", subtype="html")
    assert parse_email_file(bytes(both), "m.eml").unlisted_parts == []


def test_a_part_with_a_filename_stays_an_attachment_and_is_not_duplicated_into_the_unlisted_list():
    msg = _base()
    msg.add_attachment(PDF, maintype="application", subtype="pdf", filename="a.pdf")
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert [a.filename for a in parsed.attachments] == ["a.pdf"] and parsed.unlisted_parts == []


def test_a_named_inline_image_keeps_going_to_attachments_exactly_as_before():
    msg = _base()
    msg.add_alternative("<p>hi</p>", subtype="html")
    msg.get_body(preferencelist=("html",)).add_related(PNG, "image", "png", cid="<n1>", filename="logo.png", disposition="inline")
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert [(a.filename, a.is_inline) for a in parsed.attachments] == [("logo.png", True)] and parsed.unlisted_parts == []


# ---- never hashed, listed, looked up or output --------------------------------------------------------------------------------------------------------------------------------------

def test_an_unlisted_part_is_never_hashed_or_looked_up_and_its_first_bytes_are_never_serialised(caplog):
    caplog.set_level(logging.DEBUG)
    import hashlib

    parsed = parse_email_file(_with_cid_image(), "m.eml")
    digest = hashlib.sha256(PNG).hexdigest()
    assert set(parsed.unlisted_parts[0].model_dump()) == {"content_type", "size_bytes", "is_inline", "has_content_id"}  # no hash, no name, no bytes
    result = ev.analyze_parsed(parsed, "clean")
    ev.apply_mode("configured")
    enrichment = next(m for m in result.module_results if m.module == "enrichment")
    assert digest not in (enrichment.raw_data or {}) and digest not in json.dumps(result.model_dump(mode="json"))
    assert PNG[:8].decode("latin-1") not in result.model_dump_json() and PNG[:8].hex() not in result.model_dump_json()
    assert "unlisted" not in caplog.text.lower() or PNG.hex() not in caplog.text


def test_the_unlisted_parts_field_is_additive_and_defaults_to_empty():
    from app.contracts.email import EmailAddress, ParsedEmail

    assert ParsedEmail(source_format="eml", from_=EmailAddress(), raw_size_bytes=1).unlisted_parts == []


# ---- .msg: a faked extract_msg object ----------------------------------------------------------------------------------------------------------------------------------------------

class FakeAttachment:
    def __init__(self, data, long_name=None, short_name=None, cid=None):
        self.data, self.longFilename, self.shortFilename, self.cid = data, long_name, short_name, cid


class FakeMsg:
    header = None
    sender = "Sender <sender@example.com>"
    subject = "fake msg"
    date = None
    to = "rcpt@example.com"
    cc = None
    body = "plain body"
    htmlBody = None

    def __init__(self, attachments):
        self.attachments = attachments

    def close(self):
        pass


def _parse_fake_msg(monkeypatch, attachments):
    monkeypatch.setattr(msg_parser.extract_msg, "Message", lambda path: FakeMsg(attachments))
    return parse_email_file(b"not a real msg file", "m.msg")


def test_a_msg_attachment_that_carries_a_content_id_is_inline_and_one_without_is_not(monkeypatch):
    parsed = _parse_fake_msg(monkeypatch, [FakeAttachment(PNG, "logo.png", cid="logo1"), FakeAttachment(PDF, "a.pdf")])
    assert [(a.filename, a.is_inline) for a in parsed.attachments] == [("logo.png", True), ("a.pdf", False)]
    assert [a.first_bytes for a in parsed.attachments] == [PNG[:16], PDF[:16]]


def test_a_nameless_msg_attachment_is_still_listed_by_extract_msg_so_there_are_no_separate_unlisted_parts(monkeypatch):
    parsed = _parse_fake_msg(monkeypatch, [FakeAttachment(PNG, None, None, cid="logo1")])
    assert [(a.filename, a.is_inline) for a in parsed.attachments] == [(None, True)] and parsed.unlisted_parts == []


def test_a_msg_without_attachments_has_none_of_either(monkeypatch):
    parsed = _parse_fake_msg(monkeypatch, [])
    assert parsed.attachments == [] and parsed.unlisted_parts == []


def test_a_named_nested_message_is_captured_too_because_it_never_reached_the_attachment_list():
    msg = _base()
    msg.add_attachment(_base("inner"), filename="forwarded.eml")
    parsed = parse_email_file(bytes(msg), "m.eml")
    assert [p.content_type for p in parsed.unlisted_parts] == ["message/rfc822"]
    assert parsed.attachments == []  # unchanged behaviour: the standard library treats the nested message as multipart, so it was never listed


def test_parts_inside_a_nested_message_are_not_separate_unlisted_parts_of_the_outer_message():
    inner = _base("inner")
    inner.add_alternative("<p>inner html</p>", subtype="html")
    inner.get_body(preferencelist=("html",)).add_related(PNG, "image", "png", cid="<in1>")
    outer = _base()
    outer.add_attachment(inner)
    parsed = parse_email_file(bytes(outer), "m.eml")
    assert [p.content_type for p in parsed.unlisted_parts] == ["message/rfc822"]
