"""Address extraction parity for .msg: the same malformed headers recover the same way as in .eml."""
from datetime import datetime

from app.auth_check import run_auth_check
from app.parser.addresses import AMBIGUITY_PREFIX
from app.parser.msg_parser import _parse_extract_msg, _split_address_list
from app.parser.normalize import to_parsed_email


class FakeMsg:
    """Just the attributes _parse_extract_msg reads from extract_msg.Message."""

    def __init__(self, sender="", to="", cc="", reply_to="", header="", subject="s"):
        self.sender, self.to, self.cc, self.replyTo, self.header = sender, to, cc, reply_to, header
        self.subject, self.date, self.messageId, self.body, self.htmlBody = subject, datetime(2026, 9, 21), "<m@x.example.com>", "hi", None
        self.attachments = []


def _parse(**kw):
    warnings: list[str] = []
    raw = _parse_extract_msg(FakeMsg(**kw), b"", warnings)
    return to_parsed_email(raw)


def test_a_sender_with_an_unquoted_comma_keeps_its_address():
    parsed = _parse(sender="PayPal, Inc. <support@evil.example.net>")
    assert parsed.from_.address == "support@evil.example.net" and parsed.from_.display_name == "PayPal, Inc."


def test_an_exchange_dn_sender_falls_back_to_the_raw_from_header():
    # msg.sender can be an X.500 DN with no '@'; the embedded internet headers carry the real address
    header = "From: Doe, John <jdoe@x.example.com>\r\nTo: t@example.com\r\nSubject: s\r\n"
    parsed = _parse(sender="/O=ORG/OU=EXCHANGE/CN=RECIPIENTS/CN=jdoe", header=header)
    assert parsed.from_.address == "jdoe@x.example.com" and parsed.from_.domain == "x.example.com"
    assert any(w.startswith(f"{AMBIGUITY_PREFIX}:from:") and "unquoted comma" in w for w in parsed.parse_warnings)


def test_a_recipient_with_a_comma_in_the_display_name_is_not_torn_apart():
    to = _split_address_list("Doe, John <a@x.example.com>")
    assert [(a.display_name, a.address) for a in to] == [("Doe, John", "a@x.example.com")]


def test_semicolon_separated_lists_still_work():
    to = _split_address_list("A <a@x.example.com>; B <b@y.example.org>")
    assert [a.address for a in to] == ["a@x.example.com", "b@y.example.org"]


def test_comma_separated_lists_without_commas_in_names_still_split():
    to = _split_address_list("A <a@x.example.com>, B <b@y.example.org>")
    assert [a.address for a in to] == ["a@x.example.com", "b@y.example.org"]


def test_a_malformed_reply_to_is_recovered():
    parsed = _parse(sender="Clean <a@x.example.com>", reply_to="Support, Team <help@elsewhere.example.org>")
    assert parsed.reply_to[0].domain == "elsewhere.example.org"


def test_the_same_informational_finding_appears_for_msg_and_never_scores():
    header = "From: PayPal, Inc. <support@evil.example.net>\r\nTo: t@example.com\r\nSubject: s\r\n"
    parsed = _parse(sender="PayPal, Inc. <support@evil.example.net>", header=header)
    finding = next(f for f in run_auth_check(parsed).findings if f.title == "From header parse ambiguity")
    assert finding.severity == "low" and finding.weight == 0.0


def test_a_clean_sender_and_header_produce_no_ambiguity_warning():
    header = 'From: "Doe, John" <jdoe@x.example.com>\r\nTo: t@example.com\r\nSubject: s\r\n'
    parsed = _parse(sender="Doe, John <jdoe@x.example.com>", header=header)
    assert not [w for w in parsed.parse_warnings if w.startswith(AMBIGUITY_PREFIX)]


def test_missing_headers_and_sender_do_not_crash():
    parsed = _parse(sender=None, header="")
    assert parsed.from_.address is None
