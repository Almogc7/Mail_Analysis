import hashlib
from pathlib import Path

from app.parser.eml_parser import parse_eml
from app.parser.normalize import to_parsed_email

FIXTURES = Path(__file__).parent / "fixtures" / "samples"


def _parse(filename: str):
    raw_bytes = (FIXTURES / filename).read_bytes()
    return to_parsed_email(parse_eml(raw_bytes))


def test_clean_legit_email_basic_fields():
    parsed = _parse("clean_legit.eml")

    assert parsed.source_format == "eml"
    assert parsed.subject == "Quarterly report attached"
    assert parsed.from_.address == "alice@example.com"
    assert parsed.from_.domain == "example.com"
    assert parsed.to[0].address == "bob@example.org"
    assert parsed.return_path.address == "alice@example.com"
    assert len(parsed.authentication_results_raw) == 1
    assert "spf=pass" in parsed.authentication_results_raw[0]
    assert parsed.attachments == []
    assert parsed.parse_warnings == []


def test_from_return_path_mismatch_fixture():
    parsed = _parse("from_return_path_mismatch.eml")

    assert parsed.from_.domain == "corp-example.com"
    assert parsed.return_path.domain == "mailer-relay.net"


def test_attachment_hashing_matches_known_content():
    parsed = _parse("with_attachment.eml")

    assert len(parsed.attachments) == 1
    attachment = parsed.attachments[0]
    assert attachment.filename == "notes.txt"

    expected_content = b"This is a test attachment.\n"
    assert attachment.sha256 == hashlib.sha256(expected_content).hexdigest()
    assert attachment.sha1 == hashlib.sha1(expected_content).hexdigest()
    assert attachment.md5 == hashlib.md5(expected_content).hexdigest()
    assert attachment.size_bytes == len(expected_content)


def test_forwarded_mail_surfaces_all_authentication_results():
    parsed = _parse("forwarded_multiple_auth_results.eml")

    assert len(parsed.authentication_results_raw) == 2


def test_encoded_headers_are_decoded():
    parsed = _parse("encoded_headers.eml")

    assert parsed.from_.display_name == "François Müller"
    assert parsed.subject == "Réunion confirmée – à 09h00"
    assert parsed.from_.domain == "example.fr"


def test_spoofed_display_name_fixture_parses_cleanly():
    parsed = _parse("spoofed_display_name.eml")

    assert parsed.from_.display_name == "PayPal Support"
    assert parsed.from_.domain == "totally-legit-mailer.ru"
    assert len(parsed.urls) == 1
    assert parsed.urls[0].url.startswith("http://paypal.verify-account-now.ru")
