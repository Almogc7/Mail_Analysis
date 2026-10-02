"""Gateway banner / subject-tag stripping (app/parser/preprocess.py)."""
import pytest

import app.parser.preprocess as pp
from app.content_analysis import run_content_analysis
from app.content_analysis.text_utils import get_searchable_text, searchable_text_with_report
from app.parser import parse_email_file
from app.parser.preprocess import StripReport, clean_body_text, clean_subject, strip_injected_html_prefix
from tests.eval import FIXTURES

BANNER_HTML = "<p><strong>Attention!</strong></p><p>This email was reported as malicious. Final notice: verify your account now.</p>"
ORIGINAL_HTML = '<!DOCTYPE html><html><body><p>Hello, here is the invoice.</p><a href="https://x.example.com/i">view</a></body></html>'
BANNER_TEXT = "Attention!\r\n\r\nThis email was reported as malicious. Final notice: verify your account now.\r\n\r\n"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    # The developer's real backend/.env must never influence these tests.
    monkeypatch.setattr(pp, "GATEWAY_BANNER_PATTERNS", [])
    monkeypatch.setattr(pp, "GATEWAY_SUBJECT_TAG_PATTERNS", [])


def test_html_prefix_before_nonleading_doctype_is_stripped():
    report = StripReport()
    html, prefix = strip_injected_html_prefix("<html><body>" + BANNER_HTML + ORIGINAL_HTML, report)
    assert html.startswith("<!DOCTYPE") and "reported as malicious" in prefix
    assert report.removed[0]["kind"] == "html_injected_prefix"


@pytest.mark.parametrize(
    "html",
    [
        ORIGINAL_HTML,  # doctype is leading: nothing injected
        "<html><body>no doctype at all</body></html>",
        "<p>" + "word " * 1000 + "</p>" + ORIGINAL_HTML,  # prefix too long to be a banner
    ],
)
def test_prefix_not_stripped_when_not_banner_shaped(html):
    out, prefix = strip_injected_html_prefix(html)
    assert out == html and prefix is None


def test_plain_part_banner_removed_when_it_matches_the_html_prefix():
    text, report = clean_body_text(BANNER_TEXT + "Hello, here is the invoice.", "<html><body>" + BANNER_HTML + ORIGINAL_HTML)
    assert text.strip() == "Hello, here is the invoice."
    assert [r["kind"] for r in report.removed] == ["html_injected_prefix", "plain_injected_prefix"]


def test_plain_part_untouched_when_it_does_not_start_with_the_prefix():
    body = "Hello, here is the invoice. " + BANNER_TEXT
    text, _ = clean_body_text(body, "<html><body>" + BANNER_HTML + ORIGINAL_HTML)
    assert "reported as malicious" in text


def test_html_only_message_drops_prefix_from_visible_text():
    text, _ = clean_body_text(None, "<html><body>" + BANNER_HTML + ORIGINAL_HTML)
    assert "malicious" not in text and "invoice" in text


def test_configured_banner_patterns_apply_and_are_reported():
    text, report = clean_body_text("EXTERNAL SENDER WARNING: be careful. Real content.", None, patterns=[r"external sender warning:[^.]*\."])
    assert "careful" not in text and "Real content." in text
    assert report.removed[0]["kind"] == "banner_pattern"


def test_default_generic_banner_pattern():
    text, _ = clean_body_text("CAUTION: This email originated from outside the organization. Do not click.\nHello there.", None)
    assert "originated from outside" not in text and "Hello there." in text


def test_invalid_pattern_is_skipped_and_reported_not_raised():
    text, report = clean_body_text("keep me", None, patterns=["(unclosed"])
    assert text == "keep me" and any("invalid" in w for w in report.warnings)


@pytest.mark.parametrize(
    "subject,expected",
    [
        ("[EXTERNAL] Quarterly numbers", "Quarterly numbers"),
        ("[Caution: Suspicious Email!] Your invoice", "Your invoice"),
        ("[PayPal] Your receipt", "[PayPal] Your receipt"),  # a brand in brackets is content, not a tag
        ("Re: [JIRA-123] deploy", "Re: [JIRA-123] deploy"),
        (None, None),
    ],
)
def test_subject_default_tags(subject, expected):
    assert clean_subject(subject)[0] == expected


def test_configured_subject_tag_pattern():
    subject, report = clean_subject("[REPORTED-PHISH] Monthly bill", patterns=[r"\[REPORTED-PHISH\]\s*"])
    assert subject == "Monthly bill" and report.removed[0]["kind"] == "subject_tag"


def test_banner_phrases_no_longer_trigger_urgency_findings():
    # Without stripping, "final notice" and "verify your account" inside the gateway banner
    # would be scored as the sender's urgency language.
    raw = (
        "From: Sender <s@mail.example.com>\r\nTo: r@example.com\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/alternative; boundary="B"\r\n\r\n'
        f'--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{BANNER_TEXT}Hello, here is the invoice.\r\n'
        f'--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>{BANNER_HTML}{ORIGINAL_HTML}\r\n--B--\r\n'
    ).encode()
    parsed = parse_email_file(raw, "x.eml")
    assert "final notice" in parsed.body_text.lower()  # the original is preserved untouched
    assert run_content_analysis(parsed).findings == []


def test_kvish6_fixture_banner_is_stripped_structurally_without_any_config():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    assert "reported as malicious" in parsed.body_text  # raw body keeps it
    text, report = searchable_text_with_report(parsed)
    assert "reported as malicious" not in text and "Attention!" not in text
    assert {r["kind"] for r in report.removed} == {"html_injected_prefix", "plain_injected_prefix"}
    assert get_searchable_text(parsed) == text
    assert "תקף לחודש בלבד" in text  # real content survives
