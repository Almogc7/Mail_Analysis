"""HTML extraction hardening: anchor/href normalization, <img src>, raw-file hash."""
import hashlib

import pytest

from app.parser import parse_email_file
from app.parser.normalize import _clean_text, _extract_images_from_html, _extract_urls_from_html
from tests.eval import FIXTURES

SAMPLES = FIXTURES.parent / "fixtures" / "samples"


def test_anchor_text_whitespace_is_collapsed():
    (u,) = _extract_urls_from_html('<a href="https://x.example.com/a">view\r\n   your invoice</a>')
    assert u.anchor_text == "view your invoice"


def test_zero_width_and_bidi_marks_are_removed_from_anchor_text():
    (u,) = _extract_urls_from_html('<a href="https://evil.example.net/x">https://bank.exa​mple.com/‏</a>')
    assert u.anchor_text == "https://bank.example.com/"
    # ...which makes the displayed-URL vs real-href mismatch detectable
    assert u.is_anchor_mismatch


def test_matching_displayed_url_is_not_a_mismatch_even_when_wrapped():
    (u,) = _extract_urls_from_html('<a href="https://x.example.com/a">https://x.example.com/a\n</a>')
    assert not u.is_anchor_mismatch


def test_href_with_embedded_newlines_and_tabs_is_repaired():
    (u,) = _extract_urls_from_html('<a href="https://x.example.com/p\r\n\tath?a=1">go</a>')
    assert u.url == "https://x.example.com/path?a=1"


def test_malformed_html_with_banner_before_doctype_still_yields_links():
    html = (
        "<p><strong>Attention!</strong> reported as malicious</p><br>\r\n"
        '<!DOCTYPE html><html><body><a href="https://x.example.com/1">one</a>'
        '<p><a href="https://x.example.com/2">two</body>'
    )
    assert [u.url for u in _extract_urls_from_html(html)] == ["https://x.example.com/1", "https://x.example.com/2"]


def test_non_http_hrefs_are_ignored():
    assert _extract_urls_from_html('<a href="mailto:a@example.com">m</a><a href="javascript:void(0)">j</a>') == []


def test_clean_text_is_idempotent():
    assert _clean_text(_clean_text("  a \n\t b​ ")) == "a b"


def test_images_extracted_with_dedup_and_metadata():
    html = (
        '<img src="https://img.example.com/a.png" alt="Logo\n here" width="600" height="2">'
        '<img src="https://img.example.com/a.png">'
        '<img src="//cdn.example.net/b.gif">'
        '<img src="cid:inline1"><img src="data:image/png;base64,AAAA">'
        '<img src="/relative.png">'
    )
    imgs = _extract_images_from_html(html)
    assert [i.url for i in imgs] == ["https://img.example.com/a.png", "https://cdn.example.net/b.gif"]
    assert imgs[0].alt == "Logo here" and imgs[0].width == "600" and imgs[0].height == "2"


def test_kvish6_fixture_images_and_normalized_anchors():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    hosts = {i.url.split("/")[2] for i in parsed.images}
    assert {"api-mail.walla.co.il", "nmrdn.printernet.co.il", "nmmediaint.printernet.co.il"} <= hosts
    # images are NOT in urls (so they cannot consume the enrichment cap)
    assert not any(u.url in {i.url for i in parsed.images} and u.source == "body_html" for u in parsed.urls)
    for u in parsed.urls:
        if u.anchor_text:
            assert "\r" not in u.anchor_text and "\n" not in u.anchor_text and "  " not in u.anchor_text
    cta = next(u for u in parsed.urls if ".ct.sendgrid.net" in u.url and u.source == "body_html")
    assert cta.anchor_text == "לצפייה בחשבונית"


@pytest.mark.parametrize("name", ["clean_legit.eml", "with_attachment.eml", "sample.msg"])
def test_raw_sha256_is_the_hash_of_the_file_as_received(name):
    raw = (SAMPLES / name).read_bytes()
    assert parse_email_file(raw, name).raw_sha256 == hashlib.sha256(raw).hexdigest()


def test_kvish6_fixture_hash_matches_manifest():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    assert parsed.raw_sha256 in (FIXTURES / "MANIFEST.md").read_text(encoding="utf-8")
