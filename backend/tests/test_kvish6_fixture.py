"""The sanitized Kvish 6 fixture must still carry every structural property of the original
that the detectors rely on. If sanitization (or a parser change) loses one of these, the
regression tests built on this fixture silently stop testing what they claim to."""
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from app.parser import parse_email_file
from tests.eval import FIXTURES

PATH = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"


@pytest.fixture(scope="module")
def parsed():
    return parse_email_file(PATH.read_bytes(), PATH.name)


def _hdr(parsed, name):
    return [h.value for h in parsed.headers if h.name.lower() == name]


def test_first_hop_is_local_submission_on_sweb_shared_hosting(parsed):
    origin = parsed.received_chain[-1]  # headers are prepended: the last Received is the first hop
    assert re.search(r"with local \(Exim", origin.raw)
    assert origin.by_host == "vh319.sweb.ru"
    assert not any("ESMTPA" in h.raw or "authenticated" in h.raw.lower() for h in parsed.received_chain[-2:])
    assert any("77.222.61.245" in h.raw and "vh319.sweb.ru" in h.raw for h in parsed.received_chain)


def test_sender_is_sweb_origin_with_brand_in_display_name(parsed):
    assert parsed.from_.domain == "vh319.sweb.ru"
    assert "kvish6" in parsed.from_.display_name
    assert parsed.reply_to == [] and parsed.return_path is None


def test_only_upstream_spf_pass_no_dkim_dmarc_or_authentication_results(parsed):
    assert parsed.authentication_results_raw == []
    spf = _hdr(parsed, "received-spf")
    assert len(spf) == 1 and spf[0].lower().startswith("pass") and "x-conformance=spf_only" in spf[0]
    assert not _hdr(parsed, "dkim-signature")


def test_single_sendgrid_cta_with_decoy_brand_links(parsed):
    html_urls = [u for u in parsed.urls if u.source == "body_html"]
    assert len(html_urls) == 7
    cta = [u for u in html_urls if urlparse(u.url).netloc.endswith(".ct.sendgrid.net")]
    assert len(cta) == 1 and urlparse(cta[0].url).path == "/ls/click"
    assert "בחשבונית" in cta[0].anchor_text  # "view invoice"
    assert any(urlparse(u.url).netloc == "service.kvish6.co.il" for u in html_urls)  # decoys to the real brand
    assert any(urlparse(u.url).netloc.endswith("printernet.co.il") for u in html_urls)


def test_cloned_template_assets_include_walla_webmail_proxy(parsed):
    hosts = set(re.findall(r'<img[^>]+src="https?://([^/"]+)', parsed.body_html, re.I))
    assert "api-mail.walla.co.il" in hosts
    assert any(h.endswith("printernet.co.il") for h in hosts)


def test_gateway_banner_and_subject_tag_present_in_both_parts(parsed):
    assert "[Caution: Suspicious Email!]" in parsed.subject
    assert "reported as malicious" in parsed.body_text and "reported as malicious" in parsed.body_html


def test_per_recipient_tracking_tokens_were_replaced_with_placeholders(parsed):
    checked = 0
    for u in parsed.urls:
        qs = parse_qs(urlparse(u.url).query)
        for key in ("upn", "pt", "ow"):
            for value in qs.get(key, []):
                assert re.fullmatch(r"a+", value), (key, value[:12])
                checked += 1
    assert checked >= 3
    assert not re.search(r"[?&]id=(?!a+(&|$))", PATH.read_text(encoding="utf-8", errors="replace"))
