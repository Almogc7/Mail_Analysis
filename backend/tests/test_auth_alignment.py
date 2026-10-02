"""From / envelope / DKIM alignment findings and their wording (auth_check/alignment.py)."""
import pytest

from app.auth_check import run_auth_check
from app.contracts.email import EmailAddress, ParsedEmail, ReceivedHop
from app.parser import parse_email_file
from tests.eval import FIXTURES

MX = r"^mx\.example\.org$"
ESA = r"^esa1\.gateway\.example\.net$"
HOP = ReceivedHop(raw="from x by mx.example.org with ESMTPS", from_host="x", by_host="mx.example.org")


def _email(from_domain="example.com", ar=None, **kw):
    base = dict(
        source_format="eml",
        from_=EmailAddress(display_name="News", address=f"news@{from_domain}", domain=from_domain),
        raw_size_bytes=1,
        authentication_results_raw=[ar] if ar else [],
        received_chain=[HOP],
    )
    base.update(kw)
    return ParsedEmail(**base)


def _titles(result):
    return [f.title for f in result.findings]


def _kvish():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    return parse_email_file(path.read_bytes(), path.name)


def test_kvish6_trusted_spf_pass_says_what_alignment_proves_and_what_it_does_not(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [ESA])
    result = run_auth_check(_kvish())
    finding = next(f for f in result.findings if f.title == "SPF passed and aligns with the From domain")
    assert finding.weight == 0.0 and finding.severity == "info"
    assert "authenticated the sending infrastructure only" in finding.description
    assert "'sweb.ru'" in finding.description and "envelope domain equals the From domain" in finding.description
    assert "does not show" in finding.description and "attacker authorises their own servers" in finding.description
    assert "No authentication is aligned with the From domain" not in _titles(result)  # DKIM not evaluated


def test_alignment_is_recorded_even_when_nothing_is_trusted(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    result = run_auth_check(_kvish())
    alignment = result.raw_data["alignment"]
    assert alignment["envelope_registrable_domain"] == "sweb.ru" and alignment["from_registrable_domain"] == "sweb.ru"
    assert alignment["envelope_equals_from"] is True and alignment["envelope_source"] == "first-hop envelope-from"
    assert alignment["spf"]["evaluated"] is False and alignment["spf"]["aligned"] is None
    assert not [t for t in _titles(result) if "aligns" in t or "aligned" in t or "different domain" in t]


def test_relaxed_alignment_subdomains_of_the_same_registrable_domain_align(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.mail.example.com; dkim=none; dmarc=none"
    result = run_auth_check(_email(from_domain="mail.example.com", ar=ar))
    assert "SPF passed and aligns with the From domain" in _titles(result)


def test_esp_with_aligned_dkim_is_informational_only(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.esp.example.net; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    result = run_auth_check(_email(ar=ar))
    titles = _titles(result)
    assert "SPF passed for a different domain than From" in titles
    assert "DKIM passed and aligns with the From domain" in titles
    assert "No authentication is aligned with the From domain" not in titles
    informational = {"SPF passed for a different domain than From", "DKIM passed and aligns with the From domain"}
    assert {f.weight for f in result.findings if f.title in informational} == {0.0}
    assert sum(1 for f in result.findings if f.title in informational) == 2


def test_nothing_aligned_with_both_evaluated_is_a_medium_finding(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.esp.example.net; dkim=pass header.d=esp.example.net; dmarc=none"
    finding = next(f for f in run_auth_check(_email(ar=ar)).findings if f.title == "No authentication is aligned with the From domain")
    assert finding.severity == "medium" and finding.weight == 10.0
    assert "esp.example.net" in finding.description and "Nothing ties the visible sender" in finding.description


def test_unsigned_mail_with_spf_for_another_domain_is_also_flagged(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.esp.example.net; dkim=none; dmarc=none"
    finding = next(f for f in run_auth_check(_email(ar=ar)).findings if f.title == "No authentication is aligned with the From domain")
    assert "no usable DKIM signature" in finding.description


def test_spf_fail_does_not_also_get_a_no_alignment_finding(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [MX])
    ar = "mx.example.org; spf=fail smtp.mailfrom=bounce.esp.example.net; dkim=none; dmarc=none"
    titles = _titles(run_auth_check(_email(ar=ar)))
    assert "SPF check failed" in titles and "No authentication is aligned with the From domain" not in titles


def test_untrusted_headers_produce_no_alignment_conclusions(monkeypatch):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", [])
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.esp.example.net; dkim=pass header.d=esp.example.net; dmarc=none"
    titles = _titles(run_auth_check(_email(ar=ar)))
    assert "No authentication is aligned with the From domain" not in titles
    assert "SPF passed for a different domain than From" not in titles


@pytest.mark.parametrize("trusted", [[], [MX]])
def test_only_the_no_alignment_finding_ever_carries_weight(monkeypatch, trusted):
    monkeypatch.setattr("app.config.TRUSTED_RECEIVER_PATTERNS", trusted)
    ar = "mx.example.org; spf=pass smtp.mailfrom=bounce.esp.example.net; dkim=pass header.d=esp.example.net; dmarc=none"
    for f in run_auth_check(_email(ar=ar)).findings:
        if any(k in f.title for k in ("passed", "aligns", "not evaluated", "ignored")):
            assert f.weight == 0.0, f.title
