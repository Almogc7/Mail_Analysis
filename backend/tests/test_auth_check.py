from app.auth_check import run_auth_check
from app.auth_check.spf_dkim_dmarc import check_auth_headers
from app.auth_check.spoofing import check_identity_mismatch
from app.contracts.email import EmailAddress, ParsedEmail

PASS_AUTH_RESULTS = (
    "mx.example.org; spf=pass smtp.mailfrom=example.com; "
    "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
)
FAIL_AUTH_RESULTS = (
    "mx.example.org; spf=fail smtp.mailfrom=evil.example; "
    "dkim=fail; dmarc=fail header.from=evil.example"
)


def _base_parsed_email(**overrides) -> ParsedEmail:
    defaults = dict(
        source_format="eml",
        from_=EmailAddress(display_name="Alice", address="alice@example.com", domain="example.com"),
        raw_size_bytes=100,
    )
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def test_check_auth_headers_parses_pass_results():
    result = check_auth_headers([PASS_AUTH_RESULTS])

    assert result["spf"]["result"] == "pass"
    assert result["dkim"]["result"] == "pass"
    assert result["dmarc"]["result"] == "pass"
    assert result["header_present"] is True


def test_check_auth_headers_handles_missing_header():
    result = check_auth_headers([])

    assert result["spf"]["result"] == "none"
    assert result["header_present"] is False


def test_check_auth_headers_picks_first_as_primary_and_keeps_both():
    result = check_auth_headers([FAIL_AUTH_RESULTS, PASS_AUTH_RESULTS])

    assert result["spf"]["result"] == "fail"
    assert len(result["all_parsed"]) == 2


def test_from_return_path_mismatch_detected():
    parsed = _base_parsed_email(
        return_path=EmailAddress(address="bounce@other-domain.com", domain="other-domain.com"),
    )
    result = check_identity_mismatch(parsed)

    assert result["from_return_path_mismatch"]["mismatch"] is True


def test_from_return_path_no_mismatch_when_domains_match():
    parsed = _base_parsed_email(
        return_path=EmailAddress(address="alice@example.com", domain="example.com"),
    )
    result = check_identity_mismatch(parsed)

    assert result["from_return_path_mismatch"]["mismatch"] is False


def test_display_name_spoofing_detected():
    parsed = _base_parsed_email(
        from_=EmailAddress(
            display_name="PayPal Support",
            address="security@totally-legit-mailer.ru",
            domain="totally-legit-mailer.ru",
        ),
    )
    result = check_identity_mismatch(parsed)

    spoof = result["display_name_spoofing"]
    assert spoof["suspected"] is True
    assert spoof["claimed_brand"] == "paypal"


def test_display_name_spoofing_not_flagged_for_legitimate_sender():
    parsed = _base_parsed_email(
        from_=EmailAddress(display_name="PayPal Support", address="service@paypal.com", domain="paypal.com"),
    )
    result = check_identity_mismatch(parsed)

    assert result["display_name_spoofing"]["suspected"] is False


def test_run_auth_check_produces_findings_for_failed_and_spoofed_email():
    parsed = _base_parsed_email(
        from_=EmailAddress(
            display_name="PayPal Support",
            address="security@totally-legit-mailer.ru",
            domain="totally-legit-mailer.ru",
        ),
        authentication_results_raw=[FAIL_AUTH_RESULTS],
    )
    module_result = run_auth_check(parsed)

    assert module_result.module == "auth_check"
    assert module_result.status == "ok"
    titles = [f.title for f in module_result.findings]
    assert any("SPF check failed" in t for t in titles)
    assert any("spoofing" in t.lower() for t in titles)


def test_run_auth_check_clean_email_has_no_high_severity_findings():
    parsed = _base_parsed_email(
        return_path=EmailAddress(address="alice@example.com", domain="example.com"),
        authentication_results_raw=[PASS_AUTH_RESULTS],
    )
    module_result = run_auth_check(parsed)

    severities = [f.severity for f in module_result.findings]
    assert "high" not in severities
    assert "critical" not in severities
