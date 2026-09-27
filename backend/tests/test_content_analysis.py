from pathlib import Path

from app.content_analysis import run_content_analysis
from app.parser import parse_email_file

FIXTURES = Path(__file__).parent / "fixtures" / "samples"


def _analyze(filename: str):
    raw_bytes = (FIXTURES / filename).read_bytes()
    parsed = parse_email_file(raw_bytes, filename)
    return run_content_analysis(parsed)


def test_urgency_language_detected_with_high_severity():
    result = _analyze("urgency_language.eml")

    urgency_findings = [f for f in result.findings if f.title == "Urgency/pressure language detected"]
    assert len(urgency_findings) == 1
    finding = urgency_findings[0]
    assert finding.severity == "high"
    assert len(finding.evidence["matched_phrases"]) >= 4


def test_generic_greeting_mismatch_detected():
    result = _analyze("generic_greeting_mismatch.eml")

    titles = [f.title for f in result.findings]
    assert "Generic greeting combined with personalized account claim" in titles
    # Same phrase also independently feeds the urgency heuristic.
    assert "Urgency/pressure language detected" in titles


def test_brand_impersonation_in_body_detected():
    result = _analyze("brand_impersonation_body.eml")

    brand_findings = [f for f in result.findings if "claims to be" in f.title]
    assert len(brand_findings) == 1
    finding = brand_findings[0]
    assert "paypal" in finding.title
    assert finding.severity == "high"
    assert finding.evidence["mismatches"][0]["domain"] == "totally-fake.ru"


def test_clean_email_produces_no_content_findings():
    result = _analyze("clean_legit.eml")

    assert result.findings == []


def test_brand_mention_with_plain_esp_link_does_not_trigger_impersonation_finding():
    result = _analyze("brand_mentioned_esp_link_no_mismatch.eml")

    brand_findings = [f for f in result.findings if "claims to be" in f.title]
    assert brand_findings == []


def test_spoofed_display_name_fixture_has_no_extra_content_findings():
    # Module 2 (auth_check) already catches this email's display-name spoofing via the
    # From header. Its body doesn't literally say "PayPal" or have an anchor-mismatched
    # link, so Module 4 should stay silent on brand impersonation -- the two signals
    # should stay properly distinct rather than double-counting the same email.
    result = _analyze("spoofed_display_name.eml")

    brand_findings = [f for f in result.findings if "claims to be" in f.title]
    assert brand_findings == []
