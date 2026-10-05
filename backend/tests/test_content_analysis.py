from pathlib import Path

from app.content_analysis import run_content_analysis
from app.content_analysis.text_utils import estimate_script_coverage
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


def test_clean_email_produces_no_scoring_content_findings():
    result = _analyze("clean_legit.eml")

    # Nothing that scores. A short message may carry an informational language note (weight 0), nothing else.
    assert [f for f in result.findings if f.severity != "info" or f.weight > 0] == []


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


# --- script coverage (found via a real Hebrew phishing email that scored "benign") ---


def test_estimate_script_coverage_supported_languages_return_full_coverage():
    # English and Hebrew have real phrase-list entries, so both get full coverage -- given enough text to tell.
    english = "Please verify your account immediately because we have noticed that you are not able to sign in to this service."
    assert estimate_script_coverage(english) == 1.0
    assert estimate_script_coverage("אנא אשר את פרטי החשבון שלך בהקדם האפשרי לפני שהחשבון ייחסם") == 1.0


def test_estimate_script_coverage_unsupported_script_returns_reduced_coverage():
    # Russian/Cyrillic has no phrase-list entries -- coverage should reflect that the
    # heuristics genuinely can't check this content, not silently claim full confidence.
    russian = "Пожалуйста, подтвердите свою учетную запись немедленно, иначе она будет заблокирована"
    assert estimate_script_coverage(russian) == 0.25


def test_estimate_script_coverage_tiny_or_empty_text_is_not_full_coverage():
    # Little or no text means content analysis had (almost) nothing to read: that is not "checked and clean".
    assert estimate_script_coverage("hi") == 0.5
    assert estimate_script_coverage("") == 0.25


def test_hebrew_invoice_phishing_fixture_reports_full_coverage_and_no_longer_matches_the_removed_seed_phrase():
    # The fixture is wording from a real phishing email: Hebrew "valid for one month only" expiry pressure. Hebrew is a supported script, so coverage
    # reads as full (1.0) -- the reduced-coverage path is for scripts without any phrase-list entries (see the Russian test above). That one phrase
    # came from a single sample and was removed from the shipped lexicon (docs/DESIGN_V2.md, D13), so it no longer produces an urgency finding.
    result = _analyze("hebrew_invoice_phishing.eml")

    assert "Urgency/pressure language detected" not in [f.title for f in result.findings]
    assert result.raw_data["script_coverage"] == 1.0


def test_hebrew_urgency_is_still_detected_from_the_phrases_that_remain_in_the_lexicon():
    from app.content_analysis.urgency import URGENCY_PHRASES, detect_urgency

    removed, kept = "תקף לחודש בלבד", "נדרשת פעולה מיידית"
    assert removed not in URGENCY_PHRASES  # the single-sample seed phrase is gone
    assert kept in URGENCY_PHRASES and len([p for p in URGENCY_PHRASES if any("֐" <= ch <= "׿" for ch in p)]) >= 5
    assert detect_urgency(removed) == [] and detect_urgency(kept) == [kept]
    head = ["From: a@sender.example.org", "To: t@example.com", "Subject: x", "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: 8bit", "", "שלום, " + kept + " בחשבון שלך.", ""]
    raw = chr(13).join(head).replace(chr(13), chr(13) + chr(10)).encode("utf-8")
    result = run_content_analysis(parse_email_file(raw, "he.eml"))
    assert "Urgency/pressure language detected" in [f.title for f in result.findings]
