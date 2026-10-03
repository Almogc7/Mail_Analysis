import pytest

from app.auth_check import run_auth_check
from app.auth_check.spoofing import check_identity_mismatch
from app.contracts.email import EmailAddress, ParsedEmail
from app.scoring import run_scoring
from app.shared.brands import KNOWN_BRANDS
from app.shared.matching import domain_matches_any, find_brand_matches, registrable_domain


def _brands(text):
    return {(m.brand, m.kind, m.via) for m in find_brand_matches(text, KNOWN_BRANDS)}


@pytest.mark.parametrize(
    "name",
    [
        "Example Weekly", "Example Store", "Example Account", "Maple Leaf Foods", "Ample Hills Creamery",
        "Pineapple Bistro", "Pineapple Weekly", "Grapple Fitness", "Applebee's", "Fibonacci Books",
        "Discount Tires Direct", "DHLR Logistics", "Chasetown Dental", "Googleplex Realty",
    ],
)
def test_near_miss_names_never_match_a_brand(name):
    # A brand must never match as a substring of a longer word, nor via a loose fuzzy ratio.
    assert _brands(name) == set()


@pytest.mark.parametrize(
    "name,brand,via",
    [
        ("PayPal Support", "paypal", "plain"),
        ("Apple Support", "apple", "plain"),  # short brand: exact whole token
        ("Microsoft365 Billing", "microsoft", "plain"),  # digits stripped
        ("kvish6 (810635)", "kvish6", "plain"),  # seed brand; digit stripped on both sides
        ("Bank of America Alerts", "bank of america", "plain"),
        ("Ｐａｙｐａｌ Support", "paypal", "plain"),  # fullwidth -> NFKC
        ("Pаypal Security", "paypal", "homoglyph"),  # Cyrillic а
        ("PayPa1 Service", "paypal", "leet"),
        ("M1crosoft Team", "microsoft", "leet"),
    ],
)
def test_exact_whole_token_matches(name, brand, via):
    assert (brand, "exact", via) in _brands(name)


def test_fuzzy_only_for_long_tokens_and_distance_one():
    assert ("paypal", "fuzzy", "plain") in _brands("Paypall Billing")  # 7 chars, distance 1
    assert _brands("Paypa Billing") == set()  # 5-char candidate: below the fuzzy minimum
    assert _brands("Appel Support") == set()  # short brand "apple": exact only, never fuzzy
    assert _brands("Paypalll Billing") == set()  # distance 2


def test_registrable_domain_and_lookalike_domains():
    assert registrable_domain("vh319.sweb.ru") == "sweb.ru"
    assert registrable_domain("service.kvish6.co.il") == "kvish6.co.il"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert domain_matches_any("mail.paypal.com", ["paypal.com"])
    assert not domain_matches_any("paypal.com.evil.example.net", ["paypal.com"])
    assert not domain_matches_any("notpaypal.com", ["paypal.com"])
    assert not domain_matches_any(None, ["paypal.com"])


def _from(display, address):
    return EmailAddress(display_name=display, address=address, domain=address.split("@")[1])


def _spoof(display, address):
    parsed = ParsedEmail(source_format="eml", from_=_from(display, address), raw_size_bytes=1)
    return check_identity_mismatch(parsed)["display_name_spoofing"]


def test_exact_brand_with_non_brand_sender_is_suspected():
    s = _spoof("PayPal Support", "support@mailer.example.org")
    assert s["suspected"] and s["match_type"] == "exact" and not s["fuzzy_suspected"]
    assert s["actual_registrable_domain"] == "example.org"


def test_homoglyph_and_freemail_are_suspected():
    assert _spoof("Pаypal Security", "x@mailer.example.org")["normalization"] == "homoglyph"
    assert _spoof("Netflix Billing", "billing@gmail.com")["suspected"]


@pytest.mark.parametrize("address", ["service@paypal.com", "service@mail.paypal.com"])
def test_exact_brand_with_legit_sender_domain_is_not_suspected(address):
    s = _spoof("PayPal Support", address)
    assert not s["suspected"] and not s["fuzzy_suspected"]


def test_brand_lookalike_sender_domain_is_not_legit():
    assert _spoof("PayPal Support", "service@paypal.com.evil.example.net")["suspected"]


def test_fuzzy_only_match_is_medium_finding_without_floor():
    parsed = ParsedEmail(source_format="eml", from_=_from("Paypall Billing", "b@mailer.example.org"), raw_size_bytes=1)
    result = run_auth_check(parsed)
    spoof_findings = [f for f in result.findings if "brand" in f.title.lower()]
    assert [f.severity for f in spoof_findings] == ["medium"]
    outcome = run_scoring([result])
    assert outcome.verdict == "inconclusive"  # not flagged; inconclusive (no positive evidence)
    assert not any(o.rule == "auth_check_floor" for o in outcome.breakdown.applied_overrides)
