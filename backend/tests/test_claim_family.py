"""Claim family (docs/DETECTION_DESIGN.md): C1b body brand mention (additive), C2 claimed-entity mismatch, C3 decoy links.
Brand aliases come from the untracked local brand file."""
import json

import pytest

from app.auth_check import run_auth_check
from app.auth_check.claims import (
    GENERIC_WORDS, body_brand_mentions, claim_findings, claimed_entity_mismatch, decoy_links, dominant_foreign_domain,
    verified_aligned_pass,
)
from app.contracts.email import EmailAddress, ExtractedUrl, HeaderField, ImageRef, ParsedEmail
from app.shared import brands as brands_module
from app.shared.brands import load_local_brands
from tests.eval import FIXTURES, analyze, apply_mode

NO_AUTH: dict = {}
NO_ALIGN: dict = {}


def _email(urls=(), images=(), sender="news@mail.example.com", display="Weekly News", subject="Hello", headers=(), body="", return_path=None):
    domain = sender.split("@")[1]
    return ParsedEmail(
        source_format="eml", subject=subject, body_text=body or None, from_=EmailAddress(display_name=display, address=sender, domain=domain),
        urls=[ExtractedUrl(url=u, source="body_html") for u in urls], images=[ImageRef(url=u) for u in images],
        headers=[HeaderField(name=n, value=v) for n, v in headers],
        return_path=EmailAddress(address=return_path, domain=return_path.split("@")[1]) if return_path else None, raw_size_bytes=1)


def _signals(findings):
    return sorted(f.evidence["signal"] for f in findings if f.evidence.get("signal"))


FOREIGN = ["https://www.example.org/a", "https://www.example.org/b"]


# ---- C2 --------------------------------------------------------------------------------------------------------

def test_a_foreign_dominant_domain_on_an_unsigned_message_fires_without_any_brand_list():
    result = claimed_entity_mismatch(_email(urls=FOREIGN, images=["https://img.example.org/x.png"]), NO_AUTH, NO_ALIGN)
    assert result["domain"] == "example.org" and result["occurrences"] == 3 and result["dkim_signature_present"] is False


def test_any_dkim_signature_header_suppresses_c2_it_is_only_a_claim():
    mail = _email(urls=FOREIGN, headers=[("DKIM-Signature", "v=1; d=mail.example.com; s=x; b=y")])
    assert claimed_entity_mismatch(mail, NO_AUTH, NO_ALIGN) is None
    # even a signature from an unrelated domain, which proves nothing about the sender, hides it: the documented evasion
    assert claimed_entity_mismatch(_email(urls=FOREIGN, headers=[("DKIM-Signature", "d=other.example.net; b=y")]), NO_AUTH, NO_ALIGN) is None


def test_a_verified_aligned_pass_from_a_trusted_receiver_is_the_stronger_negative():
    mail = _email(urls=FOREIGN)  # unsigned, but DMARC passed through SPF alignment at a trusted receiver
    assert claimed_entity_mismatch(mail, {"dmarc": {"evaluated": True, "result": "pass"}}, NO_ALIGN) is None
    assert verified_aligned_pass({"dkim": {"evaluated": True, "result": "pass"}}, {"dkim": {"aligned": True}}) is True
    assert verified_aligned_pass({"dkim": {"evaluated": True, "result": "pass"}}, {"dkim": {"aligned": False}}) is False
    assert verified_aligned_pass({"dkim": {"evaluated": False, "result": "pass"}}, {"dkim": {"aligned": True}}) is False  # untrusted claim


@pytest.mark.parametrize(
    "mail",
    [
        _email(urls=["https://www.mail.example.com/a", "https://www.mail.example.com/b"]),  # the sender's own domain
        _email(urls=["https://u1.ct.sendgrid.net/a", "https://u1.ct.sendgrid.net/b"]),  # shared platform
        _email(urls=["https://www.example.org/a"]),  # one occurrence
        _email(urls=["https://www.example.org/a", "https://www.example.net/a", "https://www.example.info/a"]),  # not dominant / not repeated
        _email(urls=FOREIGN, return_path="x@bounce.example.org"),  # related to the Return-Path domain
        _email(urls=["https://www.mail.example.com/a"], images=["https://stock.example.org/1.png", "https://stock.example.org/2.png",
                                                              "https://stock.example.org/3.png"]),  # images only: not reachable
    ],
    ids=["own-domain", "platform", "single", "not-dominant", "return-path-related", "images-only-cdn"],
)
def test_near_misses_do_not_fire_c2(mail):
    assert claimed_entity_mismatch(mail, NO_AUTH, NO_ALIGN) is None


def test_images_count_toward_dominance_when_a_link_is_on_the_same_domain():
    mail = _email(urls=["https://www.example.org/x", "https://www.mail.example.com/y"],
                  images=["https://img.example.org/1.png", "https://img.example.org/2.png"])
    assert dominant_foreign_domain(mail)["occurrences"] == 3


# ---- C3 --------------------------------------------------------------------------------------------------------

def test_a_display_name_token_that_names_a_linked_domain_fires_without_a_brand_list():
    mail = _email(urls=["https://www.brandly.co.uk/x"], display="brandly6 (123456)", sender="svc@host12.hosting.example.net")
    result = decoy_links(mail)
    assert result["matches_display_or_subject"] == ["brandly.co.uk"] and result["claimed_brand_links"] == []


def test_the_subject_works_like_the_display_name_and_digits_are_stripped():
    mail = _email(urls=["https://www.brandly.co.uk/x"], display="Orders", subject="Brandly2026 invoice")
    assert decoy_links(mail)["matches_display_or_subject"] == ["brandly.co.uk"]


@pytest.mark.parametrize(
    "mail",
    [
        _email(urls=["https://www.brandly.co.uk/x"], display="Brandly", sender="hello@brandly.co.uk"),  # the sender's own domain
        _email(urls=["https://www.brandly.co.uk/x"], display="Weekly News"),  # no token names it
        _email(urls=["https://www.example.org/x"], display="Example Weekly"),  # token equals the SENDER's own label (example.com)
        _email(urls=["https://www.news.co.uk/x"], display="News Update"),  # generic words
        _email(urls=["https://www.abc.co.uk/x"], display="ABC Team"),  # token shorter than 4 letters
        _email(urls=["https://u1.ct.sendgrid.net/x"], display="Sendgrid Fan"),  # shared platform
    ],
    ids=["own-domain", "no-token", "sender-label", "generic", "short", "platform"],
)
def test_near_misses_do_not_fire_c3(mail):
    assert decoy_links(mail) is None


def test_a_bare_link_to_a_known_brand_is_not_enough_the_claim_is_required():
    # every newsletter links to social networks and app stores
    assert decoy_links(_email(urls=["https://www.facebook.com/page", "https://www.linkedin.com/company/x"])) is None
    claimed = _email(urls=["https://www.paypal.com/signin"], display="PayPal Support", sender="help@mailer.example.org")
    result = decoy_links(claimed)
    assert result["claimed_brand_links"] == [{"brand": "paypal", "link_host": "www.paypal.com"}]


def test_the_claimed_brand_from_its_own_domain_is_not_a_decoy():
    assert decoy_links(_email(urls=["https://www.paypal.com/x"], display="PayPal", sender="service@paypal.com")) is None


def test_the_stop_list_is_lowercase_whole_words():
    assert all(w == w.lower() and w.isalpha() and len(w) >= 4 for w in GENERIC_WORDS)


# ---- C1b --------------------------------------------------------------------------------------------------------

def test_a_body_brand_mention_is_additive_info_and_never_structural():
    findings = claim_findings(_email(body="Did you see the new PayPal feature?"), NO_AUTH, NO_ALIGN)
    c1b = next(f for f in findings if f.evidence["signal"] == "C1b")
    assert (c1b.severity, c1b.weight) == ("info", 3.0) and not c1b.evidence.get("structural") and "family" not in c1b.evidence


def test_a_brand_already_claimed_in_the_display_name_is_not_also_a_body_mention():
    mail = _email(display="PayPal Support", sender="help@mailer.example.org", body="Your PayPal account")
    assert body_brand_mentions(mail) == []


def test_the_brands_own_sender_domain_is_not_a_body_mention():
    assert body_brand_mentions(_email(sender="service@paypal.com", body="Your PayPal account")) == []


# ---- the findings ----------------------------------------------------------------------------------------------

def test_findings_carry_the_pre_registered_severity_weight_and_family():
    mail = _email(urls=["https://www.brandly.co.uk/a", "https://www.brandly.co.uk/b"], images=["https://img.brandly.co.uk/x.png"],
                  display="Brandly", sender="svc@host12.hosting.example.net", body="PayPal")
    by = {f.evidence["signal"]: f for f in claim_findings(mail, NO_AUTH, NO_ALIGN)}
    assert set(by) == {"C1b", "C2", "C3"}
    assert (by["C2"].severity, by["C2"].weight) == ("low", 8.0) and (by["C3"].severity, by["C3"].weight) == ("medium", 10.0)
    assert all(by[s].evidence["family"] == "claim" and by[s].evidence["structural"] is True and by[s].module == "auth_check" for s in ("C2", "C3"))


def test_run_auth_check_includes_the_claim_findings():
    mail = _email(urls=FOREIGN)
    assert "C2" in _signals(run_auth_check(mail).findings)


def test_claim_plus_sender_floors_but_claim_alone_does_not():
    from app.contracts.findings import ModuleResult
    from app.scoring import run_scoring

    def verdict(mail):
        quiet = [ModuleResult(module=m, status="ok", findings=[], raw_data={}) for m in ("enrichment", "content_analysis")]
        return run_scoring([run_auth_check(mail), *quiet]).verdict

    assert verdict(_email(urls=FOREIGN)) != "suspicious"  # C2 alone: one family
    assert verdict(_email(urls=FOREIGN, sender="x@host12.hosting.example.net", display="PayPal Support")) == "suspicious"  # C1+C2 (claim) + S1 (sender)


# ---- aliases live in the untracked local file ---------------------------------------------------------------------

def test_aliases_in_the_local_file_become_brand_keys_with_the_same_domains(tmp_path):
    f = tmp_path / "brands.local.json"
    f.write_text(json.dumps({"highway six": {"domains": ["h6.example"], "aliases": ["כביש 6", "Kvish Shesh"]}, "plain": ["plain.example"]}, ensure_ascii=False),
                 encoding="utf-8")
    loaded = load_local_brands(f)
    assert loaded == {"highway six": ["h6.example"], "כביש 6": ["h6.example"], "kvish shesh": ["h6.example"], "plain": ["plain.example"]}


@pytest.mark.parametrize("bad", ['{"b": {"domains": "x.example"}}', '{"b": {"domains": ["x.example"], "aliases": "a"}}',
                                 '{"b": {"domains": ["x.example"], "aliases": [1]}}', '{"b": 5}', '[1]', '{"b": {"aliases": ["a"]}}'])
def test_a_malformed_alias_entry_fails_loudly(tmp_path, bad):
    f = tmp_path / "b.json"
    f.write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError):
        load_local_brands(f)


def test_an_alias_in_the_display_name_is_a_brand_claim_exactly_like_the_brand_name(monkeypatch):
    from app.shared.brands import KNOWN_BRANDS

    monkeypatch.setitem(KNOWN_BRANDS, "כביש 6", ["h6road.co.il"])
    mail = _email(urls=["https://www.h6road.co.il/pay"], display="כביש 6 - חשבונית", sender="svc@host12.hosting.example.net")
    assert "C3" in _signals(claim_findings(mail, NO_AUTH, NO_ALIGN))  # form (b): claimed alias + link to its real domain


def test_tracked_brand_code_contains_no_org_specific_aliases():
    source = open(brands_module.__file__, encoding="utf-8").read()
    assert "aliases" in source and "כביש" not in source  # the mechanism is tracked; the Hebrew/org names are not


# ---- fixtures -------------------------------------------------------------------------------------------------------

BENIGN_CLAIM = ["23_brand_own_aligned_domain_own_cdn", "24_small_business_name_matches_brand_token",
                "25_small_business_brand_token_own_click_tracker", "26_small_business_brand_token_esp_tracker_and_app_store"]


@pytest.mark.parametrize("mode", ["strict", "configured"])
@pytest.mark.parametrize("name", BENIGN_CLAIM)
def test_the_benign_claim_fixtures_stay_below_suspicious(name, mode):
    apply_mode(mode)
    result = analyze(FIXTURES / "benign" / "synthetic" / f"{name}.eml", "clean")
    assert result.verdict not in ("suspicious", "malicious")


def test_apple_valley_dental_fires_c1_only_with_or_without_a_click_tracker():
    apply_mode("strict")
    for name in BENIGN_CLAIM[1:3]:
        result = analyze(FIXTURES / "benign" / "synthetic" / f"{name}.eml", "clean")
        assert {f.evidence["signal"] for f in result.findings if f.evidence.get("structural")} == {"C1"}


def test_a_brand_link_next_to_a_brand_token_claim_is_still_only_the_claim_family():
    apply_mode("strict")
    result = analyze(FIXTURES / "benign" / "synthetic" / "26_small_business_brand_token_esp_tracker_and_app_store.eml", "clean")
    structural = {f.evidence["signal"]: f.evidence["family"] for f in result.findings if f.evidence.get("structural")}
    assert structural == {"C1": "claim", "C3": "claim"} and result.verdict == "inconclusive"


@pytest.mark.xfail(strict=True, reason=(
    "KNOWN FALSE POSITIVE, reported not tuned: a third-party sender acting for a brand (agency / ESP on its own domain) that "
    "links and hot-links the brand's site is structurally the same as a cloned brand template sent from an unrelated origin: "
    "C3 (claim) + L2 (link) are two families. DKIM-Signature present does not matter here (C2 is silent); only a known-sender "
    "exemption could separate them, and that is the owner's decision. strict=True: this test starts failing when it is fixed."))
@pytest.mark.parametrize("mode", ["strict", "configured"])
def test_newsletter_sent_by_a_third_party_for_a_brand_stays_below_suspicious(mode):
    apply_mode(mode)
    result = analyze(FIXTURES / "benign" / "synthetic" / "22_newsletter_sender_differs_from_brand_link_domain_dkim.eml", "clean")
    assert result.verdict not in ("suspicious", "malicious")


def test_that_known_false_positive_is_exactly_c3_plus_l2_and_c2_is_silent():
    apply_mode("strict")
    result = analyze(FIXTURES / "benign" / "synthetic" / "22_newsletter_sender_differs_from_brand_link_domain_dkim.eml", "clean")
    structural = {f.evidence["signal"]: f.evidence["family"] for f in result.findings if f.evidence.get("structural")}
    assert structural == {"C3": "claim", "L2": "link"}  # C2 is silent because the DKIM-Signature is present
    assert result.verdict == "suspicious"


@pytest.mark.parametrize("mode", ["strict", "configured"])
def test_every_other_benign_fixture_stays_below_suspicious(mode):
    apply_mode(mode)
    flagged = {p.name for p in sorted((FIXTURES / "benign").rglob("*.eml"))
               if analyze(p, "clean").verdict in ("suspicious", "malicious")}
    assert flagged == {"22_newsletter_sender_differs_from_brand_link_domain_dkim.eml"}


def test_kvish_ablated_now_also_carries_a_claim_signal_from_the_display_name_alone(monkeypatch):
    from app.content_analysis import brand_impersonation
    from app.shared import brands

    monkeypatch.delitem(brands.KNOWN_BRANDS, "kvish6", raising=False)
    monkeypatch.delitem(brand_impersonation._BRAND_PATTERNS, "kvish6", raising=False)
    apply_mode("strict")
    result = analyze(FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "clean")
    signals = {f.evidence["signal"]: f.evidence["family"] for f in result.findings if f.evidence.get("structural")}
    assert result.verdict == "suspicious" and signals["C3"] == "claim" and {"sender", "link", "claim"} <= set(signals.values())
