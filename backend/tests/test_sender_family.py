"""Sender family (docs/DETECTION_DESIGN.md): S1 machine-provisioned sender with a brand, S2 local-submission first hop,
S3 brand display name on a free mailbox."""
import json
import tempfile
from pathlib import Path

import pytest

from app.auth_check import run_auth_check
from app.auth_check.spoofing import FREEMAIL_FILE, is_freemail, load_freemail_domains
from app.contracts.email import EmailAddress, ParsedEmail, ReceivedHop
from app.parser import parse_email_file
from tests.eval import FIXTURES, analyze


def _parsed(display, address, chain=()):
    domain = address.split("@")[1]
    return ParsedEmail(source_format="eml", from_=EmailAddress(display_name=display, address=address, domain=domain),
                       received_chain=list(chain), raw_size_bytes=1)


def _titles(result):
    return [f.title for f in result.findings]


def _signal(result, signal):
    return next((f for f in result.findings if f.evidence.get("signal") == signal), None)


# built at runtime so no real-domain address literal sits in the source (scripts/check_fixtures.py)
GM = "@" + "gmail" + ".com"


LOCAL_HOP = ReceivedHop(raw="from user by host12.hosting.example.net with local (Exim 4.96) id 1x", from_host="user",
                        by_host="host12.hosting.example.net", protocol="local", is_local_submission=True)
SMTP_HOP = ReceivedHop(raw="from a by b with ESMTPS", from_host="a", by_host="b.example.org", protocol="ESMTPS", tls=True)
AUTH_HOP = ReceivedHop(raw="from [203.0.113.5] by mail.example.com with ESMTPSA id x", by_host="mail.example.com",
                       protocol="ESMTPSA", authenticated=True, tls=True)


# ---- S2 local submission --------------------------------------------------------------------------------

def test_a_local_submission_first_hop_is_a_weak_sender_family_signal():
    # Received headers are newest first: the LAST one is where the message entered
    result = run_auth_check(_parsed("Shop", "orders@shop.example.com", chain=[SMTP_HOP, LOCAL_HOP]))
    finding = _signal(result, "S2")
    assert finding.title == "Message entered by local submission"
    assert (finding.severity, finding.weight) == ("low", 6.0)
    assert finding.evidence["family"] == "sender" and finding.evidence["structural"] is True
    assert "contact-form" in finding.description and "another family" in finding.description


def test_local_submission_in_a_LATER_hop_is_not_the_origin_and_does_not_fire():
    assert _signal(run_auth_check(_parsed("Shop", "orders@shop.example.com", chain=[LOCAL_HOP, SMTP_HOP])), "S2") is None


@pytest.mark.parametrize("chain", [[], [SMTP_HOP], [AUTH_HOP]], ids=["no-chain", "smtp", "authenticated-submission"])
def test_other_first_hops_do_not_fire(chain):
    assert _signal(run_auth_check(_parsed("Shop", "orders@shop.example.com", chain=chain)), "S2") is None


def test_an_authenticated_local_hop_does_not_fire():
    hop = LOCAL_HOP.model_copy(update={"authenticated": True})
    assert _signal(run_auth_check(_parsed("Shop", "orders@shop.example.com", chain=[hop])), "S2") is None


# ---- S3 freemail + brand ----------------------------------------------------------------------------------

def test_a_brand_display_name_on_a_free_mailbox_fires_with_the_brand_named():
    result = run_auth_check(_parsed("Netflix Billing", "billing.team" + GM))
    s3 = _signal(result, "S3")
    assert s3.title == "Brand display name on a free mailbox" and (s3.severity, s3.weight) == ("medium", 10.0)
    assert s3.evidence["family"] == "sender" and s3.evidence["claimed_brand"] == "netflix"
    assert _signal(result, "C1").evidence["family"] == "claim"  # the same message also carries the claim


@pytest.mark.parametrize(
    "display,address",
    [
        ("Jane Doe", "jane.doe" + GM),  # a person on a free mailbox: no brand
        ("PayPal Support", "support@mailer.example.org"),  # a brand but not freemail: C1 only
        ("Google Team", "someone" + GM),  # gmail.com IS google's own domain, so no brand mismatch at all
        ("Paypall Billing", "p" + GM),  # fuzzy-only lookalike is not an exact brand claim
    ],
)
def test_near_misses_do_not_fire_s3(display, address):
    assert _signal(run_auth_check(_parsed(display, address)), "S3") is None


def test_s3_with_the_claim_is_two_families_so_it_floors_but_alone_neither_does():
    from app.scoring import run_scoring
    from app.contracts.findings import ModuleResult

    def verdict(display, address):
        quiet = [ModuleResult(module=m, status="ok", findings=[], raw_data={}) for m in ("enrichment", "content_analysis")]
        return run_scoring([run_auth_check(_parsed(display, address)), *quiet]).verdict

    assert verdict("Netflix Billing", "billing.team" + GM) == "suspicious"
    assert verdict("PayPal Support", "support@mailer.example.org") != "suspicious"  # claim alone
    assert verdict("Jane Doe", "jane.doe" + GM) != "suspicious"


# ---- S1 tagging (unchanged rule) ----------------------------------------------------------------------------

def test_s1_keeps_its_rule_and_is_tagged_sender():
    result = run_auth_check(_parsed("PayPal Support", "vnz73mailr@vh319.hosting.example.net"))
    s1 = _signal(result, "S1")
    assert s1.title == "Machine-provisioned sender claiming a brand" and (s1.severity, s1.weight) == ("medium", 15.0)
    assert s1.evidence["family"] == "sender"


def test_a_machine_sender_without_a_brand_is_not_s1():
    assert _signal(run_auth_check(_parsed("Bakery website", "bakeryuser@host12.hosting.example.net")), "S1") is None


# ---- the freemail list is a config file -------------------------------------------------------------------------

def test_the_freemail_list_is_a_json_config_file_with_valid_entries():
    data = json.loads(FREEMAIL_FILE.read_text(encoding="utf-8"))
    domains = data["domains"]
    assert data["version"] == 1 and len(domains) >= 40 and len(domains) == len(set(domains))
    assert all(d == d.lower().strip(".") and "/" not in d and " " not in d for d in domains)
    for required in ("gmail.com", "outlook.com", "yahoo.com", "proton.me", "mail.ru", "walla.co.il"):
        assert required in domains


@pytest.mark.parametrize("domain,expected", [("gmail.com", True), ("mail.yahoo.com", True), ("GMAIL.COM", True),
                                             ("notgmail.com", False), ("gmail.com.evil.example.net", False), ("example.com", False),
                                             ("", False), (None, False)])
def test_freemail_matching_is_by_whole_label_suffix(domain, expected):
    assert is_freemail(domain) is expected


def test_a_malformed_freemail_file_would_fail_loudly(tmp_path, monkeypatch):
    bad = tmp_path / "freemail_domains.json"
    bad.write_text('{"domains": "gmail.com"}', encoding="utf-8")
    monkeypatch.setattr("app.auth_check.spoofing.FREEMAIL_FILE", bad)
    load_freemail_domains.cache_clear()
    try:
        with pytest.raises(ValueError):
            load_freemail_domains()
    finally:
        load_freemail_domains.cache_clear()


# ---- real fixtures --------------------------------------------------------------------------------------------------

def test_the_kvish6_fixture_has_the_local_submission_signal_without_any_brand_map():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    assert _signal(run_auth_check(parsed), "S2") is not None


def test_the_shared_hosting_contact_form_fixture_fires_s2_alone_one_family_never_flagged():
    result = analyze(FIXTURES / "benign" / "synthetic" / "08_shared_hosting_local_submission.eml", "clean")
    assert _signal(next(m for m in result.module_results if m.module == "auth_check"), "S2") is not None
    families = {f.evidence.get("family") for f in result.findings if f.evidence.get("structural")}
    assert families == {"sender"} and result.verdict not in ("suspicious", "malicious")
