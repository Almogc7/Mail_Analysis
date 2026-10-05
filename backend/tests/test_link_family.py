"""Link family (docs/DETECTION_DESIGN.md): L1 platform-mismatched click tracker, L2 hot-linked third-party assets,
L3 redirector chain. Weak, one family; they matter next to a second family."""
import pytest

from app.content_analysis import run_content_analysis
from app.content_analysis.links import (
    hot_linked_assets, link_findings, platform_mismatched_trackers, redirector_links, sending_path,
)
from app.contracts.email import EmailAddress, ExtractedUrl, HeaderField, ImageRef, ParsedEmail, ReceivedHop, ReceivedSpf
from tests.eval import FIXTURES, analyze, apply_mode

SG = "https://u1.ct.sendgrid.net/ls/click?upn=x"  # a SendGrid click tracker (esp_tracker in the shared-platform list)


def _hop(by=None, frm=None, **kw):
    return ReceivedHop(raw="r", by_host=by, from_host=frm, **kw)


LOCAL = _hop(by="host12.hosting.example.net", frm="user", protocol="local", is_local_submission=True)
NETWORK = _hop(by="mx.example.org", frm="mta.mail.example.net", protocol="ESMTPS")


def _email(urls=(), images=(), chain=(), headers=(), sender="news@mail.example.com", display="Weekly News", subject="Hello",
           return_path=None, message_id=None, spf=()):
    domain = sender.split("@")[1]
    return ParsedEmail(
        source_format="eml", subject=subject, from_=EmailAddress(display_name=display, address=sender, domain=domain),
        urls=[ExtractedUrl(url=u, source="body_html") for u in urls], images=[ImageRef(url=u) for u in images],
        received_chain=list(chain), headers=[HeaderField(name=n, value=v) for n, v in headers],
        return_path=EmailAddress(address=return_path, domain=return_path.split("@")[1]) if return_path else None,
        message_id=message_id, received_spf=list(spf), raw_size_bytes=1)


# ---- L1 -----------------------------------------------------------------------------------------------------

def test_a_tracker_with_a_local_submission_origin_and_no_platform_in_the_path_fires():
    mail = _email(urls=[SG], chain=[NETWORK, LOCAL], sender="owner@owner.example.net")
    result = platform_mismatched_trackers(mail)
    assert result["platforms"] == ["SendGrid"] and result["local_submission_origin"] is True
    assert result["tracker_hosts"] == {"SendGrid": ["u1.ct.sendgrid.net"]}


@pytest.mark.parametrize(
    "path",
    [
        dict(chain=[_hop(by="mx.example.org", frm="o3.ct.sendgrid.net")]),  # the platform's relay in the Received hops
        dict(chain=[_hop(by="o3.ct.sendgrid.net", frm="app")]),  # ... on the by side
        dict(chain=[NETWORK], headers=[("DKIM-Signature", "v=1; a=rsa-sha256; d=sendgrid.net; s=s1; b=x")]),  # DKIM d=
        dict(chain=[NETWORK], return_path="bounce@" + "bounces.sendgrid.net"),  # envelope domain
        dict(chain=[NETWORK], headers=[("List-Unsubscribe", "<https://u1.ct.sendgrid.net/unsub/1>")]),  # unsubscribe host
        dict(chain=[NETWORK], message_id="<abc@" + "o3.sendgrid.net>"),  # Message-ID domain
        dict(chain=[NETWORK], spf=[ReceivedSpf(result="pass", raw="r", header_index=0, envelope_from="x@" + "em.sendgrid.net")]),
        dict(chain=[LOCAL], return_path="x@" + "sendgrid.net"),  # even with a local origin: the platform IS in the path
    ],
    ids=["hop-from", "hop-by", "dkim-d", "envelope", "list-unsubscribe", "message-id", "received-spf", "local-but-envelope-matches"],
)
def test_a_tracker_whose_platform_appears_anywhere_in_the_sending_path_does_not_fire(path):
    assert platform_mismatched_trackers(_email(urls=[SG], sender="owner@owner.example.net", **path)) is None


def test_the_tracker_matching_is_by_platform_or_registrable_domain_not_a_fixed_pairing():
    # a different platform's relay in the path does not vouch for this tracker
    mail = _email(urls=[SG], chain=[_hop(by="x", frm="smtp.mailgun.org"), LOCAL], sender="owner@owner.example.net")
    assert platform_mismatched_trackers(mail)["platforms"] == ["SendGrid"]


def test_no_sending_path_at_all_means_no_judgement():
    assert platform_mismatched_trackers(_email(urls=[SG], chain=[])) is None  # stripped headers: not decidable


def test_a_branded_esp_send_over_the_network_is_not_a_mismatch():
    # return-path and DKIM on the From domain, mail arrived over SMTP: the standard branded-ESP setup
    mail = _email(urls=[SG], chain=[NETWORK], sender="hello@shop.example.com", return_path="bounce@em1.shop.example.com",
                  headers=[("DKIM-Signature", "v=1; d=shop.example.com; s=s1; b=x")])
    assert platform_mismatched_trackers(mail) is None


def test_a_network_origin_with_a_path_unrelated_to_the_sender_still_fires():
    mail = _email(urls=[SG], chain=[NETWORK], sender="hello@shop.example.com", return_path="x@elsewhere.example.org")
    result = platform_mismatched_trackers(mail)
    assert result["platforms"] == ["SendGrid"] and result["path_aligned_with_sender"] is False


def test_only_trackers_count_not_wrappers_shorteners_or_own_domain_tracking():
    for url in ("https://eur01.safelinks.protection.outlook.com/?url=x", "https://urldefense.com/v3/__x__", "https://bit.ly/abc",
                "https://track.owner.example.net/c/1", "https://docs.google.com/d/1"):
        assert platform_mismatched_trackers(_email(urls=[url], chain=[LOCAL], sender="owner@owner.example.net")) is None, url


def test_attachments_are_never_read_for_trackers():
    mail = _email(chain=[LOCAL], sender="owner@owner.example.net")
    mail.urls = [ExtractedUrl(url=SG, source="attachment")]
    assert platform_mismatched_trackers(mail) is None


def test_sending_path_collects_every_element():
    mail = _email(chain=[_hop(by="a.example.org", frm="b.example.net", envelope_from="u@c.example.net")],
                  headers=[("DKIM-Signature", "v=1; d=D.example.com ;s=x"), ("DKIM-Signature", "d=e.example.com; s=y"),
                           ("List-Unsubscribe", "<https://u.example.org/x>, <mailto:u@example.org>")],
                  return_path="r@rp.example.com", message_id="<m@mid.example.com>")
    path = sending_path(mail)
    assert path["received_hops"] == {"a.example.org", "b.example.net"}
    assert path["dkim_d"] == {"d.example.com", "e.example.com"}
    assert path["envelope"] == {"c.example.net", "rp.example.com"}
    assert path["list_unsubscribe"] == {"u.example.org"} and path["message_id"] == {"mid.example.com"}


# ---- L2 -----------------------------------------------------------------------------------------------------

IMG = "https://cdn.example.org/a/%d.png"


def test_hot_linked_assets_that_also_host_the_links_fire():
    mail = _email(urls=["https://www.example.org/buy"], images=[IMG % 1, IMG % 2, "https://img.mail.example.com/x.png"])
    result = hot_linked_assets(mail)
    assert result["asset_domain"] == "example.org" and result["images_from_it"] == 2 and result["also_hosts_links"] is True


def test_hot_linked_assets_named_in_the_display_name_fire_without_a_shared_link_host():
    mail = _email(images=[IMG % 1, IMG % 2], display="Example Support", urls=["https://www.mail.example.com/x"])
    assert hot_linked_assets(mail)["named_in_display_or_subject"] is True


@pytest.mark.parametrize(
    "mail",
    [
        _email(urls=["https://www.mail.example.com/x"], images=[IMG % 1, IMG % 2]),  # unrelated CDN the links never use
        _email(urls=["https://www.example.org/x"], images=[IMG % 1]),  # a single image
        _email(urls=["https://www.example.org/x"], images=[IMG % 1, "https://img.mail.example.com/1.png", "https://img.mail.example.com/2.png"]),  # not dominant
        _email(urls=["https://www.mail.example.com/x"], images=["https://img.mail.example.com/1.png", "https://img.mail.example.com/2.png"]),  # the sender's own
        _email(urls=["https://www.example.org/x"], images=["https://u1.ct.sendgrid.net/a.png", "https://u1.ct.sendgrid.net/b.png"]),  # shared platform
    ],
    ids=["unrelated-cdn", "one-image", "not-dominant", "senders-own", "platform"],
)
def test_near_misses_do_not_fire_l2(mail):
    assert hot_linked_assets(mail) is None


# ---- L3 -----------------------------------------------------------------------------------------------------

def test_a_shortener_and_an_open_redirect_fire():
    assert redirector_links(_email(urls=["https://bit.ly/abc"]))["shorteners"] == ["bit.ly"]
    result = redirector_links(_email(urls=["https://redir.example.org/go?target=https://elsewhere.example.net/x"]))
    assert result["open_redirect_hosts"] == ["redir.example.org"]


@pytest.mark.parametrize(
    "url",
    [
        "https://urldefense.com/v3/__https://example.net/x__",
        "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.net%2Fx",
        SG + "&u=https://example.net/x",
        "https://go.mail.example.com/r?u=https://elsewhere.example.net/x",  # the sender's own redirector
        "https://redir.example.org/go?page=2",  # a query that is not a URL
        "https://redir.example.org/go?target=https://other.redir.example.org/x",  # same registrable domain
    ],
    ids=["proofpoint", "safelinks", "esp-tracker", "own-redirector", "not-a-url", "same-registrable"],
)
def test_near_misses_do_not_fire_l3(url):
    assert redirector_links(_email(urls=[url])) is None


# ---- the findings ----------------------------------------------------------------------------------------------

def test_findings_carry_the_pre_registered_severity_weight_and_family():
    mail = _email(urls=[SG, "https://bit.ly/a", "https://www.example.org/buy"], chain=[LOCAL], sender="owner@owner.example.net",
                  images=[IMG % 1, IMG % 2])
    by_signal = {f.evidence["signal"]: f for f in link_findings(mail)}
    assert set(by_signal) == {"L1", "L2", "L3"}
    assert [(by_signal[s].severity, by_signal[s].weight) for s in ("L1", "L2", "L3")] == [("medium", 8.0), ("low", 5.0), ("low", 5.0)]
    assert all(f.evidence["family"] == "link" and f.evidence["structural"] is True and f.module == "content_analysis" for f in by_signal.values())


def test_content_analysis_includes_the_link_findings():
    mail = _email(urls=[SG], chain=[LOCAL], sender="owner@owner.example.net")
    assert any(f.evidence.get("signal") == "L1" for f in run_content_analysis(mail).findings)


# ---- end to end: floors, fixtures, ablation ----------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["strict", "configured"])
def test_every_benign_fixture_stays_below_suspicious_in_both_modes(mode):
    apply_mode(mode)
    bad = {}
    for path in sorted((FIXTURES / "benign").rglob("*.eml")):
        verdict = analyze(path, "clean").verdict
        if verdict in ("suspicious", "malicious"):
            bad[path.name] = verdict
    # fixture 22 is the one documented false positive (C3 claim + L2 link); see test_claim_family.py
    assert set(bad) <= {"22_newsletter_sender_differs_from_brand_link_domain_dkim.eml"}


@pytest.mark.parametrize("name", ["16_esp_hops_and_tracker_match", "17_esp_hops_match_no_dkim_signature", "18_gateway_rewritten_links_proofpoint_style",
                                  "19_small_business_own_tracking_domain", "20_small_business_newsletter_unrelated_cdn_images",
                                  "21_small_business_own_redirector_domain"])
def test_the_link_family_benign_fixtures_fire_no_link_signal(name):
    result = analyze(FIXTURES / "benign" / "synthetic" / f"{name}.eml", "clean")
    assert not [f for f in result.findings if f.evidence.get("family") == "link"]


def test_shared_hosting_plus_a_platform_tracker_it_did_not_use_is_two_families_and_floors():
    # the documented trade-off: this IS the pattern the corroboration rule exists to catch
    from app.auth_check import run_auth_check
    from app.scoring import run_scoring
    from app.contracts.findings import ModuleResult

    mail = _email(urls=[SG], chain=[NETWORK, LOCAL], sender="owner@owner.example.net")
    out = run_scoring([run_auth_check(mail), ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}),
                       run_content_analysis(mail)])
    assert out.verdict == "suspicious"
    reason = next(o.reason for o in out.breakdown.applied_overrides if o.rule == "structural_corroboration_floor")
    assert "link, sender" in reason and "L1" in reason and "S2" in reason


@pytest.mark.parametrize("mode", ["strict", "configured"])
def test_kvish_with_seeds_ablated_reaches_suspicious_from_sender_and_link_families_alone(mode, monkeypatch):
    """The pre-registered success criterion: no brand list, no single-sample seed -- structural signals only."""
    from app.content_analysis import brand_impersonation
    from app.shared import brands

    monkeypatch.delitem(brands.KNOWN_BRANDS, "kvish6", raising=False)
    monkeypatch.delitem(brand_impersonation._BRAND_PATTERNS, "kvish6", raising=False)
    apply_mode(mode)
    result = analyze(FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "clean")
    assert result.verdict == "suspicious"
    assert [o.rule for o in result.scoring.applied_overrides] == ["structural_corroboration_floor"]
    fired = {f.evidence["signal"]: f.evidence["family"] for f in result.findings if f.evidence.get("structural")}
    assert {"S2", "L1"} <= set(fired) and {fired["S2"], fired["L1"]} == {"sender", "link"}
    assert "C1" not in fired and "S1" not in fired  # nothing that needs the brand map contributed
    # a name-matches-linked-domain signal (C3) needs no brand list; the floor itself came from sender + link
    assert [o.rule for o in result.scoring.applied_overrides] == ["structural_corroboration_floor"]
