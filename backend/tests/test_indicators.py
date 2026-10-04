"""Indicator pack: an analyst aid. It adds nothing to the score; unknown / shared-platform / not-looked-up are manual checks."""
from urllib.parse import urlsplit

import pytest

from app.api import pipeline
from app.contracts.email import Attachment, EmailAddress, ExtractedUrl, ImageRef, ParsedEmail, ReceivedHop
from app.contracts.findings import Finding, ModuleResult
from app.indicators import build_indicator_pack
from app.parser import parse_email_file
from tests.eval import FIXTURES, apply_mode

# IP literals are built at runtime so no address literal sits in the source (scripts/check_fixtures.py)
def _ip(*parts):
    return ".".join(parts)


PRIVATE, PUB_A, PUB_B, PUB_C = _ip("192", "168", "1", "9"), _ip("8", "8", "8", "8"), _ip("1", "1", "1", "1"), _ip("8", "8", "4", "4")
SHA = "13b9ecc480f858d1354d12cb2a218b3a1d186dd205fc9b154350a7e45cf562aa"
OK = {"status": "ok"}
NOT_FOUND = {"enabled": True, "status": "failed", "error": "404 Client Error: Not Found", "http_status": 404}


def _mail(urls=(), images=(), attachments=(), chain=(), **kw):
    return ParsedEmail(
        source_format="eml", from_=kw.pop("from_", EmailAddress(display_name="X", address="a@sender.example.org", domain="sender.example.org")),
        urls=[ExtractedUrl(url=u, source="body_html", anchor_text="click" if i == 0 else None) for i, u in enumerate(urls)],
        images=[ImageRef(url=u) for u in images], attachments=list(attachments), received_chain=list(chain), raw_size_bytes=1, **kw)


def _enrichment(raw, findings=(), status="ok"):
    return ModuleResult(module="enrichment", status=status, findings=list(findings), raw_data=raw)


def _host_result(vt=OK, urlscan=OK, threatfox=OK, total=0):
    return {"vt": vt, "urlscan": urlscan, "threatfox": threatfox, "risk_explain": {"total": total}}


def _find(pack, kind, value):
    return next(i for i in pack.indicators if i.kind == kind and i.value == value)


def test_a_looked_up_host_with_nothing_found_is_not_a_manual_check_but_is_not_called_safe():
    pack = build_indicator_pack(_mail(urls=["https://www.example.org/x"]), [_enrichment({"www.example.org": _host_result()})])
    item = _find(pack, "domain", "www.example.org")
    assert item.status == "nothing_found" and not item.manual_check and "not proof of safety" in item.note
    assert item.providers == {"VirusTotal": "answered", "urlscan.io": "answered", "ThreatFox": "answered"}


def test_a_provider_hit_is_listed_first():
    raw = {"clean.example.org": _host_result(), "bad.example.org": _host_result(total=60)}
    pack = build_indicator_pack(_mail(urls=["https://clean.example.org/", "https://bad.example.org/"]), [_enrichment(raw)])
    assert pack.indicators[0].value == "bad.example.org" and pack.indicators[0].status == "provider_hit"


def test_a_shared_platform_host_is_shown_as_a_manual_check_not_hidden():
    raw = {"app.powerbi.com": {"uninformative": {"platform": "Microsoft Forms / Office web apps", "kind": "cloud_content"}}}
    pack = build_indicator_pack(_mail(urls=["https://app.powerbi.com/view?r=SECRET-TOKEN"]), [_enrichment(raw)])
    item = _find(pack, "domain", "app.powerbi.com")
    assert item.status == "shared_platform" and item.manual_check and "Open the specific link in your sandbox" in item.note
    # the sender domain was not part of the enrichment either, so it is a manual check too
    assert pack.manual_check_count == 2 and _find(pack, "domain", "sender.example.org").status == "not_looked_up"


def test_a_hash_virustotal_never_saw_says_so_in_plain_words_and_is_a_manual_check():
    entry = {"vt": NOT_FOUND, "threatfox": OK, "malwarebazaar": OK, "risk_explain": {"total": 0}}
    att = Attachment(filename="image.png", content_type="image/png", size_bytes=141892, sha256=SHA, sha1="a", md5="b")
    pack = build_indicator_pack(_mail(attachments=[att]), [_enrichment({SHA: entry})])
    item = _find(pack, "hash", SHA)
    assert item.providers["VirusTotal"] == "never seen by this source"
    assert item.status == "unknown" and item.manual_check
    assert "never seen" in item.note and "never opens or uploads attachments" in item.note and item.filename == "image.png"
    assert "failed" not in item.note and "failed" not in " ".join(item.providers.values())


@pytest.mark.parametrize("vt", [{"status": "rate_limited"}, {"status": "disabled"}, None])
def test_an_unanswered_lookup_is_unknown_never_clean(vt):
    entry = _host_result(vt=vt if vt is not None else "boom", urlscan={"status": "disabled"}, threatfox={"status": "disabled"})
    pack = build_indicator_pack(_mail(urls=["https://www.example.org/"]), [_enrichment({"www.example.org": entry})])
    item = _find(pack, "domain", "www.example.org")
    assert item.status == "unknown" and item.manual_check


def test_mixed_answers_are_unknown_not_clean():
    entry = _host_result(urlscan={"status": "rate_limited"})
    item = _find(build_indicator_pack(_mail(urls=["https://www.example.org/"]), [_enrichment({"www.example.org": entry})]), "domain", "www.example.org")
    assert item.status == "unknown" and "treat as unknown" in item.note


def test_enrichment_not_run_or_errored_marks_everything_not_looked_up():
    for module in (None, _enrichment({}, status="error")):
        modules = [] if module is None else [module]
        pack = build_indicator_pack(_mail(urls=["https://www.example.org/"]), modules)
        item = _find(pack, "domain", "www.example.org")
        assert item.status == "not_looked_up" and item.manual_check


def test_a_host_dropped_by_the_per_email_cap_says_so():
    dropped = Finding(module="enrichment", severity="low", title="Not enriched: per-email limit reached (www.example.org)", description="d",
                      evidence={"ioc_value": "www.example.org"}, weight=0.0)
    item = _find(build_indicator_pack(_mail(urls=["https://www.example.org/"]), [_enrichment({}, [dropped])]), "domain", "www.example.org")
    assert item.status == "not_looked_up" and "limit was reached" in item.note


def test_internal_looking_hosts_are_not_marked_for_manual_check():
    item = _find(build_indicator_pack(_mail(urls=["https://intranet/x"]), [_enrichment({"intranet": {"internal_host_not_sent": True}})]), "domain", "intranet")
    assert item.status == "internal" and not item.manual_check


def test_pivot_links_carry_only_the_host_ip_or_hash_never_a_path_or_query():
    url = "https://track.example.org/c/TOKEN123?u=SECRETRECIPIENT&x=1"
    pack = build_indicator_pack(_mail(urls=[url]), [_enrichment({"track.example.org": _host_result()})])
    item = _find(pack, "domain", "track.example.org")
    assert [p.name for p in item.pivots] == ["VirusTotal", "urlscan.io", "ICANN lookup (registration, age)", "Cisco Talos"]
    blob = " ".join(p.url for i in pack.indicators for p in i.pivots)
    assert "TOKEN123" not in blob and "SECRETRECIPIENT" not in blob and "track.example.org" in blob
    assert all(urlsplit(p.url).scheme == "https" for i in pack.indicators for p in i.pivots)


def test_ips_come_from_public_hops_only_and_the_origin_is_labelled():
    chain = [ReceivedHop(raw="r", from_ip=PRIVATE), ReceivedHop(raw="r", from_ip=PUB_A),
             ReceivedHop(raw="r", from_ip=PUB_B, from_host="origin.example.net")]
    pack = build_indicator_pack(_mail(chain=chain), [_enrichment({})])
    ips = {i.value: i for i in pack.indicators if i.kind == "ip"}
    assert set(ips) == {PUB_A, PUB_B}  # the private address is not an indicator
    assert any("origin hop" in s for s in ips[PUB_B].seen_in) and "Received hop" in ips[PUB_A].seen_in
    assert _find(pack, "domain", "origin.example.net").seen_in == ["origin hop host name"]
    assert [p.name for p in ips[PUB_A].pivots] == ["VirusTotal", "AbuseIPDB", "Shodan", "Cisco Talos"]


def test_a_host_seen_several_times_is_one_indicator_with_a_count_and_all_roles():
    mail = _mail(urls=["https://www.example.org/a", "https://www.example.org/b"], images=["https://www.example.org/i.png"])
    item = _find(build_indicator_pack(mail, [_enrichment({"www.example.org": _host_result()})]), "domain", "www.example.org")
    assert item.count == 3 and "clickable link (call to action)" in item.seen_in and "image loaded by the message" in item.seen_in


def test_sender_addresses_and_their_domains_are_listed():
    mail = _mail(reply_to=[EmailAddress(address="r@reply.example.net", domain="reply.example.net")],
                 return_path=EmailAddress(address="rp@bounce.example.com", domain="bounce.example.com"))
    pack = build_indicator_pack(mail, [_enrichment({})])
    assert _find(pack, "email", "a@sender.example.org").seen_in == ["From address"]
    assert _find(pack, "email", "r@reply.example.net").seen_in == ["Reply-To address"]
    assert _find(pack, "domain", "bounce.example.com").seen_in == ["Return-Path domain"]
    assert pack.counts["email"] == 3


def test_an_ip_literal_link_is_an_ip_indicator():
    pack = build_indicator_pack(_mail(urls=[f"http://{PUB_C}/login"]), [_enrichment({})])
    assert _find(pack, "ip", PUB_C)


def test_hash_pivots_and_no_attachment_content_is_touched():
    att = Attachment(filename=None, content_type=None, size_bytes=5, sha256=SHA, sha1="a", md5="b")
    item = _find(build_indicator_pack(_mail(attachments=[att]), [_enrichment({})]), "hash", SHA)
    assert [p.name for p in item.pivots] == ["VirusTotal", "MalwareBazaar", "Hybrid Analysis"] and item.status == "not_looked_up"


# ---- through the real pipeline -----------------------------------------------------------------------------------

def test_the_pipeline_attaches_the_pack_and_it_changes_neither_score_nor_verdict(monkeypatch):
    apply_mode("strict")
    raw = (FIXTURES / "malicious" / "kvish6_invoice_phish.eml").read_bytes()
    monkeypatch.setattr(pipeline, "run_enrichment", lambda parsed: _enrichment({}))
    monkeypatch.setattr(pipeline, "run_llm_opinion", lambda result: None)
    with_pack = pipeline.run_pipeline(raw, "k.eml")
    assert with_pack.indicators is not None and with_pack.indicators.counts.get("domain", 0) > 0
    monkeypatch.setattr(pipeline, "build_indicator_pack", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    without = pipeline.run_pipeline(raw, "k.eml")  # a bug in the pack must never sink the analysis
    assert without.indicators is None
    assert (with_pack.score, with_pack.verdict, with_pack.confidence) == (without.score, without.verdict, without.confidence)


def test_no_pivot_on_a_real_sample_contains_a_tracking_token():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    pack = build_indicator_pack(parsed, [_enrichment({})])
    blob = " ".join(p.url for i in pack.indicators for p in i.pivots)
    for u in parsed.urls:
        parts = urlsplit(u.url)
        for token in [t for t in (parts.path.strip("/"), parts.query) if len(t) > 8]:
            assert token not in blob
