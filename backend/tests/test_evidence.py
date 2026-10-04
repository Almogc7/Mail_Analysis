"""The evidence block (phase A of docs/DESIGN_V2.md): organised facts for the workbench page. It adds nothing to the score."""
from datetime import datetime, timedelta, timezone

import pytest

from app.api import pipeline
from app.contracts.analysis import AnalysisResult, Indicator, IndicatorPack
from app.contracts.email import Attachment, EmailAddress, ExtractedUrl, ImageRef, ParsedEmail, ReceivedHop
from app.contracts.findings import ModuleResult
from app.evidence import attachment_class, build_evidence, defang_url
from tests.eval import FIXTURES, apply_mode

T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)


def _mail(**kw):
    kw.setdefault("from_", EmailAddress(display_name="A", address="a@sender.example.org", domain="sender.example.org"))
    return ParsedEmail(source_format="eml", raw_size_bytes=1, **kw)


def _auth(methods=None, alignment=None, identity=None, configured=True, status="ok"):
    headers = {"trusted_receivers_configured": configured}
    headers.update(methods or {})
    return ModuleResult(module="auth_check", status=status, findings=[], raw_data={"auth_headers": headers, "alignment": alignment or {}, "identity": identity or {}})


# ---- helpers ------------------------------------------------------------------------------------------------------

def test_defanging_makes_a_url_unclickable_and_keeps_it_readable():
    assert defang_url("https://login.example.org/a?b=c@d") == "hxxps://login[.]example[.]org/a?b=c[@]d"
    assert defang_url("HTTP://x.example.org") == "hxxp://x[.]example[.]org"
    assert defang_url("ftp://x.example.org") == "ftp://x[.]example[.]org"
    assert "." not in defang_url("https://a.b.c.example.org/p.q").replace("[.]", "")
    # a wrapper URL carries another URL in its path: every scheme occurrence is neutralised, in any case
    wrapped = defang_url("https://urldefense.com/v3/__https://x.example.net/a__;HTTP://y.example.net/")
    assert wrapped == "hxxps://urldefense[.]com/v3/__hxxps://x[.]example[.]net/a__;hxxp://y[.]example[.]net/"
    assert "http" not in wrapped.lower().replace("hxxp", "")


@pytest.mark.parametrize(
    "name,ctype,expected",
    [
        ("invoice.docx", None, ("office", True, "docx", False)), ("sheet.XLSM", None, ("office", True, "xlsm", False)),
        ("scan.pdf", None, ("pdf", True, "pdf", False)), ("files.zip", None, ("archive", True, "zip", False)),
        ("disk.iso", None, ("disk_image", True, "iso", False)), ("page.html", None, ("html", True, "html", False)),
        ("run.js", None, ("script", True, "js", False)), ("setup.exe", None, ("executable", True, "exe", False)),
        ("photo.png", None, ("image", False, "png", False)), ("invite.ics", None, ("calendar", False, "ics", False)),
        ("notes.txt", None, ("text", False, "txt", False)), ("forward.eml", None, ("mail_message", True, "eml", False)),
        ("invoice.pdf.exe", None, ("executable", True, "exe", True)), ("photo.jpg.js", None, ("script", True, "js", True)),
        ("archive.tar.exe", None, ("executable", True, "exe", False)),  # an inner extension that is not a document is not a disguise
        ("noext", "application/pdf", ("pdf", True, None, False)), ("noext", "image/png", ("image", False, None, False)),
        ("noext", "text/html", ("html", True, None, False)), ("mystery.zzz", "application/octet-stream", ("other", False, "zzz", False)),
        (None, None, ("other", False, None, False)),
    ],
)
def test_attachment_classification(name, ctype, expected):
    assert attachment_class(name, ctype) == expected


# ---- hop timeline -------------------------------------------------------------------------------------------------

def _hops():
    # newest first, as the parser stores them
    return [
        ReceivedHop(raw="r3", from_host="gw.example.net", by_host="mx.example.org", timestamp=T0 + timedelta(seconds=40), tls=True, protocol="ESMTPS"),
        ReceivedHop(raw="r2", from_host="relay.example.net", by_host="gw.example.net", timestamp=T0 + timedelta(seconds=10), from_ip="198.51.100.4"),
        ReceivedHop(raw="r1", from_host="box", by_host="host12.example.net", timestamp=T0, protocol="local", is_local_submission=True),
    ]


def test_the_timeline_is_oldest_first_with_the_origin_marked_and_delays_computed():
    timeline = build_evidence(_mail(received_chain=_hops()), []).hop_timeline
    assert [h.index for h in timeline] == [1, 2, 3] and [h.by_host for h in timeline] == ["host12.example.net", "gw.example.net", "mx.example.org"]
    assert [h.is_origin for h in timeline] == [True, False, False] and timeline[0].local_submission and timeline[2].tls
    assert [h.delay_seconds_from_previous for h in timeline] == [None, 10.0, 30.0] and not any(h.clock_skew for h in timeline)
    assert timeline[0].timestamp == T0.isoformat() and timeline[1].from_ip == "198.51.100.4"


def test_a_timestamp_earlier_than_the_previous_hop_is_flagged_as_clock_skew_not_hidden():
    chain = _hops()
    chain[0] = chain[0].model_copy(update={"timestamp": T0 - timedelta(seconds=5)})
    timeline = build_evidence(_mail(received_chain=chain), []).hop_timeline
    assert timeline[2].delay_seconds_from_previous == -15.0 and timeline[2].clock_skew is True


def test_hops_without_timestamps_have_no_delay_and_the_next_dated_hop_measures_from_the_last_dated_one():
    chain = _hops()
    chain[1] = chain[1].model_copy(update={"timestamp": None})
    timeline = build_evidence(_mail(received_chain=chain), []).hop_timeline
    assert timeline[1].delay_seconds_from_previous is None and timeline[2].delay_seconds_from_previous == 40.0


def test_a_hop_that_wrote_a_trusted_result_is_marked_and_untrusted_claims_do_not_mark_anything():
    methods = {"dkim": {"evaluated": True, "result": "pass", "trust_basis": {"host": "gw.example.net", "hop_index": 1}, "source": "authentication-results"},
               "spf": {"evaluated": False, "reason": "claim_from_untrusted_source"}, "dmarc": {"evaluated": False, "reason": "no_trusted_result"}}
    timeline = build_evidence(_mail(received_chain=_hops()), [_auth(methods)]).hop_timeline
    assert [h.trusted_receiver for h in timeline] == [False, True, False]  # newest-first index 1 is the middle hop
    assert not any(h.trusted_receiver for h in build_evidence(_mail(received_chain=_hops()), []).hop_timeline)
    placeholder = {"dkim": {"evaluated": True, "result": "pass", "trust_basis": {"host": "unknown-authserv", "hop_index": None}}}
    assert not any(h.trusted_receiver for h in build_evidence(_mail(received_chain=_hops()), [_auth(placeholder)]).hop_timeline)


def test_an_empty_chain_is_an_empty_timeline():
    assert build_evidence(_mail(), []).hop_timeline == []


# ---- sender and authentication -----------------------------------------------------------------------------------------

def test_sender_block_carries_the_three_identities_the_auth_rows_and_the_mismatches():
    methods = {"spf": {"evaluated": True, "result": "pass", "trust_basis": {"host": "mx.example.org"}, "source": "received-spf"},
               "dkim": {"evaluated": False, "reason": "no_trusted_result"}, "dmarc": {"evaluated": False, "reason": "no_trusted_receivers_configured"}}
    alignment = {"spf": {"aligned": True}, "dkim": {"aligned": None}, "envelope_equals_from": False}
    identity = {"from_return_path_mismatch": {"mismatch": True}, "from_reply_to_mismatch": {"mismatch": False}}
    mail = _mail(reply_to=[EmailAddress(address="r@reply.example.net", domain="reply.example.net")],
                 return_path=EmailAddress(address="rp@bounce.example.com", domain="bounce.example.com"))
    sender = build_evidence(mail, [_auth(methods, alignment, identity)]).sender
    assert sender.from_address.domain == "sender.example.org" and sender.reply_to.domain == "reply.example.net" and sender.return_path.domain == "bounce.example.com"
    rows = {r.method: r for r in sender.auth}
    assert (rows["spf"].evaluated, rows["spf"].result, rows["spf"].receiver, rows["spf"].source) == (True, "pass", "mx.example.org", "received-spf")
    assert (rows["dkim"].evaluated, rows["dkim"].result, rows["dkim"].reason) == (False, None, "no_trusted_result")
    assert rows["dmarc"].reason == "no_trusted_receivers_configured"
    assert sender.alignment == {"spf": True, "dkim": None, "envelope_equals_from": False}
    assert sender.mismatches == ["The From domain and the Return-Path domain belong to different organisations"]
    assert sender.trusted_receivers_configured is True


def test_sender_block_without_an_auth_module_still_has_the_identities():
    for modules in ([], [_auth(status="error")]):
        sender = build_evidence(_mail(), modules).sender
        assert sender.from_address.address == "a@sender.example.org" and sender.auth == [] and sender.reply_to is None


# ---- links ----------------------------------------------------------------------------------------------------------------

def _urls():
    def u(url, text=None, source="body_html", mismatch=False):
        return ExtractedUrl(url=url, source=source, anchor_text=text, is_anchor_mismatch=mismatch)

    return [
        u("https://www.example.org/a", "Open the   document\n now", mismatch=True), u("https://www.example.org/a", None, "body_text"),
        u("https://u1.ct.sendgrid.net/ls/click?upn=x", "Pay"), u("https://urldefense.com/v3/__https://x.example.net/__", "x"),
        u("https://bit.ly/abc"), u("https://docs.google.com/d/1"),
        u("https://redir.example.net/go?u=https://elsewhere.example.org/x"), u("https://www.example.org/plain?next=/local"),
    ]


def test_links_are_grouped_defanged_and_classified_without_being_opened():
    links = {l.url: l for l in build_evidence(_mail(urls=_urls()), []).links}
    first = links["https://www.example.org/a"]
    assert first.occurrences == 2 and first.sources == ["body_html", "body_text"] and first.anchor_mismatch is True
    assert first.display_text == "Open the document now" and first.kind == "direct" and first.registrable_domain == "example.org"
    assert first.url_defanged == "hxxps://www[.]example[.]org/a" and first.host == "www.example.org"
    kinds = {url.split("/")[2]: l.kind for url, l in links.items()}
    assert kinds["u1.ct.sendgrid.net"] == "tracker" and kinds["urldefense.com"] == "wrapper" and kinds["bit.ly"] == "shortener"
    assert kinds["docs.google.com"] == "shared_platform" and kinds["redir.example.net"] == "redirector"
    assert links["https://www.example.org/plain?next=/local"].kind == "direct"  # a relative next= is not an open redirect
    assert links["https://u1.ct.sendgrid.net/ls/click?upn=x"].platform == "SendGrid"


def test_a_long_link_text_is_capped_and_a_link_without_text_has_none():
    long_text = "word " * 100
    links = build_evidence(_mail(urls=[ExtractedUrl(url="https://a.example.org/", source="body_html", anchor_text=long_text),
                                       ExtractedUrl(url="https://b.example.org/", source="body_text")]), []).links
    assert links[0].display_text.endswith("...") and len(links[0].display_text) <= 203 and links[1].display_text is None


def test_link_status_comes_from_the_indicator_of_its_host():
    pack = IndicatorPack(indicators=[Indicator(kind="domain", value="www.example.org", status="unknown", manual_check=True)])
    links = build_evidence(_mail(urls=[ExtractedUrl(url="https://www.example.org/a", source="body_html"),
                                       ExtractedUrl(url="https://other.example.net/", source="body_html")]), [], pack).links
    assert [l.status for l in links] == ["unknown", "n/a"]


# ---- attachments, images, body ---------------------------------------------------------------------------------------------

def test_attachments_are_metadata_and_hashes_only():
    atts = [Attachment(filename="invoice.pdf.exe", content_type="application/octet-stream", size_bytes=10, sha256="a" * 64, sha1="b", md5="c"),
            Attachment(filename="photo.png", content_type="image/png", size_bytes=99, sha256="d" * 64, sha1="e", md5="f")]
    evidence = build_evidence(_mail(attachments=atts), [])
    a, b = evidence.attachments
    assert (a.risk_class, a.active_content, a.double_extension, a.static_analysis, a.detected_type) == ("executable", True, True, None, None)
    assert (b.risk_class, b.active_content, b.sha256, b.size_bytes) == ("image", False, "d" * 64, 99)
    assert [(i.source, i.filename, i.size_bytes, i.decoded) for i in evidence.images] == [("attachment", "photo.png", 99, None)]


def test_html_images_are_listed_by_defanged_host_and_never_decoded():
    evidence = build_evidence(_mail(images=[ImageRef(url="https://img.example.org/a.png"), ImageRef(url="https://img.example.org/b.png")]), [])
    assert [(i.source, i.host, i.url_defanged, i.decoded) for i in evidence.images] == [("html", "img.example.org", "hxxps://img[.]example[.]org/a[.]png", None)] * 1 + \
           [("html", "img.example.org", "hxxps://img[.]example[.]org/b[.]png", None)]


def test_body_facts_are_counts_and_the_language_from_the_content_module_never_the_text():
    content = ModuleResult(module="content_analysis", status="ok", findings=[], raw_data={"language": {"language": "hebrew", "status": "supported"}})
    html = "<html><FORM action='x'><input type=password></form><form></form><img src='https://i.example.org/p.png'></html>"
    mail = _mail(body_text="SECRET-BODY-MARKER hello", body_html=html, images=[ImageRef(url="https://i.example.org/p.png")],
                 urls=[ExtractedUrl(url="https://a.example.org/", source="body_html")])
    evidence = build_evidence(mail, [content])
    body = evidence.body
    assert (body.language, body.language_status, body.text_chars, body.has_html, body.forms, body.remote_images, body.links) == ("hebrew", "supported", 24, True, 2, 1, 1)
    assert "SECRET-BODY-MARKER" not in evidence.model_dump_json()


def test_the_evidence_block_never_contains_attachment_content_or_a_raw_clickable_defanged_url():
    evidence = build_evidence(_mail(urls=_urls()), [])
    for link in evidence.links:
        assert "http://" not in link.url_defanged.lower() and "https://" not in link.url_defanged.lower() and "." not in link.url_defanged.replace("[.]", "")


# ---- through the pipeline -----------------------------------------------------------------------------------------------------

def _run(monkeypatch, builder=None):
    apply_mode("strict")
    monkeypatch.setattr(pipeline, "run_enrichment", lambda parsed: ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}))
    monkeypatch.setattr(pipeline, "run_llm_opinion", lambda result: None)
    if builder is not None:
        monkeypatch.setattr(pipeline, "build_evidence", builder)
    return pipeline.run_pipeline((FIXTURES / "malicious" / "kvish6_invoice_phish.eml").read_bytes(), "k.eml")


def test_the_pipeline_attaches_the_block_and_marks_schema_version_2(monkeypatch):
    result = _run(monkeypatch)
    assert result.schema_version == 2 and result.evidence is not None
    assert result.evidence.hop_timeline[0].is_origin and result.evidence.hop_timeline[0].local_submission  # the Kvish origin hop
    assert result.evidence.links and result.evidence.sender.from_address.domain


def test_the_block_changes_neither_verdict_nor_score_nor_priority_and_a_failure_in_it_cannot_sink_the_analysis(monkeypatch):
    with_block = _run(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("SECRET-TEXT-IN-AN-ERROR")

    without = _run(monkeypatch, boom)
    # the two blocks are independent: with the evidence builder failing the coverage report is still built (so the version is 2)
    assert without.evidence is None and without.coverage_report is not None and without.schema_version == 2
    assert (with_block.verdict, with_block.score, with_block.confidence, with_block.scoring.priority) == (without.verdict, without.score, without.confidence, without.scoring.priority)
    assert [f.title for f in with_block.findings] == [f.title for f in without.findings]


def test_a_failure_logs_only_the_exception_class_never_its_text(monkeypatch, capsys):
    from app.logging_config import configure_logging

    configure_logging()

    def boom(*a, **k):
        raise ValueError("SECRET-TEXT-IN-AN-ERROR")

    _run(monkeypatch, boom)
    err = capsys.readouterr().err
    assert "evidence block could not be built (ValueError)" in err and "SECRET-TEXT" not in err


def test_an_older_result_without_the_new_fields_still_parses_and_new_results_keep_every_old_field(monkeypatch):
    new = _run(monkeypatch).model_dump()
    old_shape = {k: v for k, v in new.items() if k not in ("evidence", "schema_version")}
    parsed_old = AnalysisResult.model_validate(old_shape)
    assert parsed_old.schema_version == 1 and parsed_old.evidence is None
    for key in ("parsed_email", "module_results", "findings", "score", "verdict", "confidence", "scoring", "llm_opinion", "indicators"):
        assert key in new
