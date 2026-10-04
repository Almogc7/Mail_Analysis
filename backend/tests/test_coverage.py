"""The coverage report: what was checked, what was not, and why, built only from data the analysis already holds. Display only: no verdict moves."""
import pytest

from app.api import pipeline
from app.contracts.email import Attachment, EmailAddress, ExtractedUrl, ImageRef, ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.coverage import HOW_TO_CLEAR, build_coverage_report
from tests.eval import FIXTURES, apply_mode

SHA = "a" * 64


def _mail(**kw):
    kw.setdefault("from_", EmailAddress(display_name="A", address="a@sender.example.org", domain="sender.example.org"))
    return ParsedEmail(source_format="eml", raw_size_bytes=1, **kw)


def _auth(spf=None, dkim=None, dmarc=None, configured=True, status="ok"):
    none = {"evaluated": False, "reason": "no_trusted_receivers_configured"}
    headers = {"trusted_receivers_configured": configured, "spf": spf or none, "dkim": dkim or none, "dmarc": dmarc or none}
    return ModuleResult(module="auth_check", status=status, findings=[], raw_data={"auth_headers": headers})


def _enrich(raw=None, findings=(), status="ok"):
    return ModuleResult(module="enrichment", status=status, findings=list(findings), raw_data=raw or {})


def _content(language="english", status="supported"):
    return ModuleResult(module="content_analysis", status="ok", findings=[], raw_data={"language": {"language": language, "status": status}})


def _report(mail=None, auth=None, enrichment=None, content=None):
    modules = [m for m in (auth or _auth(), enrichment or _enrich(), content or _content()) if m is not None]
    return build_coverage_report(mail or _mail(), modules)


def _find(report, area, subject=None, reason=None):
    return [i for i in report if i.area == area and (subject is None or i.subject == subject) and (reason is None or i.reason == reason)]


# ---- authentication ---------------------------------------------------------------------------------------------------------

def test_an_evaluated_method_is_checked_and_a_trusted_receiver_row_clears_its_blocker():
    trusted = {"evaluated": True, "result": "pass", "trust_basis": {"host": "mx.example.org"}}
    report = _report(auth=_auth(spf=trusted, dkim=trusted))
    spf = _find(report, "Authentication", "SPF")[0]
    assert (spf.status, spf.reason, spf.detail) == ("checked", "evaluated_by_trusted_receiver", "result: pass, written by a trusted receiver")
    row = _find(report, "Authentication", "trusted receiver in the Received chain")[0]
    assert row.status == "checked" and row.blocks_no_indicators is False
    assert _find(report, "Authentication", "DMARC")[0].status == "not_checked"


@pytest.mark.parametrize("reason,status", [("no_trusted_receivers_configured", "not_checked"), ("claim_from_untrusted_source", "partly"),
                                           ("no_trusted_result", "not_checked"), ("receiver_evaluated_spf_only", "not_checked")])
def test_each_authentication_reason_code_is_carried_with_its_status(reason, status):
    report = _report(auth=_auth(dkim={"evaluated": False, "reason": reason}))
    item = _find(report, "Authentication", "DKIM")[0]
    assert (item.status, item.reason, item.by_design) == (status, reason, False) and item.how_to_clear


def test_no_trusted_hop_is_a_blocker_whether_or_not_receivers_are_configured():
    unconfigured = _find(_report(auth=_auth(configured=False)), "Authentication", "trusted receiver in the Received chain")[0]
    configured = _find(_report(auth=_auth(configured=True)), "Authentication", "trusted receiver in the Received chain")[0]
    assert (unconfigured.reason, unconfigured.blocks_no_indicators) == ("no_trusted_receivers_configured", True)
    assert (configured.reason, configured.blocks_no_indicators) == ("no_trusted_receiver_hop", True)


def test_a_missing_or_failed_auth_module_is_reported_not_skipped():
    for auth in (None, _auth(status="error")):
        modules = [m for m in (auth, _enrich(), _content()) if m is not None]
        item = _find(build_coverage_report(_mail(), modules), "Authentication")[0]
        assert (item.status, item.reason) == ("not_checked", "module_did_not_run")


def test_a_from_header_without_an_address_is_not_checked():
    mail = ParsedEmail(source_format="eml", raw_size_bytes=1, from_=EmailAddress())
    assert _find(_report(mail), "Sender identity")[0].reason == "from_header_unparseable"


# ---- providers ---------------------------------------------------------------------------------------------------------------

def _host(vt="ok", urlscan="ok", threatfox="ok", **extra):
    def res(status):
        return {"status": status, **extra} if status != "disabled_cfg" else {"status": "disabled", "error": "disabled by configuration (ENRICHMENT_DISABLED_PROVIDERS)"}

    return {"vt": res(vt), "urlscan": res(urlscan), "threatfox": res(threatfox)}


def test_providers_are_summarised_per_indicator_class_with_counts_and_a_reason():
    raw = {"a.example.org": _host(), "b.example.org": _host(vt="disabled", urlscan="rate_limited"), "c.example.org": _host(vt="failed", http_status=404)}
    report = _report(enrichment=_enrich(raw))
    vt = _find(report, "VirusTotal", "domains")[0]
    # one never-seen and one no-key: a tie goes to the problem the analyst can act on first (the missing key)
    assert (vt.status, vt.reason, vt.detail) == ("partly", "no_api_key", "1 of 3 answered; 1 never_seen_by_source, 1 no_api_key")
    urlscan = _find(report, "urlscan.io", "domains")[0]
    assert (urlscan.status, urlscan.reason) == ("partly", "rate_limited")
    assert _find(report, "ThreatFox", "domains")[0].status == "checked"


def test_a_clear_majority_problem_wins_over_the_tie_break():
    raw = {f"{c}.example.org": _host(vt="failed", http_status=404) for c in "abc"} | {"d.example.org": _host(vt="disabled")}
    assert _find(_report(enrichment=_enrich(raw)), "VirusTotal")[0].reason == "never_seen_by_source"


def test_a_provider_that_never_answered_is_not_checked_and_the_two_disabled_causes_are_told_apart():
    report = _report(enrichment=_enrich({"a.example.org": _host(vt="disabled", urlscan="disabled_cfg", threatfox="failed")}))
    assert _find(report, "VirusTotal")[0].reason == "no_api_key" and _find(report, "VirusTotal")[0].status == "not_checked"
    assert _find(report, "urlscan.io")[0].reason == "disabled_by_config"
    assert _find(report, "ThreatFox")[0].reason == "provider_error"


def test_hashes_and_ips_are_separate_classes_and_not_applicable_answers_are_not_counted():
    ip = ".".join(("8", "8", "4", "4"))
    raw = {ip: _host(), SHA: {"vt": {"status": "ok"}, "threatfox": {"status": "ok"}, "malwarebazaar": {"status": "not_applicable"}}}
    report = _report(enrichment=_enrich(raw))
    assert _find(report, "VirusTotal", "IP addresses") and _find(report, "VirusTotal", "file hashes")
    assert not _find(report, "MalwareBazaar")  # it was never meant to answer


def test_internal_shared_platform_and_over_limit_indicators_are_their_own_rows_and_the_first_two_block():
    dropped = Finding(module="enrichment", severity="low", title="Not enriched: per-email limit reached (x)", description="d", evidence={}, weight=0.0)
    raw = {"intranet": {"internal_host_not_sent": True}, "docs.google.com": {"uninformative": {"platform": "Google", "kind": "cloud_content"}}}
    report = _report(enrichment=_enrich(raw, [dropped]))
    internal, shared, limit = (_find(report, "Lookups", reason=r)[0] for r in ("internal_host_not_sent", "shared_platform", "limit_reached"))
    assert (internal.blocks_no_indicators, internal.by_design, internal.detail) == (True, True, "1 host(s)")
    assert (shared.blocks_no_indicators, shared.by_design) == (True, False) and limit.blocks_no_indicators is False


def test_enrichment_that_did_not_run_is_reported():
    for enrichment in (_enrich(status="error"), _enrich(status="skipped")):
        item = _find(_report(enrichment=enrichment), "Lookups")[0]
        assert (item.status, item.reason) == ("not_checked", "enrichment_did_not_run")


# ---- content -------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("status,expected,blocks", [("supported", ("checked", "language_supported"), False), ("undetermined", ("partly", "language_undetermined"), False),
                                                    ("unsupported", ("not_checked", "language_unsupported"), True), ("none", ("not_checked", "no_readable_text"), True)])
def test_content_coverage_follows_the_language_status(status, expected, blocks):
    item = _find(_report(content=_content("russian", status)), "Content heuristics")[0]
    assert (item.status, item.reason) == expected and item.blocks_no_indicators is blocks


# ---- surfaces that are not examined ----------------------------------------------------------------------------------------------

def _att(name, ctype=None):
    return Attachment(filename=name, content_type=ctype, size_bytes=5, sha256=SHA, sha1="b", md5="c")


def test_links_are_never_opened_by_design_and_shorteners_block():
    mail = _mail(urls=[ExtractedUrl(url="https://www.example.org/a", source="body_html"), ExtractedUrl(url="https://bit.ly/x", source="body_html")])
    report = _report(mail)
    never = _find(report, "Links", reason="never_opened")[0]
    assert (never.by_design, never.blocks_no_indicators, never.subject) == (True, False, "2 link(s)")
    hidden = _find(report, "Links", reason="redirects_not_resolved")[0]
    assert (hidden.blocks_no_indicators, hidden.detail) == (True, "1 link(s)")
    assert not _find(_report(_mail(urls=[ExtractedUrl(url="https://www.example.org/a", source="body_html")])), "Links", reason="redirects_not_resolved")


@pytest.mark.parametrize("name,blocks", [("invoice.docx", True), ("scan.pdf", True), ("photo.png", False), ("notes.txt", False)])
def test_attachment_contents_are_never_opened_and_active_types_block(name, blocks):
    report = _report(_mail(attachments=[_att(name)]))
    never = _find(report, "Attachments", reason="content_never_opened")[0]
    static = _find(report, "Attachments", reason="static_analysis_off")[0]
    assert never.by_design and never.blocks_no_indicators is blocks and static.blocks_no_indicators is blocks and static.by_design is False


def test_html_attachments_and_archives_are_blockers_in_their_own_right():
    report = _report(_mail(attachments=[_att("form.html"), _att("secret.zip"), _att("disk.iso")]))
    assert _find(report, "Attachments", reason="html_attachment_unanalysed")[0].blocks_no_indicators
    archives = _find(report, "Attachments", reason="archive_contents_unexamined")[0]
    assert archives.blocks_no_indicators and archives.detail == "2 attachment(s)"
    assert not _find(_report(_mail(attachments=[_att("a.docx")])), "Attachments", reason="html_attachment_unanalysed")


def test_an_image_attachment_blocks_because_a_qr_code_could_be_inside_but_a_remote_html_image_does_not():
    attached = _report(_mail(attachments=[_att("photo.png", "image/png")]))
    assert _find(attached, "Images", reason="qr_not_decoded")[0].blocks_no_indicators
    remote = _report(_mail(images=[ImageRef(url="https://img.example.org/a.png")]))
    assert _find(remote, "Images", reason="images_not_examined")[0].by_design and not _find(remote, "Images", reason="qr_not_decoded")


def test_an_html_body_is_not_rendered_by_design():
    assert _find(_report(_mail(body_html="<p>x</p>")), "Body", reason="not_rendered")[0].by_design
    assert not _find(_report(_mail()), "Body")


def test_a_message_with_nothing_to_examine_has_no_surface_rows():
    report = _report(_mail())
    assert not [i for i in report if i.area in ("Links", "Attachments", "Images", "Body")]


# ---- invariants ----------------------------------------------------------------------------------------------------------------

def test_every_reason_code_has_a_how_to_clear_text_unless_nothing_needs_clearing():
    cleared_by_nothing = {"evaluated_by_trusted_receiver", "answered", "language_supported"}
    for code, text in HOW_TO_CLEAR.items():
        assert bool(text) is (code not in cleared_by_nothing), code


def test_every_not_checked_item_names_a_reason_and_a_way_to_clear_it():
    mail = _mail(urls=[ExtractedUrl(url="https://bit.ly/x", source="body_html")], attachments=[_att("a.zip"), _att("b.html"), _att("c.png", "image/png")], body_html="<p/>")
    raw = {"intranet": {"internal_host_not_sent": True}, "a.example.org": _host(vt="disabled")}
    for item in _report(mail, enrichment=_enrich(raw), content=_content("russian", "unsupported")):
        if item.status != "checked":
            assert item.reason in HOW_TO_CLEAR and (item.how_to_clear or item.by_design is False and item.reason == "answered"), item


def test_the_report_holds_counts_and_words_never_an_indicator_or_text_from_the_message():
    mail = _mail(urls=[ExtractedUrl(url="https://secret-host.example.org/SECRET-PATH", source="body_html", anchor_text="SECRET-ANCHOR")],
                 attachments=[_att("SECRET-NAME.zip")], body_text="SECRET-BODY", body_html="<p>SECRET-BODY</p>", subject="SECRET-SUBJECT")
    raw = {"secret-host.example.org": _host(vt="disabled"), "secret-intranet": {"internal_host_not_sent": True}, SHA: {"vt": {"status": "ok"}}}
    text = " ".join(i.model_dump_json() for i in _report(mail, enrichment=_enrich(raw)))
    for private in ("SECRET", "secret-host", "secret-intranet", SHA, "sender.example.org"):
        assert private not in text


# ---- through the pipeline ---------------------------------------------------------------------------------------------------------

def _run(monkeypatch, builder=None):
    apply_mode("strict")
    monkeypatch.setattr(pipeline, "run_enrichment", lambda parsed: ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}))
    monkeypatch.setattr(pipeline, "run_llm_opinion", lambda result: None)
    if builder is not None:
        monkeypatch.setattr(pipeline, "build_coverage_report", builder)
    return pipeline.run_pipeline((FIXTURES / "malicious" / "kvish6_invoice_phish.eml").read_bytes(), "k.eml")


def test_the_pipeline_attaches_a_non_empty_report_and_it_changes_no_verdict_score_or_priority(monkeypatch):
    with_report = _run(monkeypatch)
    assert with_report.schema_version == 2 and with_report.coverage_report
    assert {i.area for i in with_report.coverage_report} >= {"Authentication", "Content heuristics", "Links"}

    def boom(*a, **k):
        raise RuntimeError("SECRET-TEXT")

    without = _run(monkeypatch, boom)
    assert without.coverage_report is None and without.evidence is not None  # the evidence block is independent of it
    assert (with_report.verdict, with_report.score, with_report.confidence, with_report.scoring.priority) == \
           (without.verdict, without.score, without.confidence, without.scoring.priority)


def test_a_coverage_failure_logs_only_the_exception_class(monkeypatch, capsys):
    from app.logging_config import configure_logging

    configure_logging()

    def boom(*a, **k):
        raise KeyError("SECRET-TEXT")

    _run(monkeypatch, boom)
    err = capsys.readouterr().err
    assert "coverage report could not be built (KeyError)" in err and "SECRET-TEXT" not in err
