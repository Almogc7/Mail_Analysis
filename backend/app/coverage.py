"""The coverage report: a structured list of what was checked, what was not, and why (docs/DESIGN_V2.md, section 3).

Built ONLY from data the analysis already holds (the three module results, the parsed message and the evidence block). It adds nothing to the
score and changes no verdict. Every not-checked item has a stable reason code and a plain "how to clear it" sentence. Details are counts and words:
never an indicator, an address, a URL or any text from the message.

`blocks_no_indicators` marks an unchecked high-risk surface. Until verdict v2 is active it is display only: the page lists these next to the
verdict, marked as items that would block "No indicators found" once v2 is on.
"""
from __future__ import annotations

from app.contracts.analysis import CoverageItem, Evidence
from app.contracts.email import ParsedEmail
from app.contracts.findings import ModuleResult
from app.enrichment.policy import classify_host
from app.evidence import build_evidence

HOW_TO_CLEAR: dict[str, str] = {
    "evaluated_by_trusted_receiver": "",
    "no_trusted_receivers_configured": "Set TRUSTED_RECEIVER_PATTERNS in backend/.env (scripts/suggest_trusted_receivers.py reads it from your own mail).",
    "claim_from_untrusted_source": "A header claims a result but its writer is not trusted. Configure your gateway as a trusted receiver, or read the original headers by hand.",
    "no_trusted_result": "The trusted receiver did not write this result. Read the original headers by hand.",
    "receiver_evaluated_spf_only": "The gateway evaluated SPF only, so DKIM and DMARC cannot be verified from this message.",
    "no_trusted_receiver_hop": "No hop of this message wrote a result the app trusts. Configure your gateway as a trusted receiver.",
    "from_header_unparseable": "The From header has no usable address: look at the raw headers.",
    "answered": "",
    "no_api_key": "Add this provider's key to backend/.env.",
    "disabled_by_config": "Remove the provider from ENRICHMENT_DISABLED_PROVIDERS.",
    "rate_limited": "Wait a minute and analyse the message again.",
    "provider_error": "Check the connection and the key, then analyse the message again.",
    "never_seen_by_source": "Not an error: the source has no record of it. Inspect it in your sandbox.",
    "internal_host_not_sent": "By design internal-looking names are never sent to an outside service. Check them by hand.",
    "shared_platform": "A shared platform's reputation says nothing about one page on it. Open the link in your sandbox.",
    "limit_reached": "Raise MAX_URLS_TO_ENRICH or MAX_HASHES_TO_ENRICH in backend/.env, or check the rest by hand.",
    "enrichment_did_not_run": "No lookup ran. Look at the console log for the cause, then analyse the message again.",
    "module_did_not_run": "This check did not run. Look at the console log for the cause.",
    "language_supported": "",
    "language_undetermined": "There was too little text to tell the language; the English and Hebrew heuristics may not apply.",
    "language_unsupported": "The heuristics cover English and Hebrew only. Read the message yourself.",
    "no_readable_text": "There is no readable text (image-only or empty message). Look at the images and attachments yourself.",
    "never_opened": "By design the app never opens links. Open them in your sandbox.",
    "redirects_not_resolved": "A shortener or redirector hides the destination. Resolve it in your sandbox; automatic resolution is not built.",
    "content_never_opened": "By design the app never opens attachments. Analyse them in your sandbox.",
    "static_analysis_off": "Static attachment analysis is not built yet.",
    "html_attachment_unanalysed": "An HTML attachment can carry a credential form. Inspect it in your sandbox; HTML analysis is not built yet.",
    "archive_contents_unexamined": "An archive may hide its contents (a password-protected one cannot be listed). Examine it in your sandbox.",
    "images_not_examined": "By design the app does not look inside images.",
    "qr_not_decoded": "QR decoding is not built yet: look at the image for a QR code.",
    "not_rendered": "By design the app never renders HTML.",
    "verdict_v2_unavailable": "The v2 verdict could not be built for this message; the v1 result is unaffected. Look at the console log for the cause, then analyse the message again.",
}

_PROBLEM_ORDER = ("provider_error", "rate_limited", "no_api_key", "disabled_by_config", "never_seen_by_source")
_PROVIDER_LABEL = {"vt": "VirusTotal", "urlscan": "urlscan.io", "threatfox": "ThreatFox", "malwarebazaar": "MalwareBazaar"}
_HOST_PROVIDERS = ("vt", "urlscan", "threatfox")
_HASH_PROVIDERS = ("vt", "threatfox", "malwarebazaar")
_CLASS_LABEL = {"domain": "domains", "ip": "IP addresses", "hash": "file hashes"}


def _item(area, status, reason, subject=None, detail="", by_design=False, blocks=False) -> CoverageItem:
    return CoverageItem(area=area, subject=subject, status=status, reason=reason, detail=detail, by_design=by_design,
                        blocks_no_indicators=blocks, how_to_clear=HOW_TO_CLEAR.get(reason, ""))


def _ok(module: ModuleResult | None) -> bool:
    return module is not None and module.status == "ok"


def _authentication(parsed: ParsedEmail, auth: ModuleResult | None) -> list[CoverageItem]:
    if not _ok(auth):
        return [_item("Authentication", "not_checked", "module_did_not_run", subject="SPF, DKIM, DMARC")]
    headers = (auth.raw_data or {}).get("auth_headers") or {}
    items: list[CoverageItem] = []
    trusted_results = 0
    for method in ("spf", "dkim", "dmarc"):
        entry = headers.get(method) or {}
        if entry.get("evaluated"):
            trusted_results += 1
            host = (entry.get("trust_basis") or {}).get("host")
            items.append(_item("Authentication", "checked", "evaluated_by_trusted_receiver", method.upper(),
                               detail=f"result: {entry.get('result')}" + (", written by a trusted receiver" if host else "")))
        else:
            reason = entry.get("reason") or "no_trusted_result"
            items.append(_item("Authentication", "partly" if reason == "claim_from_untrusted_source" else "not_checked", reason, method.upper()))
    if trusted_results:
        items.append(_item("Authentication", "checked", "evaluated_by_trusted_receiver", "trusted receiver in the Received chain"))
    else:
        reason = "no_trusted_receivers_configured" if not headers.get("trusted_receivers_configured") else "no_trusted_receiver_hop"
        items.append(_item("Authentication", "not_checked", reason, "trusted receiver in the Received chain", blocks=True))
    if not (parsed.from_ and parsed.from_.address):
        items.append(_item("Sender identity", "not_checked", "from_header_unparseable", "From address"))
    else:
        items.append(_item("Sender identity", "checked", "answered", "From, Reply-To and Return-Path compared"))
    return items


def _provider_state(result) -> str | None:
    """One code per provider answer, or None when the provider was never meant to answer (not applicable)."""
    if not isinstance(result, dict):
        return "provider_error"
    status = result.get("status")
    if status == "ok":
        return "answered"
    if status == "not_applicable":
        return None
    if status == "disabled":
        return "disabled_by_config" if "ENRICHMENT_DISABLED_PROVIDERS" in str(result.get("error", "")) else "no_api_key"
    if status == "rate_limited":
        return "rate_limited"
    if status == "failed" and result.get("http_status") == 404:
        return "never_seen_by_source"
    return "provider_error"


def _enrichment(enrichment: ModuleResult | None) -> list[CoverageItem]:
    if not _ok(enrichment):
        return [_item("Lookups", "not_checked", "enrichment_did_not_run", subject="all providers")]
    tallies: dict[tuple[str, str], dict[str, int]] = {}  # (provider, class) -> {state: count}
    internal = shared = 0
    for key, value in (enrichment.raw_data or {}).items():
        if not isinstance(value, dict):
            continue
        if value.get("internal_host_not_sent"):
            internal += 1
            continue
        if "uninformative" in value:
            shared += 1
            continue
        is_hash = len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)
        kind = "hash" if is_hash else ("ip" if classify_host(key.split("/")[0]) == "ip" else "domain")
        for short in (_HASH_PROVIDERS if is_hash else _HOST_PROVIDERS):
            if short not in value:
                continue
            state = _provider_state(value[short])
            if state is not None:
                counts = tallies.setdefault((short, kind), {})
                counts[state] = counts.get(state, 0) + 1
    items: list[CoverageItem] = []
    for (short, kind), counts in sorted(tallies.items()):
        total = sum(counts.values())
        answered = counts.get("answered", 0)
        problems = {s: n for s, n in counts.items() if s != "answered"}
        status = "checked" if answered == total else ("partly" if answered else "not_checked")
        # the commonest problem; a tie goes to the one the analyst can act on first
        reason = "answered" if not problems else max(problems, key=lambda s: (problems[s], -_PROBLEM_ORDER.index(s)))
        detail = f"{answered} of {total} answered" + ("" if not problems else "; " + ", ".join(f"{n} {s}" for s, n in sorted(problems.items())))
        items.append(_item(_PROVIDER_LABEL[short], status, reason, _CLASS_LABEL[kind], detail=detail))
    dropped = sum(1 for f in enrichment.findings if f.title.startswith("Not enriched:"))
    if internal:
        items.append(_item("Lookups", "not_checked", "internal_host_not_sent", "internal-looking hosts", detail=f"{internal} host(s)", by_design=True, blocks=True))
    if shared:
        items.append(_item("Lookups", "not_checked", "shared_platform", "hosts on shared platforms", detail=f"{shared} host(s)", blocks=True))
    if dropped:
        items.append(_item("Lookups", "not_checked", "limit_reached", "indicators over the per-email limit", detail=f"{dropped} indicator(s)"))
    return items


def _content(content: ModuleResult | None) -> list[CoverageItem]:
    if not _ok(content):
        return [_item("Content heuristics", "not_checked", "module_did_not_run")]
    language = (content.raw_data or {}).get("language") or {}
    status = language.get("status")
    if status == "supported":
        return [_item("Content heuristics", "checked", "language_supported", detail=f"language: {language.get('language')}")]
    if status == "undetermined":
        return [_item("Content heuristics", "partly", "language_undetermined")]
    if status == "none":
        return [_item("Content heuristics", "not_checked", "no_readable_text", blocks=True)]
    return [_item("Content heuristics", "not_checked", "language_unsupported", detail=f"language: {language.get('language')}", blocks=True)]


def _surfaces(evidence: Evidence) -> list[CoverageItem]:
    items: list[CoverageItem] = []
    if evidence.links:
        items.append(_item("Links", "not_checked", "never_opened", f"{len(evidence.links)} link(s)", by_design=True))
        hidden = sum(1 for l in evidence.links if l.kind in ("shortener", "redirector"))
        if hidden:
            items.append(_item("Links", "not_checked", "redirects_not_resolved", "shorteners and redirectors", detail=f"{hidden} link(s)", blocks=True))
    attachments = evidence.attachments
    if attachments:
        active = sum(1 for a in attachments if a.active_content)
        items.append(_item("Attachments", "not_checked", "content_never_opened", f"{len(attachments)} attachment(s)", by_design=True, blocks=bool(active)))
        items.append(_item("Attachments", "not_checked", "static_analysis_off", "static analysis", detail=f"{active} of active or container type" if active else "", blocks=bool(active)))
        html = sum(1 for a in attachments if a.risk_class == "html")
        archives = sum(1 for a in attachments if a.risk_class in ("archive", "disk_image"))
        if html:
            items.append(_item("Attachments", "not_checked", "html_attachment_unanalysed", "HTML attachments", detail=f"{html} attachment(s)", blocks=True))
        if archives:
            items.append(_item("Attachments", "not_checked", "archive_contents_unexamined", "archives and disk images", detail=f"{archives} attachment(s)", blocks=True))
    attachment_images = sum(1 for i in evidence.images if i.source == "attachment")
    if evidence.images:
        items.append(_item("Images", "not_checked", "images_not_examined", f"{len(evidence.images)} image(s)", by_design=True))
    if attachment_images:
        items.append(_item("Images", "not_checked", "qr_not_decoded", "QR codes in image attachments", detail=f"{attachment_images} image(s)", blocks=True))
    if evidence.body.has_html:
        items.append(_item("Body", "not_checked", "not_rendered", "HTML body", by_design=True))
    return items


def build_coverage_report(parsed: ParsedEmail, module_results: list[ModuleResult], evidence: Evidence | None = None) -> list[CoverageItem]:
    by_module = {m.module: m for m in module_results}
    evidence = evidence if evidence is not None else build_evidence(parsed, module_results)
    return (_authentication(parsed, by_module.get("auth_check")) + _enrichment(by_module.get("enrichment"))
            + _content(by_module.get("content_analysis")) + _surfaces(evidence))
