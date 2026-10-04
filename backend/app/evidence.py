"""The evidence block: everything the message shows, organised by surface (sender and authentication, Received-hop timeline, links,
attachments, body facts, images) so one page can present it. Built from data the analysis already holds; it adds NOTHING to the score and
changes no verdict (docs/DESIGN_V2.md, phase A).

Rules this module keeps:
  * metadata only for attachments and images: nothing is opened, decoded, fetched or rendered;
  * links are carried as text with a defanged form; the app never resolves them;
  * the body text is not copied into this block (it is already in parsed_email.body_text, held in memory only, see D5): only counts are.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from app.contracts.analysis import (
    AttachmentEntry, AuthRow, BodyInfo, Evidence, HopEntry, ImageEntry, IndicatorPack, LinkEntry, SenderEvidence,
)
from app.contracts.email import ParsedEmail
from app.contracts.findings import ModuleResult
from app.enrichment.policy import host_of, platform_of
from app.hops import hidden_indexes, is_unverified, trust_boundary, trusted_hop_indexes
from app.shared.matching import registrable_domain

_TEXT_CAP = 200

_EXT_CLASSES: dict[str, tuple[str, bool]] = {}  # extension -> (risk class, active content possible)
for _ext in ("doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "odt", "ods", "one"):
    _EXT_CLASSES[_ext] = ("office", True)  # macros cannot be ruled out without parsing the file
_EXT_CLASSES["pdf"] = ("pdf", True)
for _ext in ("zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"):
    _EXT_CLASSES[_ext] = ("archive", True)
for _ext in ("iso", "img", "vhd", "vhdx"):
    _EXT_CLASSES[_ext] = ("disk_image", True)
for _ext in ("html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"):
    _EXT_CLASSES[_ext] = ("html", True)
for _ext in ("js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "wsf", "hta", "lnk", "jar"):
    _EXT_CLASSES[_ext] = ("script", True)
for _ext in ("exe", "scr", "dll", "msi", "com", "pif"):
    _EXT_CLASSES[_ext] = ("executable", True)
for _ext in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico"):
    _EXT_CLASSES[_ext] = ("image", False)
for _ext in ("ics", "vcs"):
    _EXT_CLASSES[_ext] = ("calendar", False)
for _ext in ("txt", "csv", "xml", "json", "log"):
    _EXT_CLASSES[_ext] = ("text", False)
for _ext in ("eml", "msg"):
    _EXT_CLASSES[_ext] = ("mail_message", True)  # a message inside a message carries its own links and attachments

_PLATFORM_KIND = {"esp_tracker": "tracker", "link_wrapper": "wrapper", "shortener": "shortener",
                  "cloud_content": "shared_platform", "site_builder": "shared_platform"}


def _replace_ci(text: str, old: str, new: str) -> str:
    out, lower, i = [], text.lower(), 0
    while True:
        j = lower.find(old, i)
        if j < 0:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i:j])
        out.append(new)
        i = j + len(old)


def defang_url(url: str) -> str:
    """hxxps://example[.]org/path: cannot be clicked or auto-linked. EVERY http(s):// occurrence is neutralised (a wrapper URL carries another
    URL inside its path), and every dot and every @ is bracketed."""
    text = _replace_ci(_replace_ci(url.strip(), "https://", "hxxps://"), "http://", "hxxp://")
    return text.replace(".", "[.]").replace("@", "[@]")


def _cap(text: str | None) -> str | None:
    if text is None:
        return None
    text = " ".join(text.split())
    return text[:_TEXT_CAP] + ("..." if len(text) > _TEXT_CAP else "") if text else None


def attachment_class(filename: str | None, content_type: str | None) -> tuple[str, bool, str | None, bool]:
    """(risk_class, active_content, extension, double_extension)."""
    name = (filename or "").strip().lower()
    ext = name.rsplit(".", 1)[1] if "." in name else None
    risk, active = _EXT_CLASSES.get(ext or "", (None, False))
    if risk is None:
        ctype = (content_type or "").lower()
        if ctype.startswith("image/"):
            risk, active = "image", False
        elif ctype in ("text/html", "application/xhtml+xml"):
            risk, active = "html", True
        elif ctype == "application/pdf":
            risk, active = "pdf", True
        elif ctype in ("application/zip", "application/x-zip-compressed", "application/x-rar-compressed", "application/x-7z-compressed", "application/gzip"):
            risk, active = "archive", True
        else:
            risk, active = "other", False
    double = False
    if ext and name.count(".") >= 2 and risk in ("script", "executable"):
        inner = name.rsplit(".", 2)[1]
        double = _EXT_CLASSES.get(inner, ("", False))[0] in ("office", "pdf", "image", "text")
    return risk, active, ext, double


def _is_redirector(url: str, host: str | None) -> bool:
    """The query string carries another full URL that points at a different registrable domain (an open-redirect shape)."""
    try:
        query = parse_qsl(urlsplit(url).query)
    except ValueError:
        return False
    own = registrable_domain(host) if host else None
    for _, value in query:
        if value.lower().startswith(("http://", "https://")):
            target = host_of(value)
            if target and registrable_domain(target) != own:
                return True
    return False


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _hop_timeline(parsed: ParsedEmail, auth: ModuleResult | None) -> list[HopEntry]:
    chain = list(parsed.received_chain)  # newest first
    trusted_newest_index = trusted_hop_indexes(auth)
    boundary = trust_boundary(auth)
    hidden = hidden_indexes(chain, auth)  # display only: scoring and coverage never see this
    timeline: list[HopEntry] = []
    previous = None
    for position, newest_index in enumerate(range(len(chain) - 1, -1, -1)):
        hop = chain[newest_index]
        delay = skew = None
        if hop.timestamp is not None and previous is not None:
            delay = (hop.timestamp - previous).total_seconds()
        skew = bool(delay is not None and delay < 0)
        unverified = is_unverified(newest_index, boundary)
        if newest_index in hidden:
            # Hidden by local config (and above the trust boundary): keep only what the timeline needs. No names, no address.
            timeline.append(HopEntry(
                index=position + 1, timestamp=_iso(hop.timestamp), delay_seconds_from_previous=delay, clock_skew=skew,
                trusted_receiver=newest_index in trusted_newest_index, is_origin=position == 0, internal=True, unverified=False,
            ))
        else:
            timeline.append(HopEntry(
                index=position + 1, from_host=hop.from_host, by_host=hop.by_host, from_ip=hop.from_ip, protocol=hop.protocol, tls=hop.tls,
                authenticated=hop.authenticated, local_submission=hop.is_local_submission, timestamp=_iso(hop.timestamp),
                delay_seconds_from_previous=delay, clock_skew=skew, trusted_receiver=newest_index in trusted_newest_index,
                is_origin=position == 0, unverified=unverified,
            ))
        if hop.timestamp is not None:
            previous = hop.timestamp
    return timeline


def _sender(parsed: ParsedEmail, auth: ModuleResult | None) -> SenderEvidence:
    sender = SenderEvidence(from_address=parsed.from_, reply_to=parsed.reply_to[0] if parsed.reply_to else None, return_path=parsed.return_path)
    if auth is None or auth.status != "ok":
        return sender
    raw = auth.raw_data or {}
    headers = raw.get("auth_headers") or {}
    sender.trusted_receivers_configured = bool(headers.get("trusted_receivers_configured"))
    for method in ("spf", "dkim", "dmarc"):
        entry = headers.get(method) or {}
        evaluated = bool(entry.get("evaluated"))
        sender.auth.append(AuthRow(
            method=method, evaluated=evaluated, result=entry.get("result") if evaluated else None,
            receiver=((entry.get("trust_basis") or {}).get("host") if evaluated else None),
            reason=None if evaluated else entry.get("reason"), source=entry.get("source") if evaluated else None,
        ))
    alignment = raw.get("alignment") or {}
    for key in ("spf", "dkim"):
        value = (alignment.get(key) or {}).get("aligned")
        sender.alignment[key] = value if isinstance(value, bool) else None
    equal = alignment.get("envelope_equals_from")
    sender.alignment["envelope_equals_from"] = equal if isinstance(equal, bool) else None
    identity = raw.get("identity") or {}
    if (identity.get("from_return_path_mismatch") or {}).get("mismatch"):
        sender.mismatches.append("The From domain and the Return-Path domain belong to different organisations")
    if (identity.get("from_reply_to_mismatch") or {}).get("mismatch"):
        sender.mismatches.append("The From domain and the Reply-To domain belong to different organisations")
    return sender


def _links(parsed: ParsedEmail, indicators: IndicatorPack | None) -> list[LinkEntry]:
    status_by_host = {i.value: i.status for i in (indicators.indicators if indicators else []) if i.kind in ("domain", "ip")}
    grouped: dict[str, LinkEntry] = {}
    for u in parsed.urls:
        entry = grouped.get(u.url)
        if entry is None:
            host = host_of(u.url)
            platform = platform_of(host)
            kind = _PLATFORM_KIND.get(platform.kind, "direct") if platform else "direct"
            if kind == "direct" and _is_redirector(u.url, host):
                kind = "redirector"
            entry = grouped[u.url] = LinkEntry(
                url=u.url, url_defanged=defang_url(u.url), host=host, registrable_domain=registrable_domain(host) if host else None,
                display_text=_cap(u.anchor_text), kind=kind, platform=platform.name if platform else None, occurrences=0,
                status=status_by_host.get(host or "", "n/a"),
            )
        entry.occurrences += 1
        entry.anchor_mismatch = entry.anchor_mismatch or u.is_anchor_mismatch
        if u.source not in entry.sources:
            entry.sources.append(u.source)
        if entry.display_text is None and u.anchor_text:
            entry.display_text = _cap(u.anchor_text)
    return list(grouped.values())


def _attachments(parsed: ParsedEmail) -> list[AttachmentEntry]:
    out = []
    for a in parsed.attachments:
        risk, active, ext, double = attachment_class(a.filename, a.content_type)
        out.append(AttachmentEntry(filename=_cap(a.filename), declared_type=a.content_type, extension=ext, size_bytes=a.size_bytes, sha256=a.sha256,
                                   risk_class=risk, active_content=active, double_extension=double))
    return out


def _body(parsed: ParsedEmail, content: ModuleResult | None, link_count: int) -> BodyInfo:
    language = ((content.raw_data or {}).get("language") or {}) if content is not None and content.status == "ok" else {}
    html = parsed.body_html or ""
    return BodyInfo(
        language=language.get("language"), language_status=language.get("status"), text_chars=len(parsed.body_text or ""), html_chars=len(html),
        has_html=bool(html), forms=html.lower().count("<form"), remote_images=sum(1 for i in parsed.images if host_of(i.url)), links=link_count,
    )


def _images(parsed: ParsedEmail) -> list[ImageEntry]:
    out = [ImageEntry(source="html", host=host_of(i.url), url_defanged=defang_url(i.url)) for i in parsed.images]
    for a in parsed.attachments:
        if attachment_class(a.filename, a.content_type)[0] == "image":
            out.append(ImageEntry(source="attachment", filename=_cap(a.filename), size_bytes=a.size_bytes))
    return out


def build_evidence(parsed: ParsedEmail, module_results: list[ModuleResult], indicators: IndicatorPack | None = None) -> Evidence:
    by_module = {m.module: m for m in module_results}
    links = _links(parsed, indicators)
    return Evidence(
        sender=_sender(parsed, by_module.get("auth_check")), hop_timeline=_hop_timeline(parsed, by_module.get("auth_check")), links=links,
        attachments=_attachments(parsed), body=_body(parsed, by_module.get("content_analysis"), len(links)), images=_images(parsed),
    )
