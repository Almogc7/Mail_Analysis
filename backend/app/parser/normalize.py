import hashlib
import ipaddress
import re
import unicodedata
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup

from app.contracts.email import (
    Attachment,
    EmailAddress,
    ExtractedUrl,
    HeaderField,
    ImageRef,
    ParsedEmail,
    ReceivedHop,
    ReceivedSpf,
    UnlistedPart,
)
from app.parser.raw import RawAddress, RawAttachment, RawParseResult

_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_RECEIVED_FROM_RE = re.compile(r"from\s+(\S+)", re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].lower()


def _to_email_address(raw: RawAddress | None) -> EmailAddress | None:
    if raw is None:
        return None
    return EmailAddress(
        display_name=raw.display_name,
        address=raw.address,
        domain=_domain_of(raw.address),
    )


def _to_email_address_list(raws: list[RawAddress]) -> list[EmailAddress]:
    return [addr for r in raws if (addr := _to_email_address(r)) is not None]


_RECEIVED_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9_\-]+)", re.IGNORECASE)
_RECEIVED_ENVELOPE_FROM_RE = re.compile(r"\(envelope-from\s+<?([^>)\s]*)>?\)", re.IGNORECASE)
_RECEIVED_FROM_CLAUSE_RE = re.compile(r"\bfrom\s+(.*?)(?:\s+by\s|$)", re.IGNORECASE | re.DOTALL)
_IP_CANDIDATE_RE = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9A-Fa-f:.]{3,45})\s*[\])]")
_AUTH_PROTOCOLS = {"esmtpa", "esmtpsa", "lmtpa", "lmtpsa", "smtpa"}
_LOCAL_RE = re.compile(r"\(Postfix, from userid \d+\)", re.IGNORECASE)


def _first_ip_in_from_clause(raw_line: str) -> str | None:
    clause = _RECEIVED_FROM_CLAUSE_RE.search(raw_line)
    if not clause:
        return None
    for m in _IP_CANDIDATE_RE.finditer(clause.group(1)):
        try:
            return str(ipaddress.ip_address(m.group(1)))
        except ValueError:
            continue
    return None


def _parse_received_hop(raw_line: str) -> ReceivedHop:
    from_match = _RECEIVED_FROM_RE.search(raw_line)
    by_match = _RECEIVED_BY_RE.search(raw_line)
    timestamp = None
    if ";" in raw_line:
        date_part = raw_line.rsplit(";", 1)[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_part)
        except (TypeError, ValueError):
            timestamp = None
    # The protocol is the "with X" after the by-clause. An earlier "(using TLSv1.2 with cipher
    # ...)" comment in the from-clause must not be mistaken for it.
    with_match = _RECEIVED_WITH_RE.search(raw_line, by_match.end() if by_match else 0)
    protocol = with_match.group(1) if with_match else None
    proto_l = (protocol or "").lower()
    envelope = _RECEIVED_ENVELOPE_FROM_RE.search(raw_line)
    return ReceivedHop(
        raw=raw_line,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        timestamp=timestamp,
        from_ip=_first_ip_in_from_clause(raw_line),
        protocol=protocol,
        envelope_from=envelope.group(1) or None if envelope else None,
        is_local_submission=proto_l == "local" or bool(_LOCAL_RE.search(raw_line)),
        authenticated=proto_l in _AUTH_PROTOCOLS or bool(re.search(r"\(Authenticated sender:|\bauthenticated\b", raw_line, re.IGNORECASE)),
        tls=proto_l in {"esmtps", "esmtpsa", "lmtps", "lmtpsa"} or bool(re.search(r"\bTLS|/TLS/", raw_line, re.IGNORECASE)),
    )


_SPF_RESULT_RE = re.compile(r"^\s*([A-Za-z]+)")
_SPF_COMMENT_RECEIVER_RE = re.compile(r"\(\s*([^\s:()]+)\s*:")
_SPF_PROP_RE = re.compile(r'([A-Za-z][\w-]*)\s*=\s*("[^"]*"|[^;\s]+)')
_SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def _parse_received_spf(value: str, header_index: int) -> ReceivedSpf:
    one_line = " ".join(value.split())
    m = _SPF_RESULT_RE.match(one_line)
    word = m.group(1).lower() if m else ""
    result = word if word in _SPF_RESULTS else "unknown"
    comment_end = one_line.find(")")
    rest = one_line[comment_end + 1 :] if one_line.lstrip().startswith(word) and "(" in one_line[:40] and comment_end != -1 else one_line
    props = {k.lower(): v.strip('"') for k, v in _SPF_PROP_RE.findall(rest)}
    comment = _SPF_COMMENT_RECEIVER_RE.search(one_line)
    return ReceivedSpf(
        result=result,
        raw=one_line,
        header_index=header_index,
        receiver=props.get("receiver") or (comment.group(1) if comment else None),
        client_ip=props.get("client-ip"),
        envelope_from=props.get("envelope-from"),
        identity=props.get("identity"),
        x_conformance=props.get("x-conformance"),
    )


def _extract_urls_from_text(text: str | None) -> list[ExtractedUrl]:
    if not text:
        return []
    return [ExtractedUrl(url=m.group(0), source="body_text") for m in _URL_RE.finditer(text)]


def _clean_text(text: str) -> str:
    """Collapse all whitespace (CR/LF, tabs, NBSP) and drop invisible format characters
    (zero-width space/joiners, bidi marks). Without this, anchor text that wraps across lines
    or hides a zero-width char reads as one string but compares as another."""
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return " ".join(text.split())


_HREF_CONTROL_RE = re.compile(r"[\t\r\n]")  # browsers drop these inside URLs


def _extract_urls_from_html(html: str | None) -> list[ExtractedUrl]:
    if not html:
        return []
    urls: list[ExtractedUrl] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = _HREF_CONTROL_RE.sub("", anchor["href"].strip())
        if not href.lower().startswith(("http://", "https://")):
            continue
        anchor_text = _clean_text(anchor.get_text()) or None
        is_mismatch = bool(
            anchor_text
            and _URL_RE.match(anchor_text)
            and anchor_text.rstrip("/") != href.rstrip("/")
        )
        urls.append(
            ExtractedUrl(
                url=href,
                source="body_html",
                anchor_text=anchor_text,
                is_anchor_mismatch=is_mismatch,
            )
        )
    return urls


def _extract_images_from_html(html: str | None) -> list[ImageRef]:
    """http(s) <img src> references, deduplicated by URL in document order."""
    if not html:
        return []
    images: list[ImageRef] = []
    seen: set[str] = set()
    for img in BeautifulSoup(html, "html.parser").find_all("img", src=True):
        src = _HREF_CONTROL_RE.sub("", img["src"].strip())
        if src.startswith("//"):
            src = "https:" + src
        if not src.lower().startswith(("http://", "https://")) or src in seen:
            continue
        seen.add(src)
        images.append(
            ImageRef(
                url=src,
                alt=_clean_text(img.get("alt", "")) or None,
                width=str(img["width"]) if img.get("width") else None,
                height=str(img["height"]) if img.get("height") else None,
            )
        )
    return images


def _count_data_images(html: str | None) -> int:
    """How many <img> tags carry a data: source (an image embedded in the message itself). `_extract_images_from_html` keeps only http(s) sources, so these are dropped from `images`; this keeps
    their NUMBER and nothing else (no content): a picture the message carries may hold a QR code, which is why it is a blocker for 'No indicators found' while QR decoding is off. Each tag counts
    once, the same data source twice counts twice, and the browsers' dropped control characters are removed first, as for any URL here. CSS backgrounds and srcset are not counted."""
    if not html:
        return 0
    return sum(1 for img in BeautifulSoup(html, "html.parser").find_all("img", src=True) if _HREF_CONTROL_RE.sub("", img["src"].strip()).lower().startswith("data:"))


def _describe_unlisted(raw) -> UnlistedPart:
    """Metadata only (type, size, two flags, the first 16 bytes kept out of every serialisation). The content is never hashed and never leaves this function."""
    return UnlistedPart(content_type=raw.content_type, size_bytes=len(raw.content), is_inline=raw.is_inline, has_content_id=raw.has_content_id, first_bytes=raw.content[:16])


def _hash_attachment(raw: RawAttachment) -> Attachment:
    content = raw.content
    return Attachment(
        filename=raw.filename,
        content_type=raw.content_type,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        sha1=hashlib.sha1(content).hexdigest(),
        md5=hashlib.md5(content).hexdigest(),
        is_inline=raw.is_inline,
        first_bytes=content[:16],  # metadata only, never serialised (see contracts/email.py); taken here, before the content is dropped
    )


def to_parsed_email(raw: RawParseResult) -> ParsedEmail:
    urls = _extract_urls_from_text(raw.body_text) + _extract_urls_from_html(raw.body_html)

    return ParsedEmail(
        source_format=raw.source_format,
        message_id=raw.message_id,
        subject=raw.subject,
        date=raw.date,
        headers=[HeaderField(name=name, value=value) for name, value in raw.headers],
        from_=_to_email_address(raw.from_addr) or EmailAddress(),
        to=_to_email_address_list(raw.to),
        cc=_to_email_address_list(raw.cc),
        reply_to=_to_email_address_list(raw.reply_to),
        return_path=_to_email_address(raw.return_path),
        received_chain=[_parse_received_hop(line) for line in raw.received_raw],
        authentication_results_raw=raw.authentication_results_raw,
        received_spf=[
            _parse_received_spf(value, i) for i, (name, value) in enumerate(raw.headers) if name.lower() == "received-spf"
        ],
        body_text=raw.body_text,
        body_html=raw.body_html,
        urls=urls,
        images=_extract_images_from_html(raw.body_html),
        data_image_count=_count_data_images(raw.body_html),
        attachments=[_hash_attachment(a) for a in raw.attachments],
        unlisted_parts=[_describe_unlisted(p) for p in raw.unlisted_parts],
        parse_warnings=raw.parse_warnings,
        raw_size_bytes=raw.raw_size_bytes,
    )
