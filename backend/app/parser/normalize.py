import hashlib
import re
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup

from app.contracts.email import (
    Attachment,
    EmailAddress,
    ExtractedUrl,
    HeaderField,
    ParsedEmail,
    ReceivedHop,
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
    return ReceivedHop(
        raw=raw_line,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        timestamp=timestamp,
    )


def _extract_urls_from_text(text: str | None) -> list[ExtractedUrl]:
    if not text:
        return []
    return [ExtractedUrl(url=m.group(0), source="body_text") for m in _URL_RE.finditer(text)]


def _extract_urls_from_html(html: str | None) -> list[ExtractedUrl]:
    if not html:
        return []
    urls: list[ExtractedUrl] = []
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        anchor_text = anchor.get_text(strip=True) or None
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
        body_text=raw.body_text,
        body_html=raw.body_html,
        urls=urls,
        attachments=[_hash_attachment(a) for a in raw.attachments],
        parse_warnings=raw.parse_warnings,
        raw_size_bytes=raw.raw_size_bytes,
    )
