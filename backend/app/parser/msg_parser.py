import email
import email.policy
import re
import tempfile
from datetime import datetime
from pathlib import Path

import extract_msg
from bs4 import UnicodeDammit

from app.parser.addresses import AMBIGUITY_PREFIX, parse_address_header
from app.parser.eml_parser import _raw_header_text
from app.parser.raw import RawAddress, RawAttachment, RawParseFlag, RawParseResult

_ADDR_RE = re.compile(r"^(?P<name>.*?)\s*<(?P<addr>[^<>]+)>\s*$")


def _split_address(raw: str | None) -> RawAddress | None:
    if not raw:
        return None
    raw = raw.strip()
    match = _ADDR_RE.match(raw)
    if match:
        name = match.group("name").strip().strip('"') or None
        return RawAddress(display_name=name, address=match.group("addr").strip())
    if "@" in raw:
        return RawAddress(display_name=None, address=raw)
    return RawAddress(display_name=raw, address=None)


def _split_address_list(raw: str | None) -> list[RawAddress]:
    """Outlook separates recipients with ';'. Without one, the tolerant extractor reads the list (splitting
    on commas would tear 'Doe, John <a@b>' apart)."""
    if not raw:
        return []
    if ";" in raw:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        return [addr for p in parts if (addr := _split_address(p)) is not None]
    parsed = parse_address_header(raw)
    if parsed.addresses:
        return [RawAddress(display_name=name, address=addr) for name, addr in parsed.addresses]
    single = _split_address(raw)
    return [single] if single is not None else []


def _decode_html_bytes(data: bytes | None) -> str | None:
    """extract_msg's htmlBody is always bytes (auto-generated from RTF or plain text when
    no direct HTML stream exists), never str -- decode it the same way BeautifulSoup's own
    encoding auto-detection works, since there's no reliable encoding hint exposed for it."""
    if not data:
        return None
    return UnicodeDammit(data).unicode_markup


def parse_msg(raw_bytes: bytes) -> RawParseResult:
    warnings: list[str] = []

    with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
        tmp.write(raw_bytes)
        tmp_path = Path(tmp.name)

    try:
        msg = extract_msg.Message(str(tmp_path))
        try:
            return _parse_extract_msg(msg, raw_bytes, warnings)
        finally:
            msg.close()
    finally:
        tmp_path.unlink(missing_ok=True)


def _parse_extract_msg(msg: "extract_msg.Message", raw_bytes: bytes, warnings: list[str]) -> RawParseResult:
    headers: list[tuple[str, str]] = []
    received_raw: list[str] = []
    auth_results_raw: list[str] = []
    flags: list[RawParseFlag] = []

    return_path: RawAddress | None = None
    header_from_raw: str | None = None

    raw_header_text = getattr(msg, "header", None)
    if raw_header_text:
        try:
            parsed_headers = email.message_from_string(str(raw_header_text), policy=email.policy.default)
            for name, value in parsed_headers.items():
                str_value = str(value)
                headers.append((name, str_value))
                if name.lower() == "received":
                    received_raw.append(str_value)
                elif name.lower() == "authentication-results":
                    auth_results_raw.append(str_value)
            return_path = _split_address(parsed_headers.get("return-path"))
            header_from_raw = _raw_header_text(parsed_headers, "from")
        except Exception as exc:
            warnings.append(f"Failed to parse embedded raw headers: {exc}")
            flags.append(RawParseFlag("header_parse_failed", "headers"))
    else:
        warnings.append(
            "No raw internet headers found in .msg file (Outlook may not have stored them); "
            "SPF/DKIM/DMARC results will be unavailable for this message."
        )

    if not auth_results_raw:
        warnings.append("No Authentication-Results header found — auth-check module will have nothing to parse.")

    attachments: list[RawAttachment] = []
    for att in msg.attachments:
        try:
            content = att.data if isinstance(att.data, bytes) else bytes(att.data or b"")
        except Exception as exc:
            warnings.append(f"Failed to read attachment '{att.longFilename or att.shortFilename}': {exc}")
            flags.append(RawParseFlag("attachment_read_failed", f"attachment:{len(attachments)}"))
            content = b""
        attachments.append(
            RawAttachment(
                filename=att.longFilename or att.shortFilename,
                content_type=None,
                content=content,
                # an attachment that carries a Content-ID is an inline (cid:) part; extract_msg lists every attachment, with or without a name, so there are no separate unlisted parts here
                is_inline=bool(getattr(att, "cid", None)),
            )
        )

    from_addr = _split_address(msg.sender)
    header_from = parse_address_header(header_from_raw) if header_from_raw else None
    if header_from is not None and header_from.reasons:
        warnings.append(f"{AMBIGUITY_PREFIX}:from: " + "; ".join(dict.fromkeys(header_from.reasons)))
    if (from_addr is None or not from_addr.address or "@" not in from_addr.address) and header_from and header_from.addresses:
        # msg.sender can be an Exchange DN or a bare display name; the raw From header carries the real address
        name, address = header_from.addresses[0]
        from_addr = RawAddress(display_name=name, address=address)

    return RawParseResult(
        source_format="msg",
        raw_size_bytes=len(raw_bytes),
        message_id=getattr(msg, "messageId", None),
        subject=msg.subject,
        date=msg.date if isinstance(msg.date, datetime) else None,
        headers=headers,
        from_addr=from_addr,
        to=_split_address_list(msg.to),
        cc=_split_address_list(msg.cc),
        reply_to=_split_address_list(getattr(msg, "replyTo", None)),
        return_path=return_path,
        received_raw=received_raw,
        authentication_results_raw=auth_results_raw,
        body_text=msg.body,
        body_html=_decode_html_bytes(getattr(msg, "htmlBody", None)),
        attachments=attachments,
        parse_flags=flags,
        parse_warnings=warnings,
    )
