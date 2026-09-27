import email
import email.policy
import re
import tempfile
from datetime import datetime
from pathlib import Path

import extract_msg

from app.parser.raw import RawAddress, RawAttachment, RawParseResult

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
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if len(parts) <= 1 and "," in raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
    return [addr for p in parts if (addr := _split_address(p)) is not None]


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
        except Exception as exc:
            warnings.append(f"Failed to parse embedded raw headers: {exc}")
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
            content = b""
        attachments.append(
            RawAttachment(
                filename=att.longFilename or att.shortFilename,
                content_type=None,
                content=content,
                is_inline=False,
            )
        )

    return RawParseResult(
        source_format="msg",
        raw_size_bytes=len(raw_bytes),
        message_id=getattr(msg, "messageId", None),
        subject=msg.subject,
        date=msg.date if isinstance(msg.date, datetime) else None,
        headers=headers,
        from_addr=_split_address(msg.sender),
        to=_split_address_list(msg.to),
        cc=_split_address_list(msg.cc),
        reply_to=_split_address_list(getattr(msg, "replyTo", None)),
        return_path=None,
        received_raw=received_raw,
        authentication_results_raw=auth_results_raw,
        body_text=msg.body,
        body_html=getattr(msg, "htmlBody", None) if isinstance(getattr(msg, "htmlBody", None), str) else None,
        attachments=attachments,
        parse_warnings=warnings,
    )
