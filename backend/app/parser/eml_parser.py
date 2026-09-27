import email
import email.policy
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import parseaddr

from app.parser.raw import RawAddress, RawAttachment, RawParseResult


def _to_raw_addresses(msg: EmailMessage, header_name: str) -> list[RawAddress]:
    try:
        addresses = msg.get(header_name)
    except (LookupError, TypeError):
        return []
    if addresses is None:
        return []
    result: list[RawAddress] = []
    for addr in getattr(addresses, "addresses", [addresses]):
        if isinstance(addr, Address):
            result.append(
                RawAddress(display_name=addr.display_name or None, address=addr.addr_spec or None)
            )
    return result


def _to_single_raw_address(msg: EmailMessage, header_name: str) -> RawAddress | None:
    addrs = _to_raw_addresses(msg, header_name)
    if addrs:
        return addrs[0]
    # Some headers (e.g. Return-Path) aren't registered as structured address headers
    # under email.policy.default, so they come back as plain unstructured text.
    raw_value = msg.get(header_name)
    if raw_value is None:
        return None
    display_name, address = parseaddr(str(raw_value))
    if not address:
        return None
    return RawAddress(display_name=display_name or None, address=address)


def parse_eml(raw_bytes: bytes) -> RawParseResult:
    warnings: list[str] = []
    msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    headers: list[tuple[str, str]] = []
    received_raw: list[str] = []
    auth_results_raw: list[str] = []
    for name, value in msg.items():
        str_value = str(value)
        headers.append((name, str_value))
        if name.lower() == "received":
            received_raw.append(str_value)
        elif name.lower() == "authentication-results":
            auth_results_raw.append(str_value)

    body_text: str | None = None
    body_html: str | None = None
    attachments: list[RawAttachment] = []

    try:
        body_part = msg.get_body(preferencelist=("plain",))
        if body_part is not None:
            body_text = body_part.get_content()
    except Exception as exc:
        warnings.append(f"Failed to extract text body: {exc}")

    try:
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            body_html = html_part.get_content()
    except Exception as exc:
        warnings.append(f"Failed to extract html body: {exc}")

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_disposition = part.get_content_disposition()
        if content_disposition in ("attachment", "inline") and part.get_filename():
            try:
                content = part.get_payload(decode=True) or b""
            except Exception as exc:
                warnings.append(f"Failed to decode attachment '{part.get_filename()}': {exc}")
                content = b""
            attachments.append(
                RawAttachment(
                    filename=part.get_filename(),
                    content_type=part.get_content_type(),
                    content=content,
                    is_inline=(content_disposition == "inline"),
                )
            )

    date_header = msg.get("date")
    date_value = None
    if date_header is not None:
        try:
            date_value = date_header.datetime
        except Exception as exc:
            warnings.append(f"Failed to parse Date header: {exc}")

    return RawParseResult(
        source_format="eml",
        raw_size_bytes=len(raw_bytes),
        message_id=msg.get("message-id"),
        subject=msg.get("subject"),
        date=date_value,
        headers=headers,
        from_addr=_to_single_raw_address(msg, "from"),
        to=_to_raw_addresses(msg, "to"),
        cc=_to_raw_addresses(msg, "cc"),
        reply_to=_to_raw_addresses(msg, "reply-to"),
        return_path=_to_single_raw_address(msg, "return-path"),
        received_raw=received_raw,
        authentication_results_raw=auth_results_raw,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        parse_warnings=warnings,
    )
