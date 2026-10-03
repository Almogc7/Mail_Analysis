import email
import email.policy
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import parseaddr

from app.parser.addresses import AMBIGUITY_PREFIX, parse_address_header
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


# Headers whose ambiguity is worth surfacing (they decide who the sender appears to be). For To/Cc a list
# of several addresses is normal, so only an unusable strict parse matters there.
_AMBIGUITY_HEADERS = {"from", "reply-to"}


def _raw_header_text(msg: EmailMessage, header_name: str) -> str | None:
    """The header exactly as received (unfolded by the caller), not the policy's interpretation of it."""
    for name, value in msg.raw_items():
        if name.lower() == header_name:
            text = str(value)
            try:  # 8-bit bytes arrive as surrogate escapes; recover them as UTF-8
                text = text.encode("ascii", "surrogateescape").decode("utf-8", "replace")
            except UnicodeError:
                pass
            return text
    return None


def _addresses(msg: EmailMessage, header_name: str, warnings: list[str] | None) -> list[RawAddress]:
    """Strict parse when it is clean AND agrees with the tolerant one; otherwise the tolerant parse (the
    address in the angle brackets), with the reasons recorded as a parse warning. Well-formed mail is
    unchanged; a malformed From (unquoted comma in the display name, ...) no longer loses its domain."""
    strict = _to_raw_addresses(msg, header_name)
    raw = _raw_header_text(msg, header_name)
    if raw is None:
        return strict
    robust = parse_address_header(raw)
    robust_specs = [a.lower() for _, a in robust.addresses]
    strict_ok = bool(strict) and all(a.address and "@" in a.address for a in strict) and [
        (a.address or "").lower() for a in strict
    ] == robust_specs
    reasons = list(robust.reasons if header_name in _AMBIGUITY_HEADERS else [r for r in robust.reasons if not r.startswith("multiple")])
    if strict_ok and not reasons:
        return strict  # clean and unambiguous
    chosen = strict
    if not strict_ok and robust.addresses:
        chosen = [RawAddress(display_name=name, address=addr) for name, addr in robust.addresses]
        reasons.append("the standard parser's result was unusable; address recovered from the angle brackets")
    if warnings is not None and header_name in _AMBIGUITY_HEADERS and reasons:
        warnings.append(f"{AMBIGUITY_PREFIX}:{header_name}: " + "; ".join(dict.fromkeys(reasons)))
    return chosen


def _to_single_raw_address(msg: EmailMessage, header_name: str, warnings: list[str] | None = None) -> RawAddress | None:
    addrs = _addresses(msg, header_name, warnings)
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
        from_addr=_to_single_raw_address(msg, "from", warnings),
        to=_addresses(msg, "to", warnings),
        cc=_addresses(msg, "cc", warnings),
        reply_to=_addresses(msg, "reply-to", warnings),
        return_path=_to_single_raw_address(msg, "return-path"),
        received_raw=received_raw,
        authentication_results_raw=auth_results_raw,
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        parse_warnings=warnings,
    )
