from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RawAddress:
    display_name: str | None
    address: str | None


@dataclass
class RawAttachment:
    filename: str | None
    content_type: str | None
    content: bytes
    is_inline: bool = False


@dataclass
class RawUnlistedPart:
    """A part of the message that is NOT the body and is NOT in `attachments` (the attachment list requires a filename): an inline image referenced as cid:, a message/rfc822 or a calendar part
    without a name. Metadata for blocker detection only: it is never hashed, never looked up, never listed."""

    content_type: str | None
    content: bytes
    is_inline: bool = False
    has_content_id: bool = False


@dataclass
class RawParseResult:
    """Internal, format-agnostic parse output. Not part of the public contract —
    both eml_parser and msg_parser produce this shape, and normalize.py converts it
    into the public ParsedEmail model."""

    source_format: str  # "eml" | "msg"
    raw_size_bytes: int
    message_id: str | None = None
    subject: str | None = None
    date: datetime | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    from_addr: RawAddress | None = None
    to: list[RawAddress] = field(default_factory=list)
    cc: list[RawAddress] = field(default_factory=list)
    reply_to: list[RawAddress] = field(default_factory=list)
    return_path: RawAddress | None = None
    received_raw: list[str] = field(default_factory=list)
    authentication_results_raw: list[str] = field(default_factory=list)
    body_text: str | None = None
    body_html: str | None = None
    attachments: list[RawAttachment] = field(default_factory=list)
    unlisted_parts: list[RawUnlistedPart] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
