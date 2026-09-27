from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class EmailAddress(BaseModel):
    display_name: str | None = None
    address: str | None = None
    domain: str | None = None


class HeaderField(BaseModel):
    name: str
    value: str


class ReceivedHop(BaseModel):
    raw: str
    from_host: str | None = None
    by_host: str | None = None
    timestamp: datetime | None = None


class ExtractedUrl(BaseModel):
    url: str
    source: Literal["body_text", "body_html", "attachment"]
    anchor_text: str | None = None
    is_anchor_mismatch: bool = False


class Attachment(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    is_inline: bool = False


class ParsedEmail(BaseModel):
    source_format: Literal["eml", "msg"]
    message_id: str | None = None
    subject: str | None = None
    date: datetime | None = None
    headers: list[HeaderField] = []
    from_: EmailAddress
    to: list[EmailAddress] = []
    cc: list[EmailAddress] = []
    reply_to: list[EmailAddress] = []
    return_path: EmailAddress | None = None
    received_chain: list[ReceivedHop] = []
    authentication_results_raw: list[str] = []
    body_text: str | None = None
    body_html: str | None = None
    urls: list[ExtractedUrl] = []
    attachments: list[Attachment] = []
    parse_warnings: list[str] = []
    raw_size_bytes: int
