from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    display_name: str | None = None
    address: str | None = None
    domain: str | None = None


class HeaderField(BaseModel):
    name: str
    value: str


class ReceivedHop(BaseModel):
    """One Received header. ParsedEmail.received_chain is in header order, i.e. NEWEST hop
    first: received_chain[-1] is the first hop (where the message entered the mail system)."""

    raw: str
    from_host: str | None = None
    by_host: str | None = None
    timestamp: datetime | None = None
    # Structured fields (best-effort; None/False when the MTA's format doesn't expose them).
    from_ip: str | None = None  # first IP in the from-clause, e.g. "from h (h [1.2.3.4])"
    protocol: str | None = None  # token after "with": ESMTP, ESMTPS, ESMTPSA, local, Microsoft, ...
    envelope_from: str | None = None  # Exim "(envelope-from <x>)"
    is_local_submission: bool = False  # Exim "with local", Postfix "(Postfix, from userid N)"
    authenticated: bool = False  # ESMTPA/ESMTPSA/LMTPA or an explicit "authenticated" marker
    tls: bool = False


class ReceivedSpf(BaseModel):
    """A Received-SPF header. NOT trusted by default: whoever controls the sending domain
    controls whether SPF passes for it, and any hop can add this header. `receiver` is the
    host that claims to have evaluated SPF, used to decide whether to trust it."""

    result: str  # pass | fail | softfail | neutral | none | temperror | permerror | unknown
    raw: str
    header_index: int  # position among ParsedEmail.headers
    receiver: str | None = None
    client_ip: str | None = None
    envelope_from: str | None = None
    identity: str | None = None  # mailfrom | helo
    x_conformance: str | None = None  # e.g. "spf_only" (Cisco ESA: DKIM/DMARC not evaluated)


class ExtractedUrl(BaseModel):
    url: str
    source: Literal["body_text", "body_html", "attachment"]
    anchor_text: str | None = None
    is_anchor_mismatch: bool = False


class ImageRef(BaseModel):
    """An <img src> from the HTML body. Kept out of ParsedEmail.urls on purpose: images are
    fetched automatically (not clicked), would crowd the per-email enrichment cap, and are
    evidence about the template (hot-linked/cloned assets), not about a link target."""

    url: str
    alt: str | None = None
    width: str | None = None
    height: str | None = None


class Attachment(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    is_inline: bool = False
    # The first (at most 16) bytes of the attachment, kept ONLY so metadata-level blocker detection (app/blockers.py) can read a magic number. It is excluded from every serialisation
    # (the API response, JSON, logs, the feedback record and the LLM prompt) and from the repr: it is never output. Additive: an older Attachment without it still builds.
    first_bytes: bytes = Field(default=b"", exclude=True, repr=False)


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
    received_spf: list[ReceivedSpf] = []
    body_text: str | None = None
    body_html: str | None = None
    urls: list[ExtractedUrl] = []
    images: list[ImageRef] = []
    attachments: list[Attachment] = []
    parse_warnings: list[str] = []
    raw_size_bytes: int
    # SHA256 of the file exactly as received (before any banner/tag stripping or decoding).
    raw_sha256: str | None = None
