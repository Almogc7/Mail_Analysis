from typing import Literal

from pydantic import BaseModel

from app.contracts.email import EmailAddress, ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.contracts.llm_opinion import LLMOpinion
from app.contracts.scoring import ScoringBreakdown

Verdict = Literal["malicious", "suspicious", "benign", "inconclusive"]

IndicatorStatus = Literal["provider_hit", "unknown", "shared_platform", "not_looked_up", "internal", "nothing_found", "n/a"]


class Pivot(BaseModel):
    """A plain hyperlink to look an indicator up by hand. The app never contacts it."""

    name: str
    url: str


class Indicator(BaseModel):
    """One domain, IP, email address or file hash found in the message. Adds nothing to the score."""

    kind: Literal["domain", "ip", "email", "hash"]
    value: str
    seen_in: list[str] = []
    count: int = 0
    status: IndicatorStatus = "n/a"
    note: str = ""
    providers: dict[str, str] = {}
    pivots: list[Pivot] = []
    # unknown / shared-platform / not looked up: shown as something for the analyst to check, never as clean
    manual_check: bool = False
    filename: str | None = None
    # Seen ONLY in hops hidden by the local INTERNAL_HOP_PATTERNS. The full pack (used by evidence and coverage) keeps them; the response never does.
    hidden_by_config: bool = False
    # The address of a trusted receiver itself (it wrote a trusted authentication result): the analyst's own gateway, so there is nothing to check by hand.
    # The full pack keeps manual_check as computed; only the response pack clears it (see visible_pack).
    gateway: bool = False


class IndicatorPack(BaseModel):
    indicators: list[Indicator] = []
    counts: dict[str, int] = {}
    manual_check_count: int = 0
    hidden_by_config_count: int = 0  # how many indicators were left out of the response because they came only from hidden hops


class HopEntry(BaseModel):
    """One Received hop, OLDEST FIRST (index 1 is where the message entered the mail system)."""

    index: int
    from_host: str | None = None
    by_host: str | None = None
    from_ip: str | None = None
    protocol: str | None = None
    tls: bool = False
    authenticated: bool = False
    local_submission: bool = False
    timestamp: str | None = None
    delay_seconds_from_previous: float | None = None
    clock_skew: bool = False  # the timestamp is earlier than the previous hop's: a clock is wrong or a header was edited
    trusted_receiver: bool = False  # this hop wrote an authentication result the app trusts
    is_origin: bool = False
    internal: bool = False  # hidden by local config (INTERNAL_HOP_PATTERNS), and only ever a hop at or above the first trusted hop: names and address are blanked, only timing remains
    unverified: bool = False  # below the trust boundary (or no trusted hop exists): written by whoever sent the message, so every field is a CLAIM


class AuthRow(BaseModel):
    method: str  # spf | dkim | dmarc
    evaluated: bool
    result: str | None = None
    receiver: str | None = None  # the trusted host that wrote the result, when evaluated
    reason: str | None = None  # why it was not evaluated
    source: str | None = None


class SenderEvidence(BaseModel):
    from_address: EmailAddress | None = None
    reply_to: EmailAddress | None = None
    return_path: EmailAddress | None = None
    auth: list[AuthRow] = []
    alignment: dict[str, bool | None] = {}
    mismatches: list[str] = []
    trusted_receivers_configured: bool = False


class LinkEntry(BaseModel):
    """A link in the message. Never opened, never resolved, never rendered as a clickable link by the UI."""

    url: str
    url_defanged: str
    host: str | None = None
    registrable_domain: str | None = None
    display_text: str | None = None
    kind: Literal["direct", "tracker", "wrapper", "shortener", "redirector", "shared_platform"] = "direct"
    platform: str | None = None
    anchor_mismatch: bool = False
    occurrences: int = 1
    sources: list[str] = []
    status: str = "n/a"  # the indicator status of its host (see IndicatorStatus)


class AttachmentEntry(BaseModel):
    """Metadata and hashes only: the file is never opened, never offered for download."""

    filename: str | None = None
    declared_type: str | None = None
    detected_type: str | None = None  # filled by static analysis (a later phase)
    extension: str | None = None
    size_bytes: int = 0
    sha256: str
    risk_class: str = "other"
    active_content: bool = False
    double_extension: bool = False
    static_analysis: dict | None = None  # filled by static analysis (a later phase)


class BodyInfo(BaseModel):
    language: str | None = None
    language_status: str | None = None
    text_chars: int = 0
    html_chars: int = 0
    has_html: bool = False
    forms: int = 0
    remote_images: int = 0
    links: int = 0


class ImageEntry(BaseModel):
    source: Literal["html", "attachment"]
    host: str | None = None
    url_defanged: str | None = None
    filename: str | None = None
    size_bytes: int | None = None
    decoded: list[dict] | None = None  # QR decoding is a later phase; None means "not decoded"


class Evidence(BaseModel):
    sender: SenderEvidence = SenderEvidence()
    hop_timeline: list[HopEntry] = []
    links: list[LinkEntry] = []
    attachments: list[AttachmentEntry] = []
    body: BodyInfo = BodyInfo()
    images: list[ImageEntry] = []


class CoverageItem(BaseModel):
    """One line of 'what was checked, what was not, and why'. Built from data the analysis already holds; adds nothing to the score."""

    area: str
    subject: str | None = None
    status: Literal["checked", "partly", "not_checked"]
    reason: str = ""  # a stable code, e.g. no_trusted_receiver_configured, no_api_key, never_opened
    detail: str = ""  # counts and plain words only: never an indicator, address, URL or text from the message
    by_design: bool = False  # the app never does this on purpose (it never opens links or attachments)
    blocks_no_indicators: bool = False  # an unchecked high-risk surface: once verdict v2 is active, it blocks "No indicators found"
    how_to_clear: str = ""


class AnalysisResult(BaseModel):
    parsed_email: ParsedEmail
    module_results: list[ModuleResult] = []
    findings: list[Finding] = []
    score: int | None = None
    verdict: Verdict | None = None
    confidence: float | None = None
    scoring: ScoringBreakdown | None = None
    llm_opinion: LLMOpinion | None = None
    indicators: IndicatorPack | None = None
    # Workbench blocks (docs/DESIGN_V2.md, phase A). All optional and additive: an older result without them still parses, and an older
    # client ignores them. schema_version is 2 when the blocks are present.
    schema_version: int = 1
    evidence: Evidence | None = None
    coverage_report: list[CoverageItem] | None = None
