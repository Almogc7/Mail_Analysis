from typing import Literal

from pydantic import BaseModel

from app.contracts.email import ParsedEmail
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


class IndicatorPack(BaseModel):
    indicators: list[Indicator] = []
    counts: dict[str, int] = {}
    manual_check_count: int = 0


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
