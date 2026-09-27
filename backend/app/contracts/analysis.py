from typing import Literal

from pydantic import BaseModel

from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult

Verdict = Literal["malicious", "suspicious", "legit", "needs_review"]


class AnalysisResult(BaseModel):
    parsed_email: ParsedEmail
    module_results: list[ModuleResult] = []
    findings: list[Finding] = []
    score: int | None = None
    verdict: Verdict | None = None
    confidence: float | None = None
    llm_opinion: str | None = None
