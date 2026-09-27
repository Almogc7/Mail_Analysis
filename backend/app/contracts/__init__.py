from app.contracts.email import (
    Attachment,
    EmailAddress,
    ExtractedUrl,
    HeaderField,
    ParsedEmail,
    ReceivedHop,
)
from app.contracts.findings import Finding, ModuleResult
from app.contracts.llm_opinion import LLMOpinion
from app.contracts.scoring import AppliedOverride, CategoryScore, ScoringBreakdown
from app.contracts.analysis import AnalysisResult

__all__ = [
    "Attachment",
    "EmailAddress",
    "ExtractedUrl",
    "HeaderField",
    "ParsedEmail",
    "ReceivedHop",
    "Finding",
    "ModuleResult",
    "AppliedOverride",
    "CategoryScore",
    "ScoringBreakdown",
    "LLMOpinion",
    "AnalysisResult",
]
