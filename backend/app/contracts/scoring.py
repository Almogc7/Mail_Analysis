from pydantic import BaseModel


class CategoryScore(BaseModel):
    category: str
    subscore: float
    weight: float
    contribution: float
    coverage: float
    finding_count: int


class AppliedOverride(BaseModel):
    rule: str
    effect: str
    reason: str


class ScoringBreakdown(BaseModel):
    categories: list[CategoryScore]
    weighted_score: float
    applied_overrides: list[AppliedOverride]
    # Triage aids (docs/DETECTION_DESIGN.md). inconclusive_reason is set only when the verdict is inconclusive:
    # "signals_present" (something was flagged but not enough to call) or "no_signals_insufficient_evidence" (nothing
    # fired and nothing positive was established). priority orders a review queue, higher first; it is not a probability.
    inconclusive_reason: str | None = None
    priority: float = 0.0
