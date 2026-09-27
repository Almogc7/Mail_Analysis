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
