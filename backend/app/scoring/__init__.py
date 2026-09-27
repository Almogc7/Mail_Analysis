from dataclasses import dataclass

from app.contracts.analysis import AnalysisResult
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.contracts.scoring import CategoryScore, ScoringBreakdown
from app.scoring.aggregate import category_coverage, category_finding_count, category_subscore
from app.scoring.config import CATEGORIES, ScoringConfig
from app.scoring.overrides import apply_overrides

_SEVERITY_SORT_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ScoringOutcome:
    score: int
    verdict: str
    confidence: float
    breakdown: ScoringBreakdown


def _verdict_from_score(score: float, config: ScoringConfig) -> str:
    if score >= config.verdict_score_malicious:
        return "malicious"
    if score >= config.verdict_score_suspicious:
        return "suspicious"
    return "legit"


def run_scoring(
    module_results: list[ModuleResult],
    config: ScoringConfig | None = None,
) -> ScoringOutcome:
    config = config or ScoringConfig()
    by_category: dict[str, ModuleResult | None] = {c: None for c in CATEGORIES}
    for result in module_results:
        if result.module in by_category:
            by_category[result.module] = result

    category_scores: list[CategoryScore] = []
    subscores: dict[str, float] = {}
    weighted_score = 0.0
    confidence = 0.0

    for category in CATEGORIES:
        result = by_category[category]
        subscore = category_subscore(result, config.category_subscore_cap)
        coverage = category_coverage(category, result)
        weight = config.category_weights[category]

        subscores[category] = subscore
        weighted_score += weight * subscore
        confidence += weight * coverage

        category_scores.append(
            CategoryScore(
                category=category,
                subscore=subscore,
                weight=weight,
                contribution=weight * subscore,
                coverage=coverage,
                finding_count=category_finding_count(result),
            )
        )

    base_bucket = _verdict_from_score(weighted_score, config)
    final_bucket, applied_overrides = apply_overrides(
        base_bucket, by_category, subscores, confidence, weighted_score, config
    )

    breakdown = ScoringBreakdown(
        categories=category_scores,
        weighted_score=weighted_score,
        applied_overrides=applied_overrides,
    )

    return ScoringOutcome(
        score=round(weighted_score),
        verdict=final_bucket,
        confidence=round(confidence, 3),
        breakdown=breakdown,
    )


def build_analysis_result(parsed: ParsedEmail, module_results: list[ModuleResult]) -> AnalysisResult:
    outcome = run_scoring(module_results)

    all_findings: list[Finding] = [f for result in module_results for f in result.findings]
    all_findings.sort(key=lambda f: (_SEVERITY_SORT_RANK.get(f.severity, 5), -f.weight))

    return AnalysisResult(
        parsed_email=parsed,
        module_results=module_results,
        findings=all_findings,
        score=outcome.score,
        verdict=outcome.verdict,
        confidence=outcome.confidence,
        scoring=outcome.breakdown,
    )


__all__ = ["run_scoring", "build_analysis_result", "ScoringOutcome"]
