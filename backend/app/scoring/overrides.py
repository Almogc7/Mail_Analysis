from app.contracts.findings import ModuleResult
from app.contracts.scoring import AppliedOverride
from app.scoring.config import ScoringConfig, severity_at_least

_BUCKET_RANK = {"legit": 0, "suspicious": 1, "malicious": 2}


def apply_overrides(
    base_bucket: str,
    module_results: dict[str, ModuleResult | None],
    category_subscores: dict[str, float],
    confidence: float,
    weighted_score: float,
    config: ScoringConfig,
) -> tuple[str, list[AppliedOverride]]:
    bucket = base_bucket
    applied: list[AppliedOverride] = []
    # True once ANY floor trigger exists -- even when the score alone already put the bucket at "suspicious", so
    # no floor override gets recorded. A floor means "a hard indicator fired": uncertainty about OTHER evidence
    # (low coverage) must never erase it, so the needs_review rule below must not touch such a verdict.
    floor_triggered = False

    # 1. Floor overrides: a single hard indicator forces at least "suspicious".
    for category, min_severity in config.floor_override_severity.items():
        result = module_results.get(category)
        if result is None or result.status in {"error", "skipped"}:
            continue
        triggering = [f for f in result.findings if severity_at_least(f.severity, min_severity)]
        floor_triggered = floor_triggered or bool(triggering)
        if triggering and _BUCKET_RANK[bucket] < _BUCKET_RANK["suspicious"]:
            bucket = "suspicious"
            applied.append(
                AppliedOverride(
                    rule=f"{category}_floor",
                    effect="floor=suspicious",
                    reason=(
                        f"{category} has {len(triggering)} finding(s) at severity>="
                        f"{min_severity}: {triggering[0].title}"
                    ),
                )
            )

    # 1b. Content-only floor: 2+ independently-firing high-severity content_analysis
    # findings forces at least "suspicious" -- without this, content_analysis's low
    # category weight (0.25) means it could never cross the suspicious score threshold
    # through weighted scoring alone, no matter how many heuristics fire.
    content_result = module_results.get("content_analysis")
    if content_result is not None and content_result.status not in {"error", "skipped"}:
        high_severity_findings = [f for f in content_result.findings if severity_at_least(f.severity, "high")]
        corroborated = len(high_severity_findings) >= config.content_floor_min_high_severity_count
        floor_triggered = floor_triggered or corroborated
        if corroborated and _BUCKET_RANK[bucket] < _BUCKET_RANK["suspicious"]:
            bucket = "suspicious"
            applied.append(
                AppliedOverride(
                    rule="content_analysis_floor",
                    effect="floor=suspicious",
                    reason=(
                        f"content_analysis has {len(high_severity_findings)} independently-firing "
                        f"findings at severity>=high (corroborated content-only signal): "
                        f"{', '.join(f.title for f in high_severity_findings)}"
                    ),
                )
            )

    # 2. Ceiling override: content_analysis alone can't reach "malicious".
    hard_categories_quiet = all(
        category_subscores.get(c, 0.0) <= config.ceiling_hard_category_threshold
        for c in ("auth_check", "enrichment")
    )
    if (
        category_subscores.get("content_analysis", 0.0) > 0
        and hard_categories_quiet
        and _BUCKET_RANK[bucket] > _BUCKET_RANK["suspicious"]
    ):
        bucket = "suspicious"
        applied.append(
            AppliedOverride(
                rule="content_only_ceiling",
                effect="cap=suspicious",
                reason=(
                    "content_analysis is the only category with meaningful evidence "
                    "(auth_check and enrichment are both quiet) -- capped below malicious."
                ),
            )
        )

    # 3. Needs-review: evidence too incomplete to trust a legit/suspicious call -- but never over a floor.
    would_need_review = (
        bucket in {"legit", "suspicious"}
        and confidence < config.confidence_threshold
        and weighted_score >= config.needs_review_score_floor
    )
    if would_need_review and floor_triggered:
        applied.append(
            AppliedOverride(
                rule="floor_protects_verdict",
                effect=f"verdict stays {bucket}",
                reason=(
                    f"Overall confidence {confidence:.2f} is below {config.confidence_threshold}, which would normally "
                    "mean needs_review, but a hard indicator (a floor trigger) fired. Low coverage of OTHER evidence "
                    "cannot cancel it, so the verdict is not downgraded."
                ),
            )
        )
    elif would_need_review:
        applied.append(
            AppliedOverride(
                rule="low_confidence_needs_review",
                effect="verdict=needs_review",
                reason=(
                    f"Overall confidence {confidence:.2f} is below threshold "
                    f"{config.confidence_threshold} with a non-trivial score "
                    f"({weighted_score:.1f}) -- evidence is too incomplete to trust a "
                    f"{bucket} call."
                ),
            )
        )
        bucket = "needs_review"

    return bucket, applied
