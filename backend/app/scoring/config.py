from dataclasses import dataclass, field

CATEGORIES = ("auth_check", "enrichment", "content_analysis")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_at_least(severity: str, threshold: str) -> bool:
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(threshold, 0)


@dataclass(frozen=True)
class ScoringConfig:
    category_weights: dict[str, float] = field(
        default_factory=lambda: {
            "auth_check": 0.35,
            "enrichment": 0.40,
            "content_analysis": 0.25,
        }
    )
    category_subscore_cap: float = 100.0

    verdict_score_malicious: float = 70.0
    verdict_score_suspicious: float = 35.0

    # Floor overrides: {category: min_severity} -> forces verdict >= "suspicious"
    floor_override_severity: dict[str, str] = field(
        default_factory=lambda: {
            "auth_check": "high",
            "enrichment": "critical",
        }
    )

    # Content-only floor: 2+ independently-firing high-severity content_analysis findings
    # (corroboration within the category) forces verdict >= "suspicious" on its own, even
    # though content_analysis's low category weight means it could never cross the
    # suspicious score threshold through weighted scoring alone.
    content_floor_min_high_severity_count: int = 2

    # Ceiling override: content_analysis alone (auth_check and enrichment both at/below
    # this) can't push the verdict past "suspicious".
    ceiling_hard_category_threshold: float = 10.0

    # Needs-review trigger (confidence-based).
    confidence_threshold: float = 0.6
    needs_review_score_floor: float = 10.0
