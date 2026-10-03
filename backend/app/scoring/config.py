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

    # Structural corroboration floor (docs/DETECTION_DESIGN.md): findings tagged evidence.structural + evidence.family
    # from at least this many DIFFERENT families (sender / link / claim) force the verdict to at least 'suspicious'.
    # Several signals in one family count once. Not to be loosened to raise tuning recall.
    structural_floor_min_families: int = 2

    # Known senders (registrable domains) that may be benign. None = read app.config.KNOWN_SENDER_DOMAINS (the untracked
    # list, empty by default). Authentication proves who sent a message, not that the sender is legitimate, so benign
    # needs a sender on this list as well (iteration 1 in docs/DETECTION_DESIGN.md).
    known_sender_domains: frozenset[str] | None = None
    # Test/diagnostic switch: False reproduces the pre-iteration-1 rule (authentication alone) so the cases it
    # let through can be counted. Never set it in production.
    require_known_sender_for_benign: bool = True

    # Ceiling override: content_analysis alone (auth_check and enrichment both at/below
    # this) can't push the verdict past "suspicious".
    ceiling_hard_category_threshold: float = 10.0

    # Needs-review trigger (confidence-based).
    confidence_threshold: float = 0.6
    inconclusive_score_floor: float = 10.0
