from app.contracts.findings import ModuleResult
from app.contracts.scoring import AppliedOverride
from app import config as app_config
from app.scoring.aggregate import category_coverage
from app.scoring.config import ScoringConfig, severity_at_least
from app.shared.matching import registrable_domain
from app.verdict_labels import verdict_label

_BUCKET_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}


def benign_evidence_gaps(
    module_results: dict[str, ModuleResult | None], confidence: float, config: ScoringConfig
) -> list[str]:
    """What is missing for a verdict of 'benign' (shown to users as 'no indicators found'). An EMPTY list means the
    message has POSITIVE evidence. 'No findings' is never evidence of safety, and neither is authentication: an
    attacker authenticates their own domain. Benign needs all of:

      1. a verified, ALIGNED DKIM pass or a DMARC pass from a TRUSTED receiver (authentication that ties the
         message to the From domain; a header is only a claim unless a trusted receiver wrote it);
      2. the sender's registrable domain is on the KNOWN-SENDER list (untracked config, empty by default) -- the only
         positive evidence of legitimacy, as opposed to authenticity;
      3. no finding above info severity anywhere (info findings are visibility notes);
      4. adequate coverage: overall confidence at or above the threshold AND enrichment complete (an unknown or
         uninformative indicator, or an enrichment module that did not run, counts as inadequate).

    Anything else that is not flagged is inconclusive."""
    gaps: list[str] = []

    auth = module_results.get("auth_check")
    raw = (auth.raw_data or {}) if auth is not None and auth.status == "ok" else {}
    headers = raw.get("auth_headers", {})
    alignment = raw.get("alignment", {})
    dkim, dmarc = headers.get("dkim", {}), headers.get("dmarc", {})
    dkim_ok = bool(dkim.get("evaluated")) and dkim.get("result") == "pass" and alignment.get("dkim", {}).get("aligned") is True
    dmarc_ok = bool(dmarc.get("evaluated")) and dmarc.get("result") == "pass"
    if not (dkim_ok or dmarc_ok):
        if not headers.get("trusted_receivers_configured"):
            gaps.append("no trusted receiver is configured, so no authentication result can be relied on")
        else:
            gaps.append("no verified, aligned DKIM pass or DMARC pass from a trusted receiver")

    if config.require_known_sender_for_benign:
        known = config.known_sender_domains if config.known_sender_domains is not None else app_config.KNOWN_SENDER_DOMAINS
        known = {registrable_domain(d.strip().strip('.').lower()) or d.strip().strip('.').lower() for d in known}
        sender = ((raw.get("identity") or {}).get("display_name_spoofing") or {}).get("actual_registrable_domain")
        if not known:
            gaps.append("no known-sender list is configured, so no sender can be recognised as legitimate")
        elif not sender or sender not in known:
            gaps.append("the sender's domain is not on the known-sender list")

    above_info = [
        f for result in module_results.values() if result is not None and result.status not in {"error", "skipped"}
        for f in result.findings if f.severity != "info"
    ]
    if above_info:
        gaps.append(f"{len(above_info)} finding(s) above info severity (e.g. '{above_info[0].title}')")

    if confidence < config.confidence_threshold:
        gaps.append(f"coverage is too low (confidence {confidence:.2f} < {config.confidence_threshold})")
    enrichment = module_results.get("enrichment")
    if enrichment is None or enrichment.status in {"error", "skipped"}:
        gaps.append("enrichment did not run")
    elif category_coverage("enrichment", enrichment) < 1.0:
        gaps.append("enrichment is incomplete (an indicator is unknown, uninformative or was not looked up)")
    return gaps


def _benign_gap_lead(module_results: dict[str, ModuleResult | None]) -> str:
    """The opening of the 'no positive evidence' reason. It must not say nothing was flagged when something was: a low finding does not make a
    message suspicious, but it is a finding."""
    flagged = any(
        f.severity != "info" for result in module_results.values() if result is not None and result.status not in {"error", "skipped"} for f in result.findings
    )
    if flagged:
        return ("Something was flagged, but not enough to call it suspicious, and nothing positive was established either; "
                "the lack of a strong finding is not evidence of safety.")
    return "Nothing was flagged, but 'no findings' is not evidence of safety."


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
    # (low coverage) must never erase it, so the inconclusive rule below must not touch such a verdict.
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

    # 1c. Structural corroboration floor (docs/DETECTION_DESIGN.md): signals from >= N DIFFERENT families. A single
    # family never floors -- several signals in one family usually share one cause (one hosting box, one cloned
    # template) -- and weak signals only add to the score through their weights.
    structural = [
        f
        for result in module_results.values()
        if result is not None and result.status not in {"error", "skipped"}
        for f in result.findings
        if f.evidence.get("structural") is True and f.evidence.get("family")
    ]
    families = sorted({f.evidence["family"] for f in structural})
    if len(families) >= config.structural_floor_min_families:
        floor_triggered = True
        if _BUCKET_RANK[bucket] < _BUCKET_RANK["suspicious"]:
            bucket = "suspicious"
            signals = ", ".join(sorted({str(f.evidence.get("signal", f.title)) for f in structural}))
            applied.append(
                AppliedOverride(
                    rule="structural_corroboration_floor",
                    effect="floor=suspicious",
                    reason=(
                        f"signals from {len(families)} different families ({', '.join(families)}) corroborate each other: "
                        f"{signals}. No single family would have been enough."
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

    # 3. Inconclusive: evidence too incomplete to trust a benign/suspicious call -- but never over a floor.
    would_need_review = (
        bucket in {"benign", "suspicious"}
        and confidence < config.confidence_threshold
        and weighted_score >= config.inconclusive_score_floor
    )
    if would_need_review and floor_triggered:
        applied.append(
            AppliedOverride(
                rule="floor_protects_verdict",
                effect=f"verdict stays {verdict_label(bucket)}",
                reason=(
                    f"Overall confidence {confidence:.2f} is below {config.confidence_threshold}, which would normally "
                    "mean inconclusive, but a hard indicator (a floor trigger) fired. Low coverage of OTHER evidence "
                    "cannot cancel it, so the verdict is not downgraded."
                ),
            )
        )
    elif would_need_review:
        applied.append(
            AppliedOverride(
                rule="low_confidence_inconclusive",
                effect="verdict=inconclusive",
                reason=(
                    f"Overall confidence {confidence:.2f} is below threshold "
                    f"{config.confidence_threshold} with a non-trivial score "
                    f"({weighted_score:.1f}) -- evidence is too incomplete to trust a "
                    f"'{verdict_label(bucket)}' call."
                ),
            )
        )
        bucket = "inconclusive"

    # 4. Benign needs POSITIVE evidence. Everything not flagged and not proven benign is inconclusive.
    if bucket == "benign":
        gaps = benign_evidence_gaps(module_results, confidence, config)
        if gaps:
            applied.append(
                AppliedOverride(
                    rule="no_positive_evidence_for_benign",
                    effect="verdict=inconclusive (inconclusive)",
                    reason=_benign_gap_lead(module_results) + " Missing: " + "; ".join(gaps) + ".",
                )
            )
            bucket = "inconclusive"

    return bucket, applied
