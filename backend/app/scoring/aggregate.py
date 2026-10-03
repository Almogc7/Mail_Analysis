from app.contracts.findings import ModuleResult

_INACTIVE_STATUSES = {"error", "skipped"}


def category_subscore(result: ModuleResult | None, cap: float) -> float:
    """Sum of a category's finding weights, capped. A missing module or a module that
    errored/was skipped contributes 0 -- absence of data is not evidence of "clean"."""
    if result is None or result.status in _INACTIVE_STATUSES:
        return 0.0
    return min(sum(f.weight for f in result.findings), cap)


def category_coverage(category: str, result: ModuleResult | None) -> float:
    """0-1: how much reliable data actually went into this category, independent of its
    subscore. Lets a "checked and clean" result be distinguished from a "couldn't check"
    result, both of which would otherwise look identical (subscore 0)."""
    if result is None or result.status in _INACTIVE_STATUSES:
        return 0.0

    if category == "auth_check":
        auth_headers = (result.raw_data or {}).get("auth_headers", {})
        return 1.0 if auth_headers.get("header_present") else 0.4

    if category == "enrichment":
        # An indicator counts as covered only if every provider answered and it was not left out. Gaps
        # come in three forms, all reported as findings: "Enrichment incomplete" (a provider did not
        # answer, or the host is uninformative/internal) and "Not enriched" (dropped by the per-email cap).
        enriched = set(result.raw_data or {})
        dropped = {f.evidence.get("ioc_value") for f in result.findings if f.title.startswith("Not enriched:")}
        total = enriched | dropped
        if not total:
            return 1.0  # nothing to enrich -- nothing to be uncertain about
        incomplete = dropped | {
            f.evidence.get("ioc_value") for f in result.findings if f.title.startswith("Enrichment incomplete for")
        }
        return max(0.0, 1.0 - len(incomplete & total) / len(total))

    if category == "content_analysis":
        # Not unconditionally 1.0: the fixed phrase lists only cover certain scripts
        # (see content_analysis.text_utils.estimate_script_coverage). A non-English email
        # with weak/no findings elsewhere previously looked "fully checked" here even
        # though the heuristics couldn't meaningfully read it -- this is what lets
        # needs_review actually trigger for that case instead of silently reading as clean.
        return (result.raw_data or {}).get("script_coverage", 1.0)

    # Any future category with no external dependency: always fully computable.
    return 1.0


def _active_findings(by_category: dict[str, ModuleResult | None]):
    return [f for r in by_category.values() if r is not None and r.status not in _INACTIVE_STATUSES for f in r.findings]


def priority_score(weighted_score: float, by_category: dict[str, ModuleResult | None]) -> float:
    """Queue-ordering number, higher = look at it sooner. Set a priori, not fitted:
        weighted score (0-100)  +  5 per DIFFERENT structural family  +  2 per finding above info (at most 10 counted)
    capped at 100. The family term rewards corroboration, which is what separates a coincidence from a pattern; the
    finding term breaks ties among messages with the same score. It orders; it is not a probability and not a verdict."""
    findings = _active_findings(by_category)
    families = {f.evidence["family"] for f in findings if f.evidence.get("structural") is True and f.evidence.get("family")}
    above_info = sum(1 for f in findings if f.severity != "info")
    return round(min(100.0, weighted_score + 5.0 * len(families) + 2.0 * min(above_info, 10)), 1)


def inconclusive_reason(verdict: str, by_category: dict[str, ModuleResult | None]) -> str | None:
    """Why a message is inconclusive: something fired but was not enough, or nothing did and nothing positive exists."""
    if verdict != "needs_review":
        return None
    if any(f.severity != "info" for f in _active_findings(by_category)):
        return "signals_present"
    return "no_signals_insufficient_evidence"


def category_finding_count(result: ModuleResult | None) -> int:
    if result is None or result.status in _INACTIVE_STATUSES:
        return 0
    return len(result.findings)
