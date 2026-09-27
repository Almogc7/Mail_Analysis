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
        enriched_count = len(result.raw_data or {})
        if enriched_count == 0:
            return 1.0  # nothing to enrich -- nothing to be uncertain about
        incomplete_iocs = {
            f.evidence.get("ioc_value")
            for f in result.findings
            if f.title.startswith("Enrichment incomplete for")
        }
        return max(0.0, 1.0 - len(incomplete_iocs) / enriched_count)

    if category == "content_analysis":
        # Not unconditionally 1.0: the fixed phrase lists only cover certain scripts
        # (see content_analysis.text_utils.estimate_script_coverage). A non-English email
        # with weak/no findings elsewhere previously looked "fully checked" here even
        # though the heuristics couldn't meaningfully read it -- this is what lets
        # needs_review actually trigger for that case instead of silently reading as clean.
        return (result.raw_data or {}).get("script_coverage", 1.0)

    # Any future category with no external dependency: always fully computable.
    return 1.0


def category_finding_count(result: ModuleResult | None) -> int:
    if result is None or result.status in _INACTIVE_STATUSES:
        return 0
    return len(result.findings)
