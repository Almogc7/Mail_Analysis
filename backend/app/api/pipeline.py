import logging
from typing import Callable

from app import config as app_config
from app.auth_check import run_auth_check
from app.contracts.analysis import AnalysisResult, CoverageItem
from app.contracts.findings import ModuleResult
from app.content_analysis import run_content_analysis
from app.enrichment import run_enrichment
from app.coverage import HOW_TO_CLEAR, build_coverage_report
from app.evidence import build_evidence
from app.indicators import build_indicator_pack, visible_pack
from app.llm import run_llm_opinion
from app.parser import parse_email_file
from app.scoring import build_analysis_result
from app.scoring.tiers import compute_tier
from app.scoring.v2_inputs import build_tier_inputs
from app.scoring.v2_verdict import assemble_verdict_v2, count_checks

StepCallback = Callable[[str], None]
logger = logging.getLogger(__name__)


def _safe_run(module_name: str, fn: Callable[[], ModuleResult]) -> ModuleResult:
    try:
        return fn()
    except Exception as exc:
        return ModuleResult(module=module_name, status="error", findings=[], raw_data={"error": str(exc)})


def _noop(step: str) -> None:
    pass


def run_pipeline(raw_bytes: bytes, filename: str, on_step: StepCallback = _noop) -> AnalysisResult:
    """Runs Modules 1-6 end to end. Parsing and Module 5 (scoring) are allowed to raise --
    nothing meaningful can be returned without them. Modules 2-4 are individually wrapped
    so one category failing (e.g. an enrichment provider raising unexpectedly) doesn't
    sink the whole analysis; Module 6 already never raises by its own contract."""
    on_step("parsing")
    parsed = parse_email_file(raw_bytes, filename)

    on_step("auth_check")
    auth_result = _safe_run("auth_check", lambda: run_auth_check(parsed))

    on_step("enrichment")
    enrichment_result = _safe_run("enrichment", lambda: run_enrichment(parsed))

    on_step("content_analysis")
    content_result = _safe_run("content_analysis", lambda: run_content_analysis(parsed))

    on_step("scoring")
    analysis_result = build_analysis_result(parsed, [auth_result, enrichment_result, content_result])

    # The indicator pack is an analyst aid (no scoring, no verdict); a bug in it must never sink the analysis.
    try:
        indicators = build_indicator_pack(parsed, [auth_result, enrichment_result, content_result])
    except Exception:
        indicators = None

    # The evidence block is the same kind of aid: organised facts for the workbench page, no scoring, no verdict. If it fails, the analysis
    # still returns (the page falls back to the older layout); only the exception's class is logged, never its text.
    evidence = None
    try:
        evidence = build_evidence(parsed, [auth_result, enrichment_result, content_result], indicators)
    except Exception as exc:
        logger.warning("evidence block could not be built (%s)", type(exc).__name__)

    coverage = None
    try:
        coverage = build_coverage_report(parsed, [auth_result, enrichment_result, content_result], evidence)
    except Exception as exc:
        logger.warning("coverage report could not be built (%s)", type(exc).__name__)

    # Verdict v2 and the checks count: additive fields computed from data already held (no scoring change, no enrichment request, no v1 field touched). Without a coverage report the blockers cannot be
    # known, so no verdict is attached rather than one that could read a gap as an absence. That is never silent: verdict_v2_status says `unavailable` and the coverage report gains an item with the reason
    # code verdict_v2_unavailable. Only the exception's class is logged, never its text.
    verdict_v2 = checks_completed = None
    if coverage is None:
        logger.warning("verdict v2 is unavailable (no coverage report)")
    else:
        try:
            tier_inputs, blocker_items = build_tier_inputs(parsed, [auth_result, enrichment_result, content_result], analysis_result, coverage,
                                                           known_sender_domains=app_config.KNOWN_SENDER_DOMAINS, own_domains=app_config.OWN_DOMAINS)
            verdict_v2 = assemble_verdict_v2(compute_tier(tier_inputs), analysis_result, blocker_items)
            checks_completed = count_checks(coverage)
        except Exception as exc:
            logger.warning("verdict v2 could not be built (%s)", type(exc).__name__)
    if verdict_v2 is None:
        coverage = list(coverage or []) + [CoverageItem(area="Verdict v2", status="not_checked", reason="verdict_v2_unavailable", how_to_clear=HOW_TO_CLEAR["verdict_v2_unavailable"])]

    on_step("llm_opinion")
    opinion = run_llm_opinion(analysis_result)

    # The response carries the pack WITHOUT indicators that came only from hops hidden by local config (display only; evidence and coverage above were
    # built from the full pack).
    update: dict = {"llm_opinion": opinion, "indicators": visible_pack(indicators)}
    if evidence is not None:
        update.update(evidence=evidence, schema_version=2)
    if coverage is not None:
        update.update(coverage_report=coverage, schema_version=2)
    update.update(verdict_v2_status="ok" if verdict_v2 is not None else "unavailable")
    if verdict_v2 is not None:
        update.update(verdict_v2=verdict_v2, checks_completed=checks_completed)
    return analysis_result.model_copy(update=update)


__all__ = ["run_pipeline"]
