from typing import Callable

from app.auth_check import run_auth_check
from app.contracts.analysis import AnalysisResult
from app.contracts.findings import ModuleResult
from app.content_analysis import run_content_analysis
from app.enrichment import run_enrichment
from app.llm import run_llm_opinion
from app.parser import parse_email_file
from app.scoring import build_analysis_result

StepCallback = Callable[[str], None]


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
    so one category failing (e.g. enrichment's IOC_ENRICHER_PATH misconfigured) doesn't
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

    on_step("llm_opinion")
    opinion = run_llm_opinion(analysis_result)

    return analysis_result.model_copy(update={"llm_opinion": opinion})


__all__ = ["run_pipeline"]
