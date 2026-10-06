"""Parity checks for Phase B (docs/PHASE_B_PREREGISTRATION.md), read-only and not imported by the application.

    python scripts/check_tier_parity.py                  # all 856 baseline rows (about twenty seconds); exit 1 on any difference
    python scripts/check_tier_parity.py --variants fast  # the 214 as-is clean rows only (what the unit test runs in-process)

Check A (clarification C1): counting the content and enrichment floors BY REASON CLASS gives the same tier and route as the frozen predictor (scripts/predict_tiers.py), which counts them by module,
on every row. The two differ only for a link-class finding at severity high, which no producer emits.

The rows are the regression baseline's: same variants, modes, samples and keys. The seeds-ablated variants cannot be undone inside one process, which is why the unit test runs this script in a
subprocess for the full set. Nothing is written; the hold-out is never read.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.reason_classes import REASON_TABLE  # noqa: E402
from app.scoring.config import ScoringConfig  # noqa: E402
from app.scoring.overrides import benign_evidence_gaps  # noqa: E402
from tests import eval as ev  # noqa: E402
from tests import regression_baseline as rb  # noqa: E402


def _load_predictor():
    spec = importlib.util.spec_from_file_location("predict_tiers", ROOT / "scripts" / "predict_tiers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rows(variants):
    """Yield (row key, analysis result) for every baseline row of the given variants, exactly as the predictor and the baseline enumerate them."""
    items = ev.collect(None)
    ablated_done = False
    for enrichment, ablated in variants:
        if ablated and not ablated_done:
            ev._ablate_seeds()
            ablated_done = True
        for mode in ev.MODES:
            ev.apply_mode(mode)
            for path, _label, source in items:
                key = f"{rb.variant_name(enrichment, ablated)}/{mode}/{source}/{path.name}"
                yield key, ev.analyze(path, "disabled" if enrichment == "unknown" else "clean")


def class_based_prediction(predictor, result) -> tuple[str, str, str]:
    """predictor.predict_result with each finding's `module` replaced by a stand-in derived from its REASON CLASS, so the floors are counted by class."""
    by_name = {m.module: m for m in result.module_results}
    active = {k: v for k, v in by_name.items() if v is not None and v.status not in {"error", "skipped"}}
    stand_in = {"content": "content_analysis", "enrichment": "enrichment"}
    findings = [{"code": f.code, "severity": f.severity, "module": stand_in.get(REASON_TABLE[f.code].cls, "other_class")} for m in active.values() for f in m.findings]
    gaps = benign_evidence_gaps(by_name, result.confidence, ScoringConfig())
    return predictor.tier_for(findings, result.scoring.weighted_score, result.confidence, predictor.hard_evidence(by_name), not gaps, predictor.blockers(result))


def check(variants=rb.ALL_VARIANTS) -> dict:
    predictor = _load_predictor()
    total = 0
    differing: list[str] = []
    for key, result in rows(variants):
        total += 1
        if class_based_prediction(predictor, result) != predictor.predict_result(result):
            differing.append(key)
    return {"rows": total, "class_based_differs_from_module_based": differing}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logging.getLogger("app").setLevel(logging.ERROR)
    variants = rb.FAST_VARIANTS if "fast" in argv else rb.ALL_VARIANTS
    outcome = check(variants)
    print(f"checked {outcome['rows']} rows; class-based differs from module-based: {len(outcome['class_based_differs_from_module_based'])}")
    for key in outcome["class_based_differs_from_module_based"]:
        print("DIFFERS:", key)
    return 1 if outcome["class_based_differs_from_module_based"] else 0


if __name__ == "__main__":
    sys.exit(main())
