"""Parity checks for Phase B (docs/PHASE_B_PREREGISTRATION.md), read-only and not imported by the application.

    python scripts/check_tier_parity.py                  # all 856 baseline rows (about twenty seconds); exit 1 on any difference
    python scripts/check_tier_parity.py --variants fast  # the 214 as-is clean rows only (what the unit test runs in-process)

Check A (clarification C1): counting the content and enrichment floors BY REASON CLASS gives the same tier and route as the frozen predictor (scripts/predict_tiers.py), which counts them by module,
on every row. The two differ only for a link-class finding at severity high, which no producer emits.

Check B (Phase B step 8): app.scoring.tiers.compute_tier, fed by the input builder below (an adapter: it lives here, not in app/), gives the tier, the route and the T3 sub-reason recorded in
backend/tests/fixtures/predicted_tiers.json on every row. A difference is NOT fixed by adjusting the function or the prediction: it is listed and reported (iteration 1 of 3).

The rows are the regression baseline's: same variants, modes, samples and keys. The seeds-ablated variants cannot be undone inside one process, which is why the unit test runs this script in a
subprocess for the full set. Nothing is written; the hold-out is never read.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import config as app_config  # noqa: E402
from app.enrichment.policy import classify_host, platform_of  # noqa: E402
from app.reason_classes import REASON_TABLE  # noqa: E402
from app.scoring.aggregate import category_coverage  # noqa: E402
from app.scoring.config import ScoringConfig  # noqa: E402
from app.scoring.overrides import benign_evidence_gaps  # noqa: E402
from app.shared.matching import registrable_domain  # noqa: E402
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


PREDICTED = ROOT / "backend" / "tests" / "fixtures" / "predicted_tiers.json"


def candidates_from_enrichment(raw_data: dict, known: set[str]) -> list[dict]:
    """Provider answers as hard-evidence CANDIDATES (the contract's input), one per matching provider answer, with the flags the rules need. compute_tier applies rules 1 to 6 and the thresholds."""
    out: list[dict] = []
    for key, value in (raw_data or {}).items():
        if not isinstance(value, dict) or "uninformative" in value or value.get("internal_host_not_sent"):
            continue
        is_hash = len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)
        host = key.split("/")[0]
        is_url = (not is_hash) and "/" in key
        flags = {
            "indicator_type": "attachment_hash" if is_hash else ("link_url" if is_url else "link_host"),
            "is_ip": (not is_hash) and classify_host(host) == "ip",
            "is_shared_platform": (not is_hash) and platform_of(host) is not None,
            "path_optin_on": is_url,
            "exact_url_match": is_url,
            "is_known_sender_or_own_domain": (not is_hash) and ((registrable_domain(host) or host) in known),
        }
        vt, tf, mb = value.get("vt") or {}, value.get("threatfox") or {}, value.get("malwarebazaar") or {}
        if vt.get("status") == "ok" and (vt.get("malicious") or 0) > 0:
            out.append({**flags, "source": "virustotal", "engine_count": vt["malicious"], "confidence": None})
        if tf.get("status") == "ok" and tf.get("matched") is True:
            out.append({**flags, "source": "threatfox", "engine_count": None, "confidence": tf.get("confidence_level")})
        if mb.get("status") == "ok" and mb.get("matched") is True:
            out.append({**flags, "source": "malwarebazaar", "engine_count": None, "confidence": None})
    return out


def tier_inputs(predictor, result) -> dict:
    """The inputs of the interface contract for one analysis result, built only from data the pipeline already produces (the same sources the predictor reads)."""
    by_name = {m.module: m for m in result.module_results}
    active = {k: v for k, v in by_name.items() if v is not None and v.status not in {"error", "skipped"}}
    findings = [{"code": f.code, "severity": f.severity, "class": REASON_TABLE[f.code].cls if f.code in REASON_TABLE else "unknown"} for m in active.values() for f in m.findings]
    auth = by_name.get("auth_check")
    raw = (auth.raw_data or {}) if auth is not None and auth.status == "ok" else {}
    headers, alignment = raw.get("auth_headers", {}), raw.get("alignment", {})
    dkim, dmarc = headers.get("dkim", {}), headers.get("dmarc", {})
    dkim_ok = bool(dkim.get("evaluated")) and dkim.get("result") == "pass" and alignment.get("dkim", {}).get("aligned") is True
    dmarc_ok = bool(dmarc.get("evaluated")) and dmarc.get("result") == "pass"
    known = {registrable_domain(d.strip().strip(".").lower()) or d.strip().strip(".").lower() for d in app_config.KNOWN_SENDER_DOMAINS}
    sender = ((raw.get("identity") or {}).get("display_name_spoofing") or {}).get("actual_registrable_domain")
    enrichment = by_name.get("enrichment")
    ran = enrichment is not None and enrichment.status not in {"error", "skipped"}
    failures = [{"method": m, "result": headers[m]["result"], "trusted": True} for m in ("spf", "dkim", "dmarc") if (headers.get(m) or {}).get("evaluated") and headers[m].get("result") == "fail"]
    return {
        "findings": findings,
        "score": result.scoring.weighted_score,
        "contributions": {c.category: c.contribution for c in result.scoring.categories},
        "trusted_auth_failures": failures,
        "hard_evidence_candidates": candidates_from_enrichment(enrichment.raw_data, known) if ran else [],
        "blockers": predictor.blockers(result),
        "t4_positive_flags": {"trusted_aligned_dkim_or_dmarc_pass": dkim_ok or dmarc_ok, "sender_on_known_list": bool(known) and sender in known},
        "coverage_gate": {"confidence": result.confidence, "confidence_threshold": 0.6, "enrichment_complete": ran and category_coverage("enrichment", enrichment) >= 1.0},
    }


def check(variants=rb.ALL_VARIANTS) -> dict:
    from app.scoring.tiers import compute_tier

    predictor = _load_predictor()
    predicted = json.loads(PREDICTED.read_text(encoding="utf-8"))["rows"]
    total = 0
    differing: list[str] = []
    tier_differs: list[str] = []
    for key, result in rows(variants):
        total += 1
        if class_based_prediction(predictor, result) != predictor.predict_result(result):
            differing.append(key)
        out = compute_tier(tier_inputs(predictor, result))
        want = predicted[key]
        sub = out["needs_analyst_reason"][0] if out["tier"] == "T3" else ""
        if (out["tier"], out["route_id"], sub) != (want["tier"], want["route"], want["sub"]):
            tier_differs.append(f"{key} | compute_tier {out['tier']} {out['route_id']} {sub} | predicted {want['tier']} {want['route']} {want['sub']}")
    return {"rows": total, "class_based_differs_from_module_based": differing, "compute_tier_differs_from_prediction": tier_differs}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logging.getLogger("app").setLevel(logging.ERROR)
    variants = rb.FAST_VARIANTS if "fast" in argv else rb.ALL_VARIANTS
    outcome = check(variants)
    print(f"checked {outcome['rows']} rows; class-based differs from module-based: {len(outcome['class_based_differs_from_module_based'])}")
    print(f"compute_tier differs from predicted_tiers.json (tier, route, T3 sub-reason): {len(outcome['compute_tier_differs_from_prediction'])}")
    for key in outcome["class_based_differs_from_module_based"]:
        print("DIFFERS (class-based):", key)
    for line in outcome["compute_tier_differs_from_prediction"]:
        print("DIFFERS (compute_tier):", line)
    return 1 if outcome["class_based_differs_from_module_based"] or outcome["compute_tier_differs_from_prediction"] else 0


if __name__ == "__main__":
    sys.exit(main())
