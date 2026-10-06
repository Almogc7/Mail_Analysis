"""Read-only predictor for Phase B (docs/PHASE_B_PREREGISTRATION.md): applies the FROZEN tier rules (sections 1.2 to 1.6) to the 856 regression-baseline rows
and writes the predicted tier and route per row to backend/tests/fixtures/predicted_tiers.json.

It is NOT imported by the application and creates no tier code: the rules live here only so that the pre-registration has predicted row movements computed before any
scoring change. It reruns the same pipeline as tests/regression_baseline.py (same variants, modes, samples and row keys) and builds its inputs ONLY from data the pipeline
already produces: the findings with their codes, the weighted score, the coverage report and the provider answers. The hold-out is never read.

    python scripts/predict_tiers.py            # print the summary and every row that differs from the written prediction
    python scripts/predict_tiers.py --write    # also write backend/tests/fixtures/predicted_tiers.json

Rows hold codes and tier words only: no subject, address, URL or content.
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import config as app_config  # noqa: E402
from app.coverage import build_coverage_report  # noqa: E402
from app.enrichment.policy import classify_host, platform_of  # noqa: E402
from app.reason_classes import REASON_TABLE  # noqa: E402
from app.scoring.config import ScoringConfig  # noqa: E402
from app.scoring.overrides import benign_evidence_gaps  # noqa: E402
from app.shared.matching import registrable_domain  # noqa: E402
from tests import eval as ev  # noqa: E402
from tests import regression_baseline as rb  # noqa: E402

OUT = ROOT / "backend" / "tests" / "fixtures" / "predicted_tiers.json"
FAMILY_CLASSES = ("sender", "link", "claim")
MEDIUM_UP = ("medium", "high", "critical")
TRUSTED_FAILURE_CODES = ("AUTH_SPF_CHECK_FAILED", "AUTH_DKIM_CHECK_FAILED", "AUTH_DMARC_CHECK_FAILED")
GATE = 0.6
# The prediction written in words before this script was run (PHASE_B_PREREGISTRATION.md 3.1): the v1 verdict maps to a tier, and a suspicious row goes through R1 or R2.
WORD_TIER = {"suspicious": "T2", "inconclusive": "T3", "benign": "T4"}


def sha256_lf(path: Path) -> str:
    """SHA-256 of the file's bytes with CRLF replaced by LF, so the value does not depend on the checkout's line endings."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


# ---- the inputs of the interface contract (section 2), built from what the pipeline already produces ------------------------------------------------------------------

def _known_registrables() -> set[str]:
    return {registrable_domain(d.strip().strip(".").lower()) or d.strip().strip(".").lower() for d in app_config.KNOWN_SENDER_DOMAINS}


def hard_evidence(module_results: dict) -> list[dict]:
    """H1 to H3 candidates that survive rules 1 to 4 of 1.5. Each carries `conflict` when its registrable domain is on the known-sender list (rule 5)."""
    enrichment = module_results.get("enrichment")
    if enrichment is None or enrichment.status in {"error", "skipped"}:
        return []
    known = _known_registrables()
    found: list[dict] = []
    for key, value in (enrichment.raw_data or {}).items():
        if not isinstance(value, dict) or "uninformative" in value or value.get("internal_host_not_sent"):
            continue  # a shared-platform or internal host is never evidence (rule 3), and was never looked up
        is_hash = len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)
        host = key.split("/")[0]
        if not is_hash and classify_host(host) == "ip":
            continue  # an IP alone never counts (rule 2)
        if not is_hash and platform_of(host) is not None:
            continue
        conflict = (not is_hash) and ((registrable_domain(host) or host) in known)
        mb, tf, vt = value.get("malwarebazaar") or {}, value.get("threatfox") or {}, value.get("vt") or {}
        if is_hash and mb.get("status") == "ok" and mb.get("matched") is True:
            found.append({"rule": "H1", "source": "malwarebazaar", "conflict": False})
        if tf.get("status") == "ok" and tf.get("matched") is True and (tf.get("confidence_level") or 0) >= 75:
            found.append({"rule": "H2", "source": "threatfox", "conflict": conflict})
        if vt.get("status") == "ok" and (vt.get("malicious") or 0) >= 10:
            found.append({"rule": "H3", "source": "virustotal", "conflict": conflict})
    return found


def blockers(result) -> list[str]:
    """The blockers derivable from data the pipeline already holds today: every coverage item that blocks, plus an unparseable From and a calendar invite."""
    items = build_coverage_report(result.parsed_email, result.module_results)
    codes = sorted({i.reason for i in items if i.blocks_no_indicators})
    parsed = result.parsed_email
    if not (parsed.from_ and parsed.from_.address):
        codes.append("from_header_unparseable")
    for attachment in parsed.attachments:
        name = (attachment.filename or "").lower()
        if name.endswith(".ics") or "calendar" in (getattr(attachment, "content_type", "") or "").lower():
            codes.append("calendar_invite")
            break
    return sorted(set(codes))


# ---- the frozen rules (PHASE_B_PREREGISTRATION.md 1.2 to 1.6) -----------------------------------------------------------------------------------------------------------

def tier_for(findings: list[dict], score: float, confidence: float, evidence: list[dict], t4_ok: bool, block: list[str]) -> tuple[str, str, str]:
    """(tier, route, sub-reason). `findings`: dicts with code, severity, module. Pure: the same inputs always give the same answer."""
    live = [f for f in evidence if not f["conflict"]]
    if live:
        return "T1", "HARD_EVIDENCE", ""
    reasons = [f for f in findings if REASON_TABLE[f["code"]].counts_as_reason and f["severity"] != "info"]
    medium_plus = [f for f in reasons if f["severity"] in MEDIUM_UP]
    classes_medium = {REASON_TABLE[f["code"]].cls for f in medium_plus}
    families = {REASON_TABLE[f["code"]].cls for f in reasons if REASON_TABLE[f["code"]].cls in FAMILY_CLASSES}
    r1 = len(families) >= 2
    r2 = any(f["code"] in TRUSTED_FAILURE_CODES and f["severity"] in ("high", "critical") for f in findings)  # high or higher, as v1 and compute_tier (clarification C2)
    content_floor = sum(1 for f in findings if f["module"] == "content_analysis" and f["severity"] in ("high", "critical")) >= 2
    enrichment_floor = any(f["module"] == "enrichment" and f["severity"] == "critical" for f in findings)
    r4 = content_floor and any(c != "content" for c in classes_medium)
    r5 = enrichment_floor and any(c != "enrichment" for c in classes_medium)
    r6 = bool(evidence) and all(f["conflict"] for f in evidence)
    r3 = 35 <= score < 70 and len(classes_medium) >= 2
    r3b = score >= 70
    floor_condition = r1 or r2 or content_floor or enrichment_floor
    for route, holds in (("R1", r1), ("R2", r2), ("R3B", r3b), ("R4", r4), ("R5", r5), ("R6", r6)):
        if holds:
            return "T2", route, ""
    if r3:
        if confidence < GATE and score >= 10 and not floor_condition:
            return "T3", "DEFAULT", "low_confidence"
        return "T2", "R3", ""
    if t4_ok and not block:
        return "T4", "T4_POSITIVE_EVIDENCE", ""
    sub = "signals_present" if any(f["severity"] != "info" for f in findings) else "no_signals_insufficient_evidence"
    return "T3", "DEFAULT", sub


def predict_result(result) -> tuple[str, str, str]:
    by_name = {m.module: m for m in result.module_results}
    active = {k: v for k, v in by_name.items() if v is not None and v.status not in {"error", "skipped"}}
    findings = [{"code": f.code, "severity": f.severity, "module": f.module} for m in active.values() for f in m.findings]
    gaps = benign_evidence_gaps(by_name, result.confidence, ScoringConfig())
    return tier_for(findings, result.scoring.weighted_score, result.confidence, hard_evidence(by_name), not gaps, blockers(result))


# ---- the 856 rows ----------------------------------------------------------------------------------------------------------------------------------------------------------

def compute(variants=rb.ALL_VARIANTS) -> dict[str, dict]:
    rows: dict[str, dict] = {}
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
                result = ev.analyze(path, "disabled" if enrichment == "unknown" else "clean")
                tier, route, sub = predict_result(result)
                rows[key] = {"v1": result.verdict, "tier": tier, "route": route, "sub": sub, "v1_sub": result.scoring.inconclusive_reason or ""}
    return rows


def differences(rows: dict[str, dict]) -> list[tuple[str, str]]:
    """Rows where the result differs from the written prediction (3.1): the tier mapping, R1 or R2 for a suspicious row, and the kept sub-reason for an inconclusive one."""
    out = []
    for key, r in sorted(rows.items()):
        expected = WORD_TIER.get(r["v1"])
        if expected is None:
            out.append((key, f"v1 verdict {r['v1']} has no written prediction"))
        elif r["tier"] != expected:
            out.append((key, f"tier {r['tier']} (route {r['route']}), written prediction {expected}"))
        elif r["v1"] == "suspicious" and r["route"] not in ("R1", "R2"):
            out.append((key, f"route {r['route']}, written prediction R1 or R2"))
        elif r["v1"] == "inconclusive" and r["sub"] != r["v1_sub"]:
            out.append((key, f"sub-reason {r['sub']}, v1 {r['v1_sub']}"))
    return out


def summarize(rows: dict[str, dict]) -> dict:
    by_verdict = collections.defaultdict(collections.Counter)
    by_group = collections.defaultdict(collections.Counter)
    routes = collections.Counter()
    subs = collections.Counter()
    for key, r in rows.items():
        by_verdict[r["v1"]][r["tier"]] += 1
        variant = "/".join(key.split("/")[:3])
        by_group[variant][r["tier"]] += 1
        routes[r["route"]] += 1
        if r["tier"] == "T3":
            subs[r["sub"]] += 1
    return {
        "rows": len(rows),
        "by_v1_verdict_to_tier": {v: dict(sorted(c.items())) for v, c in sorted(by_verdict.items())},
        "by_variant_and_mode_to_tier": {g: dict(sorted(c.items())) for g, c in sorted(by_group.items())},
        "by_route": dict(sorted(routes.items())),
        "t3_sub_reasons": dict(sorted(subs.items())),
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logging.getLogger("app").setLevel(logging.ERROR)
    rows = compute()
    baseline = rb.load()
    v1_moved = sorted(k for k, r in rows.items() if baseline.get(k, {}).get("verdict") != r["v1"])
    summary = summarize(rows)
    summary["v1_verdict_differs_from_recorded_baseline"] = len(v1_moved)
    diffs = differences(rows)
    summary["rows_that_differ_from_the_written_prediction"] = len(diffs)
    print(json.dumps(summary, indent=2, sort_keys=True))
    for key, why in diffs:
        print("DIFFERS:", key, "|", why)
    if "--write" in argv:
        payload = {"note": "see scripts/predict_tiers.py and docs/PHASE_B_PREREGISTRATION.md section 3", "counts": summary, "rows": rows}
        OUT.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print("wrote", OUT.relative_to(ROOT), len(rows), "rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
