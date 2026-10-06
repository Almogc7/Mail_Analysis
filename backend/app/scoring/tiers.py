"""Verdict v2: the tier function (docs/PHASE_B_PREREGISTRATION.md sections 1 and 2; docs/DESIGN_V2.md 2.1 to 2.3, D16 and D22).

`compute_tier(inputs)` is a PURE function: no I/O, no network, no logging, deterministic, and it never mutates its input. It is NOT wired into the pipeline, the API or the frontend yet
(`verdict_v2` does not exist); only tests and read-only scripts call it.

Evaluation order, first match wins:
  1. hard evidence (DESIGN_V2.md 2.2, rules 1 to 6): a live entry gives T1; an entry in conflict gives route R6 later, never T1;
  2. the T2 routes in the order R1, R2, R3, R3B, R4, R5, R6 (the first that holds names the route; every reason of every route that holds is listed);
  3. T4 (positive evidence, complete coverage, no finding above info, no blocker);
  4. T3, the default, with its sub-reason and its gaps.

A finding counts as a REASON only if its code is registered, the table says the kind counts (app/reason_classes.py) and its produced severity is above info; routes R3, R4 and R5 also need medium or
higher. The class always comes from the table, never from the input. An unknown code is never a reason and adds the blocker `unknown_finding_code`, so it can never reach T4.
Counting is by reason CLASS, not by module (clarification C1). The 0.6 gate applies to route R3 only. Every threshold is in `TierConfig`, reusing scoring/config.py where a value already exists there.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.reason_classes import REASON_TABLE
from app.scoring.config import ScoringConfig, severity_at_least

_V1 = ScoringConfig()

SEVERITIES = ("info", "low", "medium", "high", "critical")
FAMILY_CLASSES = ("sender", "link", "claim")
HARD_EVIDENCE_TYPES = ("link_host", "link_url", "attachment_hash")
# The strong signal (a closed list, D22 route 2): a trusted-receiver authentication failure.
TRUSTED_FAILURE_CODES = ("AUTH_SPF_CHECK_FAILED", "AUTH_DKIM_CHECK_FAILED", "AUTH_DMARC_CHECK_FAILED")
UNKNOWN_CODE_BLOCKER = "unknown_finding_code"
ROUTE_ORDER = ("R1", "R2", "R3", "R3B", "R4", "R5", "R6")


@dataclass(frozen=True)
class TierConfig:
    """Every threshold of the tier rules in one place. Values that exist in scoring/config.py are taken from it, not repeated."""

    score_band_low: float = _V1.verdict_score_suspicious  # 35: route R3 starts here
    score_band_high: float = _V1.verdict_score_malicious  # 70: route R3B starts here
    confidence_threshold: float = _V1.confidence_threshold  # 0.6, the internal gate
    gate_score_floor: float = _V1.inconclusive_score_floor  # 10: the gate applies from this weighted score
    min_families: int = _V1.structural_floor_min_families  # R1: different structural families
    band_min_classes: int = 2  # R3: different reason classes among the medium-or-higher reasons
    content_floor_count: int = _V1.content_floor_min_high_severity_count  # R4: content findings at the floor severity
    content_floor_severity: str = "high"
    enrichment_floor_severity: str = _V1.floor_override_severity["enrichment"]  # R5: critical
    auth_floor_severity: str = _V1.floor_override_severity["auth_check"]  # R2: high
    reason_min_severity: str = "medium"  # the second-reason severity rule of routes R3, R4 and R5
    threatfox_min_confidence: int = 75  # H2 (a priori, D2)
    virustotal_min_engines: int = 10  # H3 (a priori, D2)


TIER_CONFIG = TierConfig()


def _hard_evidence(candidates: list[dict], config: TierConfig) -> list[dict]:
    """H1 to H3 candidates that survive rules 1 to 4 and the thresholds. `conflict` is by registrable domain, and never applies to a hash (it has no domain)."""
    kept: list[dict] = []
    for cand in candidates:
        indicator_type = cand.get("indicator_type")
        if indicator_type not in HARD_EVIDENCE_TYPES or cand.get("is_ip"):
            continue  # rule 1 (only indicators the recipient interacts with) and rule 2 (an IP alone never counts)
        if cand.get("is_shared_platform") and not (indicator_type == "link_url" and cand.get("exact_url_match") and cand.get("path_optin_on")):
            continue  # rules 3 and 4
        source = cand.get("source")
        if source == "malwarebazaar" and indicator_type == "attachment_hash":
            rule = "H1"
        elif source == "threatfox" and (cand.get("confidence") or 0) >= config.threatfox_min_confidence:
            rule = "H2"
        elif source == "virustotal" and (cand.get("engine_count") or 0) >= config.virustotal_min_engines:
            rule = "H3"
        else:
            continue
        kept.append({"indicator": cand.get("indicator") or indicator_type, "source": source, "rule": rule,
                     "conflict": bool(cand.get("is_known_sender_or_own_domain")) and indicator_type != "attachment_hash"})
    return kept


def _item(finding: dict, routes: list[str] | None = None) -> dict:
    return {"code": finding["code"], "class": finding["class"], "severity": finding["severity"], "routes": list(routes or [])}


def compute_tier(inputs: dict[str, Any], config: TierConfig = TIER_CONFIG) -> dict[str, Any]:
    score = float(inputs.get("score") or 0.0)
    gate = inputs.get("coverage_gate") or {}
    confidence = float(gate.get("confidence", 1.0))
    threshold = float(gate.get("confidence_threshold", config.confidence_threshold))
    enrichment_complete = bool(gate.get("enrichment_complete", True))
    flags = inputs.get("t4_positive_flags") or {}

    # ---- the findings: class and eligibility from the table, severity as produced -----------------------------------------------------------------------------
    known: list[dict] = []
    unknown_code = False
    above_info_any = False
    for raw in inputs.get("findings") or []:
        code, severity = raw.get("code"), raw.get("severity")
        above_info_any = above_info_any or severity != "info"
        entry = REASON_TABLE.get(code) if isinstance(code, str) else None
        if entry is None:
            unknown_code = True
            continue
        known.append({"code": code, "class": entry.cls, "severity": severity, "counts": entry.counts_as_reason})
    blockers = sorted(set(inputs.get("blockers") or []) | ({UNKNOWN_CODE_BLOCKER} if unknown_code else set()))

    pool = [f for f in known if f["counts"] and f["severity"] in SEVERITIES and f["severity"] != "info"]  # reasons: eligible and above info
    medium_plus = [f for f in pool if severity_at_least(f["severity"], config.reason_min_severity)]

    # ---- 1. hard evidence --------------------------------------------------------------------------------------------------------------------------------------------
    evidence = _hard_evidence(list(inputs.get("hard_evidence_candidates") or []), config)
    live = [e for e in evidence if not e["conflict"]]
    conflicted = [e for e in evidence if e["conflict"]]
    conflict_item = {"code": "evidence_conflict", "class": "hard_evidence", "severity": "high", "routes": ["R6"],
                     "sources": sorted({e["source"] for e in conflicted}), "against": "known_sender_or_own_domain"}
    if live:
        return {"tier": "T1", "route_id": "HARD_EVIDENCE", "reasons": [conflict_item] if conflicted else [],
                "hard_evidence": [{"indicator": e["indicator"], "source": e["source"], "rule": e["rule"]} for e in live],
                "blockers": blockers, "needs_analyst_reason": []}

    # ---- 2. the T2 routes --------------------------------------------------------------------------------------------------------------------------------------------
    supports: dict[str, list[dict]] = {}
    families = {f["class"] for f in pool if f["class"] in FAMILY_CLASSES}
    if len(families) >= config.min_families:
        supports["R1"] = [f for f in pool if f["class"] in FAMILY_CLASSES]
    strong = [f for f in known if f["code"] in TRUSTED_FAILURE_CODES and severity_at_least(f["severity"], config.auth_floor_severity)]
    if strong:
        supports["R2"] = strong
    content_floor = [f for f in known if f["class"] == "content" and severity_at_least(f["severity"], config.content_floor_severity)]
    content_floor_holds = len(content_floor) >= config.content_floor_count
    enrichment_floor = [f for f in known if f["class"] == "enrichment" and severity_at_least(f["severity"], config.enrichment_floor_severity)]
    enrichment_floor_holds = bool(enrichment_floor)
    floor_condition = bool(supports) or content_floor_holds or enrichment_floor_holds  # R1, R2, or either floor's own condition

    gate_demoted = False
    if config.score_band_low <= score < config.score_band_high and len({f["class"] for f in medium_plus}) >= config.band_min_classes:
        if confidence < threshold and score >= config.gate_score_floor and not floor_condition:
            gate_demoted = True  # the internal 0.6 gate applies to R3 only; a floor is never erased by low coverage
        else:
            supports["R3"] = medium_plus
    if score >= config.score_band_high:
        supports["R3B"] = pool
    if content_floor_holds and any(f["class"] != "content" for f in medium_plus):
        supports["R4"] = content_floor + [f for f in medium_plus if f["class"] != "content"]
    if enrichment_floor_holds and any(f["class"] != "enrichment" for f in medium_plus):
        supports["R5"] = enrichment_floor + [f for f in medium_plus if f["class"] != "enrichment"]
    if conflicted:
        supports["R6"] = []

    holding = [route for route in ROUTE_ORDER if route in supports]
    if holding:
        reasons: list[dict] = []
        by_key: dict[tuple, dict] = {}
        for route in holding:
            for f in supports[route]:
                key = (f["code"], f["severity"])
                if key not in by_key:
                    by_key[key] = _item(f)
                    reasons.append(by_key[key])
                if route not in by_key[key]["routes"]:
                    by_key[key]["routes"].append(route)
        if "R3" in holding:
            reasons.append({"code": "weighted_score_band", "class": "score", "severity": "medium", "routes": ["R3"]})
        if "R3B" in holding:
            reasons.append({"code": "weighted_score_70_or_more", "class": "score", "severity": "high", "routes": ["R3B"]})
        if conflicted:
            reasons.append(conflict_item)
        return {"tier": "T2", "route_id": holding[0], "reasons": reasons, "hard_evidence": [], "blockers": blockers, "needs_analyst_reason": []}

    # ---- 3. T4 -------------------------------------------------------------------------------------------------------------------------------------------------------
    if (flags.get("trusted_aligned_dkim_or_dmarc_pass") and flags.get("sender_on_known_list") and confidence >= threshold and enrichment_complete
            and not above_info_any and not blockers):
        positive = [{"code": "trusted_aligned_dkim_or_dmarc_pass", "class": "positive_evidence", "severity": "info", "routes": []},
                    {"code": "sender_on_known_list", "class": "positive_evidence", "severity": "info", "routes": []}]
        return {"tier": "T4", "route_id": "T4_POSITIVE_EVIDENCE", "reasons": positive, "hard_evidence": [], "blockers": blockers, "needs_analyst_reason": []}

    # ---- 4. T3, the default ------------------------------------------------------------------------------------------------------------------------------------------
    sub = "signals_present" if above_info_any else "no_signals_insufficient_evidence"
    needs = [sub] + (["low_confidence"] if gate_demoted else [])
    gaps = [{"code": code, "class": "gap", "severity": "info", "routes": []} for code in needs + blockers]
    return {"tier": "T3", "route_id": "DEFAULT", "reasons": gaps, "hard_evidence": [], "blockers": blockers, "needs_analyst_reason": needs}
