"""Properties of app.scoring.tiers.compute_tier (docs/DESIGN_V2.md V2, V3, V12, V14 to V16; docs/PHASE_B_PREREGISTRATION.md section 1).

The ORACLE below is written from the frozen rules and the reason-class table, NOT from tiers.py: it re-derives the tier and the route from the inputs with its own code, and the tests compare the two
over generated inputs. If the oracle and the function disagree, one of them misreads the rules; the rules in the document decide.
"""
import ast
import copy
import itertools
import json
from pathlib import Path

import pytest

from app.reason_classes import REASON_TABLE
from app.scoring.tiers import compute_tier

BACKEND = Path(__file__).resolve().parents[1]
FAMILIES = ("sender", "link", "claim")
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TRUSTED_FAILURES = ("AUTH_SPF_CHECK_FAILED", "AUTH_DKIM_CHECK_FAILED", "AUTH_DMARC_CHECK_FAILED")
UNKNOWN = "ZZZ_NOT_A_REGISTERED_KIND"
BLOCKING_PARSER_CODES = ("parse_failure", "parse_limit", "parse_timeout")


# ---- the oracle -------------------------------------------------------------------------------------------------------------------------------------------------------------

def oracle(inputs):
    """(tier, route) from the frozen rules (pre-registration 1.2 to 1.6), re-derived independently of tiers.py."""
    findings = inputs["findings"]
    score = inputs["score"]
    gate = inputs["coverage_gate"]
    flags = inputs["t4_positive_flags"]
    blockers = set(inputs["blockers"]) | ({"unknown_finding_code"} if any(f["code"] not in REASON_TABLE for f in findings) else set())

    # 1. hard evidence: rules 1 to 4, thresholds, and the conflict rule (by registrable domain; a hash has no domain)
    live, conflicted = [], []
    for c in inputs["hard_evidence_candidates"]:
        if c["indicator_type"] not in ("link_host", "link_url", "attachment_hash") or c["is_ip"]:
            continue
        if c["is_shared_platform"] and not (c["indicator_type"] == "link_url" and c["exact_url_match"] and c["path_optin_on"]):
            continue
        qualifies = ((c["source"] == "malwarebazaar" and c["indicator_type"] == "attachment_hash")
                     or (c["source"] == "threatfox" and (c["confidence"] or 0) >= 75)
                     or (c["source"] == "virustotal" and (c["engine_count"] or 0) >= 10))
        if not qualifies:
            continue
        (conflicted if c["is_known_sender_or_own_domain"] and c["indicator_type"] != "attachment_hash" else live).append(c)
    if live:
        return "T1", "HARD_EVIDENCE"

    # reasons: a registered code, counted by the table, produced severity above info
    reasons = [(REASON_TABLE[f["code"]].cls, f["severity"], f["code"]) for f in findings
               if f["code"] in REASON_TABLE and REASON_TABLE[f["code"]].counts_as_reason and f["severity"] in RANK and f["severity"] != "info"]
    medium_plus = [r for r in reasons if RANK[r[1]] >= RANK["medium"]]
    all_known = [(REASON_TABLE[f["code"]].cls, f["severity"], f["code"]) for f in findings if f["code"] in REASON_TABLE and f["severity"] in RANK]

    r1 = len({cls for cls, _s, _c in reasons if cls in FAMILIES}) >= 2
    r2 = any(code in TRUSTED_FAILURES and RANK[sev] >= RANK["high"] for _cls, sev, code in all_known)
    content_floor = sum(1 for cls, sev, _c in all_known if cls == "content" and RANK[sev] >= RANK["high"]) >= 2
    enrichment_floor = any(cls == "enrichment" and sev == "critical" for cls, sev, _c in all_known)
    floor_condition = r1 or r2 or content_floor or enrichment_floor
    band = 35.0 <= score < 70.0 and len({cls for cls, _s, _c in medium_plus}) >= 2
    gated = band and gate["confidence"] < gate["confidence_threshold"] and score >= 10.0 and not floor_condition  # the gate: R3 only
    r3 = band and not gated
    r3b = score >= 70.0
    r4 = content_floor and any(cls != "content" for cls, _s, _c in medium_plus)
    r5 = enrichment_floor and any(cls != "enrichment" for cls, _s, _c in medium_plus)
    r6 = bool(conflicted)
    for route, holds in (("R1", r1), ("R2", r2), ("R3", r3), ("R3B", r3b), ("R4", r4), ("R5", r5), ("R6", r6)):
        if holds:
            return "T2", route

    # T4: positive evidence, complete coverage, no finding above info, no blocker
    above_info = any(f["severity"] != "info" for f in findings)
    if (flags["trusted_aligned_dkim_or_dmarc_pass"] and flags["sender_on_known_list"] and gate["confidence"] >= gate["confidence_threshold"]
            and gate["enrichment_complete"] and not above_info and not blockers):
        return "T4", "T4_POSITIVE_EVIDENCE"
    return "T3", "DEFAULT"


# ---- generators -------------------------------------------------------------------------------------------------------------------------------------------------------------

REPRESENTATIVES = ("AUTH_ALIGN_NONE_ALIGNED", "ENRICH_REPUTATION_HOST_SUSPICIOUS", "CONTENT_URGENCY_LANGUAGE", "AUTH_IDENTITY_MACHINE_SENDER_BRAND", "CONTENT_LINK_REDIRECTOR",
                   "AUTH_CLAIM_DECOY_LINKS", "AUTH_SPF_CHECK_FAILED")
EXTRAS = (("AUTH_FROM_HEADER_AMBIGUOUS", "low"), ("AUTH_ALIGN_NONE_ALIGNED_FALLBACK", "medium"), ("ENRICH_SKIPPED_PER_EMAIL_LIMIT", "low"), ("AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED", "low"),
          ("AUTH_ALL_METHODS_PASSED", "info"), ("CONTENT_LANGUAGE_UNSUPPORTED", "info"), (UNKNOWN, "high"), ("AUTH_DKIM_CHECK_FAILED", "critical"))
SEVERITIES = ("info", "low", "medium", "high", "critical")


def _finding(code, severity):
    return {"code": code, "severity": severity, "class": REASON_TABLE[code].cls if code in REASON_TABLE else "unknown"}


FINDING_TYPES = [_finding(code, sev) for code in REPRESENTATIVES for sev in SEVERITIES] + [_finding(code, sev) for code, sev in EXTRAS]


def make_inputs(findings=(), score=0.0, candidates=(), blockers=(), flags=(False, False), confidence=1.0, enrichment_complete=True):
    return {"findings": [dict(f) for f in findings], "score": score, "contributions": {"auth_check": 0.0, "enrichment": 0.0, "content_analysis": 0.0},
            "trusted_auth_failures": [], "hard_evidence_candidates": [dict(c) for c in candidates], "blockers": list(blockers),
            "t4_positive_flags": {"trusted_aligned_dkim_or_dmarc_pass": flags[0], "sender_on_known_list": flags[1]},
            "coverage_gate": {"confidence": confidence, "confidence_threshold": 0.6, "enrichment_complete": enrichment_complete}}


def _cand(indicator_type, source, value, ip=False, shared=False, optin=False, exact=False, known=False):
    return {"indicator_type": indicator_type, "source": source, "engine_count": value if source == "virustotal" else None, "confidence": value if source == "threatfox" else None,
            "is_ip": ip, "is_shared_platform": shared, "path_optin_on": optin, "exact_url_match": exact, "is_known_sender_or_own_domain": known}


def candidate_pool():
    pool = []
    for indicator_type, source, ip, shared, known in itertools.product(("link_host", "link_url", "attachment_hash", "other"), ("malwarebazaar", "threatfox", "virustotal"),
                                                                     (False, True), (False, True), (False, True)):
        values = {"malwarebazaar": (None,), "threatfox": (74, 75), "virustotal": (9, 10)}[source]
        for value in values:
            if shared and indicator_type == "link_url":
                for optin, exact in itertools.product((False, True), repeat=2):
                    pool.append(_cand(indicator_type, source, value, ip, shared, optin, exact, known))
            else:
                pool.append(_cand(indicator_type, source, value, ip, shared, False, False, known))
    return pool


def finding_sets(max_size):
    for size in range(max_size + 1):
        yield from itertools.combinations_with_replacement(FINDING_TYPES, size)


# ---- the function agrees with the oracle: tier and route ---------------------------------------------------------------------------------------------------------

def test_findings_scores_and_the_gate_agree_with_the_oracle_on_every_set_up_to_size_3():
    disagreements = []
    count = 0
    for chosen in finding_sets(3):
        for score in (0.0, 9.9, 10.0, 34.9, 35.0, 69.9, 70.0, 85.0):
            for confidence in (1.0, 0.59):
                count += 1
                inputs = make_inputs(chosen, score, confidence=confidence)
                got = compute_tier(inputs)
                if (got["tier"], got["route_id"]) != oracle(inputs):
                    disagreements.append(([(f["code"], f["severity"]) for f in chosen], score, confidence, got["tier"], got["route_id"], oracle(inputs)))
    assert count > 200_000, "the generator must really be exhaustive"
    assert disagreements[:5] == []


def test_the_t4_conditions_agree_with_the_oracle_one_by_one():
    disagreements = []
    for chosen in finding_sets(1):
        for flags in itertools.product((False, True), repeat=2):
            for confidence in (1.0, 0.59, 0.6):
                for complete in (True, False):
                    for blockers in ((), ("qr_not_decoded",), ("parse_failure",)):
                        inputs = make_inputs(chosen, 0.0, blockers=blockers, flags=flags, confidence=confidence, enrichment_complete=complete)
                        got = compute_tier(inputs)
                        if (got["tier"], got["route_id"]) != oracle(inputs):
                            disagreements.append(([(f["code"], f["severity"]) for f in chosen], flags, confidence, complete, blockers, got["tier"], oracle(inputs)))
    assert disagreements[:5] == []


def test_hard_evidence_candidates_agree_with_the_oracle_for_every_single_candidate_and_for_pairs_of_the_interesting_ones():
    pool = candidate_pool()
    base_findings = ((), (_finding("AUTH_IDENTITY_FREE_MAILBOX_BRAND", "medium"), _finding("CONTENT_LINK_REDIRECTOR", "low")), (_finding("AUTH_SPF_CHECK_FAILED", "high"),))
    disagreements = []
    for candidate in pool:
        for findings in base_findings:
            inputs = make_inputs(findings, 0.0, candidates=[candidate], flags=(True, True))
            got = compute_tier(inputs)
            if (got["tier"], got["route_id"]) != oracle(inputs):
                disagreements.append((candidate, got["tier"], oracle(inputs)))
    interesting = [c for c in pool if c["indicator_type"] in ("link_host", "attachment_hash") and not c["is_ip"] and not c["is_shared_platform"]][:24]
    for a, b in itertools.combinations(interesting, 2):
        inputs = make_inputs((), 0.0, candidates=[a, b])
        got = compute_tier(inputs)
        if (got["tier"], got["route_id"]) != oracle(inputs):
            disagreements.append((a, b, got["tier"], oracle(inputs)))
    assert disagreements[:5] == []


# ---- the named invariants ---------------------------------------------------------------------------------------------------------------------------------------------

def _all_generated():
    for chosen in finding_sets(1):
        for score in (0.0, 36.0, 72.0):
            for flags in ((False, False), (True, True)):
                for blockers in ((), ("qr_not_decoded",), BLOCKING_PARSER_CODES):
                    yield make_inputs(chosen, score, blockers=blockers, flags=flags)
    for candidate in itertools.islice(candidate_pool(), 0, None, 3):
        yield make_inputs((), 0.0, candidates=[candidate], flags=(True, True))


def test_v2_t4_is_never_reached_with_a_blocker_or_an_unknown_finding_code():
    for inputs in _all_generated():
        result = compute_tier(inputs)
        if inputs["blockers"] or any(f["code"] == UNKNOWN for f in inputs["findings"]):
            assert result["tier"] != "T4", inputs
        if result["tier"] == "T4":
            assert result["blockers"] == [] and not any(f["severity"] != "info" for f in inputs["findings"])


def test_v3_t1_only_with_a_hard_evidence_entry_that_meets_its_threshold_and_never_without_one():
    for inputs in _all_generated():
        result = compute_tier(inputs)
        assert (result["tier"] == "T1") == bool(result["hard_evidence"]), inputs
        for entry in result["hard_evidence"]:
            assert entry["rule"] in ("H1", "H2", "H3")
        if result["tier"] == "T1":
            assert any(c["source"] in ("malwarebazaar", "threatfox", "virustotal") for c in inputs["hard_evidence_candidates"])


def test_v14_and_v15_every_tier_has_reasons_or_hard_evidence_and_every_hard_evidence_entry_names_an_indicator_and_a_source():
    seen = set()
    for inputs in _all_generated():
        result = compute_tier(inputs)
        seen.add(result["tier"])
        if result["tier"] == "T1":
            assert result["hard_evidence"], inputs  # V15: T1 carries hard_evidence entries
            assert all(e["indicator"] and e["source"] and e["rule"] for e in result["hard_evidence"])
        else:
            assert result["reasons"], (result["tier"], inputs)  # V14: T2 names its route's reasons, T3 at least a gap reason, T4 the positive evidence
            assert not result["hard_evidence"]
        if result["tier"] == "T3":
            assert any(r["class"] == "gap" for r in result["reasons"]) and result["needs_analyst_reason"]
        if result["tier"] == "T4":
            assert all(r["class"] == "positive_evidence" for r in result["reasons"])
    assert seen == {"T1", "T2", "T3", "T4"}, "the generated inputs must reach every tier"


def test_v16_a_parser_failure_limit_or_timeout_never_yields_t4_and_is_listed():
    for code in BLOCKING_PARSER_CODES:
        inputs = make_inputs((), 0.0, blockers=(code,), flags=(True, True))
        result = compute_tier(inputs)
        assert result["tier"] == "T3" and code in result["blockers"]


def test_the_output_has_exactly_the_contract_names_whatever_the_tier():
    names = {"tier", "route_id", "reasons", "hard_evidence", "blockers", "needs_analyst_reason"}
    for inputs in itertools.islice(_all_generated(), 0, None, 7):
        assert set(compute_tier(inputs)) == names


def test_the_reasons_list_contains_evidence_conflict_whenever_the_conflict_applies_whatever_the_route():
    conflicted = _cand("link_host", "threatfox", 90, known=True)
    live = _cand("attachment_hash", "virustotal", 15)
    family_pair = (_finding("AUTH_IDENTITY_FREE_MAILBOX_BRAND", "medium"), _finding("CONTENT_LINK_REDIRECTOR", "low"))
    strong = (_finding("AUTH_SPF_CHECK_FAILED", "high"),)
    for findings, candidates, score in (((), [conflicted], 0.0), (family_pair, [conflicted], 7.0), (strong, [conflicted], 9.0), ((), [conflicted], 72.0), ((), [conflicted, live], 0.0),
                                        (family_pair, [conflicted, live], 7.0)):
        result = compute_tier(make_inputs(findings, score, candidates=candidates))
        assert "evidence_conflict" in {r["code"] for r in result["reasons"]}, (result["tier"], result["route_id"])
    # and never when nothing conflicts, and never for a hash (it has no domain)
    for candidates in ([], [_cand("attachment_hash", "malwarebazaar", None, known=True)], [live]):
        result = compute_tier(make_inputs((), 0.0, candidates=candidates))
        assert "evidence_conflict" not in {r["code"] for r in result["reasons"]}


# ---- unknown codes and severities -------------------------------------------------------------------------------------------------------------------------------------

def test_an_unknown_finding_code_is_never_a_reason_adds_a_blocker_and_cannot_complete_a_route():
    unknown = _finding(UNKNOWN, "critical")
    band_base = (_finding("ENRICH_REPUTATION_HOST_SUSPICIOUS", "high"), _finding("ENRICH_REPUTATION_HOST_SUSPICIOUS", "high"))
    result = compute_tier(make_inputs(band_base + (unknown,), 40.0))
    assert result["tier"] == "T3" and "unknown_finding_code" in result["blockers"]  # it is not the second class of route R3
    assert UNKNOWN not in {r["code"] for r in result["reasons"]}
    result = compute_tier(make_inputs((unknown,), 0.0, flags=(True, True)))
    assert result["tier"] == "T3" and result["blockers"] == ["unknown_finding_code"] and result["needs_analyst_reason"] == ["signals_present"]
    # a route that holds without it is unchanged
    assert compute_tier(make_inputs((unknown, _finding("AUTH_SPF_CHECK_FAILED", "high")), 9.0))["route_id"] == "R2"


def test_an_unrecognised_severity_is_never_a_reason_and_blocks_t4():
    odd = _finding("AUTH_ALIGN_NONE_ALIGNED", "catastrophic")
    result = compute_tier(make_inputs((odd,), 0.0, flags=(True, True)))
    assert result["tier"] == "T3" and result["needs_analyst_reason"] == ["signals_present"]
    pair = (_finding("ENRICH_REPUTATION_HOST_SUSPICIOUS", "high"), _finding("ENRICH_REPUTATION_HOST_SUSPICIOUS", "high"), odd)
    assert compute_tier(make_inputs(pair, 40.0))["tier"] == "T3"


def test_missing_optional_inputs_take_safe_defaults():
    assert compute_tier({})["tier"] == "T3"
    assert compute_tier({"findings": [_finding("AUTH_SPF_CHECK_FAILED", "high")]})["route_id"] == "R2"


# ---- determinism, no mutation, purity ---------------------------------------------------------------------------------------------------------------------------------

def test_the_function_is_deterministic_and_never_mutates_its_input():
    for inputs in itertools.islice(_all_generated(), 0, None, 5):
        before = copy.deepcopy(inputs)
        first = compute_tier(inputs)
        assert inputs == before, "the input was mutated"
        assert compute_tier(copy.deepcopy(inputs)) == first
        assert json.dumps(first, sort_keys=True) == json.dumps(compute_tier(inputs), sort_keys=True)
        first["reasons"].append("tampered")  # the output shares nothing with the input
        assert inputs == before


def test_the_module_is_pure_it_imports_nothing_with_io_network_logging_time_or_randomness():
    tree = ast.parse((BACKEND / "app" / "scoring" / "tiers.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "dataclasses", "typing", "app.reason_classes", "app.scoring.config"}, imported
    calls = {getattr(n.func, "id", getattr(n.func, "attr", "")) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"open", "print", "input", "exec", "eval", "getLogger", "urlopen", "request", "random", "now", "time"}, calls & {"open", "print", "input"}


def test_every_threshold_lives_in_the_config_block_and_the_shared_ones_come_from_scoring_config():
    from app.scoring.config import ScoringConfig
    from app.scoring.tiers import TIER_CONFIG

    v1 = ScoringConfig()
    assert (TIER_CONFIG.score_band_low, TIER_CONFIG.score_band_high, TIER_CONFIG.confidence_threshold) == (v1.verdict_score_suspicious, v1.verdict_score_malicious, v1.confidence_threshold)
    assert (TIER_CONFIG.gate_score_floor, TIER_CONFIG.min_families, TIER_CONFIG.content_floor_count) == (v1.inconclusive_score_floor, v1.structural_floor_min_families,
                                                                                                    v1.content_floor_min_high_severity_count)
    assert (TIER_CONFIG.enrichment_floor_severity, TIER_CONFIG.auth_floor_severity) == (v1.floor_override_severity["enrichment"], v1.floor_override_severity["auth_check"])
    assert (TIER_CONFIG.threatfox_min_confidence, TIER_CONFIG.virustotal_min_engines, TIER_CONFIG.reason_min_severity) == (75, 10, "medium")
    # no bare threshold literals in the function bodies: the numbers 35, 70, 0.6, 75 and 10 appear only in the config block
    source = (BACKEND / "app" / "scoring" / "tiers.py").read_text(encoding="utf-8")
    body = source[source.index("def _hard_evidence"):]
    tree = ast.parse(body)
    literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool)}
    assert literals <= {0, 0.0, 1, 1.0}, literals
