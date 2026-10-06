"""The Phase B specification cases (D23; docs/PHASE_B_PREREGISTRATION.md): data first, before any tier code exists.

Three kinds of test live here.
  * COMPLETENESS and CONSISTENCY tests, which pass now: every D23 category is present, ids are unique, every finding code exists in the registry and carries the class the table gives it, every
    blocker of DESIGN_V2.md 2.3 has its case, the arithmetic fact behind R3B holds, and every case agrees with the frozen rules as the read-only predictor (scripts/predict_tiers.py) executes them.
  * The BEHAVIOUR test and the V12 PROPERTY test, which import `compute_tier` from `app.scoring.tiers` (not built) and are marked xfail(strict=True): the implementation commit MUST remove the
    marks, and the strict mark makes it fail loudly if it forgets.

Calling convention pinned here, so the implementation has one thing to satisfy: `compute_tier(inputs: dict)`, where `inputs` has the contract names of section 2 (findings, score, contributions,
trusted_auth_failures, hard_evidence_candidates, blockers, t4_positive_flags, coverage_gate); the result exposes `tier`, `route_id`, `reasons` (each with a `code`), `hard_evidence` (each with a `rule`),
`blockers` and `needs_analyst_reason`, as attributes or as keys.
"""
import importlib.util
import itertools
import json
from pathlib import Path

import pytest

from app.finding_codes import BY_CODE
from app.reason_classes import CLASSES, REASON_TABLE
from app.scoring.config import ScoringConfig

ROOT = Path(__file__).resolve().parents[2]
CASES_FILE = ROOT / "backend" / "tests" / "fixtures" / "v2_cases.json"
DOC = ROOT / "docs" / "PHASE_B_PREREGISTRATION.md"
SEVERITIES = ("info", "low", "medium", "high", "critical")
FAMILY_CLASSES = ("sender", "link", "claim")
ROUTES = {"R1", "R2", "R3", "R3B", "R4", "R5", "R6"}
SPEC = json.loads(CASES_FILE.read_text(encoding="utf-8"))
CASES = SPEC["cases"]

# Every D23 category and every extra the owner listed for step 7.
REQUIRED_CATEGORIES = {
    "demoted_route_one_class", "demoted_route_second_class", "severity_rule", "r3b", "score_boundary", "ineligible_code", "strong_signal", "structural_family",
    "hard_evidence_positive", "hard_evidence_boundary", "hard_evidence_never", "shared_platform", "conflict", "t4_positive", "t4_condition", "blocker", "parser_failure",
    "coverage_gate", "precedence",
}
# DESIGN_V2.md 2.3: one case per blocker, each stopping T4.
REQUIRED_BLOCKER_KINDS = {
    "image_attachment", "inline_cid_image", "data_uri_image", "active_attachment_office_macro", "active_attachment_pdf", "active_attachment_script", "html_attachment", "archive",
    "password_protected_archive", "disk_image", "encrypted_office_file", "encrypted_pdf", "nested_message", "calendar_invite", "shortener_unresolved", "shared_platform_link_not_looked_at",
    "internal_host", "unreadable_language", "no_readable_text", "no_trusted_hop", "malformed_from", "parser_failure", "parser_limit", "parser_timeout",
}


@pytest.fixture(scope="module")
def predictor():
    spec = importlib.util.spec_from_file_location("predict_tiers", ROOT / "scripts" / "predict_tiers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---- completeness ----------------------------------------------------------------------------------------------------------------------------------------------------------

def test_every_d23_category_and_every_listed_extra_is_present():
    assert REQUIRED_CATEGORIES - {c["category"] for c in CASES} == set()


def test_ids_are_unique_and_every_case_has_inputs_and_an_expected_result():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))
    for c in CASES:
        assert set(c["inputs"]) == set(SPEC["defaults"]), c["id"]
        assert set(c["expected"]) == {"tier", "route", "reason_codes", "hard_evidence", "needs_analyst_reason", "blockers"}, c["id"]


def test_every_finding_code_used_exists_in_the_registry_with_the_class_the_table_gives_it():
    for c in CASES:
        for f in c["inputs"]["findings"]:
            assert f["code"] in BY_CODE, (c["id"], f["code"])
            assert f["class"] == REASON_TABLE[f["code"]].cls and f["class"] in CLASSES, (c["id"], f["code"])
            assert f["severity"] in SEVERITIES, (c["id"], f["code"])


def test_expected_tiers_and_routes_are_well_formed():
    for c in CASES:
        e = c["expected"]
        assert e["tier"] in {"T1", "T2", "T3", "T4"}, c["id"]
        if e["tier"] == "T2":
            assert e["route"] in ROUTES, c["id"]
        assert e["route"] in ROUTES | {"HARD_EVIDENCE", "T4_POSITIVE_EVIDENCE", "DEFAULT"}, c["id"]
        assert (e["tier"] == "T1") == bool(e["hard_evidence"]), f"{c['id']}: hard_evidence is non-empty exactly for T1"
        assert (e["tier"] == "T1") == (e["route"] == "HARD_EVIDENCE"), c["id"]
        assert (e["tier"] == "T4") == (e["route"] == "T4_POSITIVE_EVIDENCE"), c["id"]


def test_every_blocker_of_2_3_has_its_case_and_each_stops_t4_with_every_positive_condition_true():
    blocker_cases = {c["blocker_kind"]: c for c in CASES if "blocker_kind" in c}
    assert set(blocker_cases) == REQUIRED_BLOCKER_KINDS
    vocabulary = set(SPEC["blocker_codes"]["existing"]) | set(SPEC["blocker_codes"]["phase_b_new"])
    for kind, c in blocker_cases.items():
        flags = c["inputs"]["t4_positive_flags"]
        assert flags == {"trusted_aligned_dkim_or_dmarc_pass": True, "sender_on_known_list": True}, kind
        assert c["inputs"]["findings"] == [] and c["inputs"]["coverage_gate"]["confidence"] >= 0.6, kind
        assert len(c["inputs"]["blockers"]) == 1 and c["inputs"]["blockers"][0] in vocabulary, kind
        assert c["expected"]["tier"] == "T3" and c["expected"]["blockers"] == c["inputs"]["blockers"], kind


def test_each_demoted_route_has_a_one_class_case_that_is_t3_and_a_second_class_case_that_is_t2():
    by_id = {c["id"]: c for c in CASES}
    for one, two, route in (("content_floor_one_class", "content_floor_second_class_auth", "R4"), ("enrichment_floor_one_class", "enrichment_floor_second_class_claim", "R5"),
                            ("score_band_one_class", "score_band_second_class", "R3")):
        assert by_id[one]["expected"]["tier"] == "T3" and (by_id[two]["expected"]["tier"], by_id[two]["expected"]["route"]) == ("T2", route)


def test_the_named_boundaries_are_pinned():
    ids = {c["id"] for c in CASES}
    assert {"h2_boundary_75", "h2_boundary_74", "h3_boundary_10", "h3_boundary_9", "boundary_score_34_9", "boundary_score_35", "boundary_score_69_9", "boundary_score_70"} <= ids


def test_no_single_module_can_reach_70_so_r3b_needs_at_least_two_modules():
    config = ScoringConfig()
    largest = {category: weight * config.category_subscore_cap for category, weight in config.category_weights.items()}
    assert round(sum(config.category_weights.values()), 9) == 1.0
    assert largest["enrichment"] == 40.0  # 0.40 x 100, the largest single-module contribution
    assert max(largest.values()) < config.verdict_score_malicious == 70.0
    # and two modules are enough: the two largest contributions add to more than 70
    assert sorted(largest.values())[-1] + sorted(largest.values())[-2] > 70.0
    for c in CASES:  # the cases never claim a contribution a module cannot make
        for category, value in c["inputs"]["contributions"].items():
            assert value <= largest[category] + 1e-9, (c["id"], category)


def test_the_cases_file_hash_is_recorded_in_the_pre_registration(predictor):
    digest = predictor.sha256_lf(CASES_FILE)
    assert f"`{digest}`" in DOC.read_text(encoding="utf-8"), "v2_cases.json changed: log the change in section 6 of docs/PHASE_B_PREREGISTRATION.md and update section 7"


# ---- consistency with the frozen rules as the predictor executes them -------------------------------------------------------------------------------

def _survives(c):
    """Rules 1 to 4 of 1.5 and the thresholds for one candidate; returns {rule, source, conflict} or None."""
    if c["indicator_type"] not in ("link_host", "link_url", "attachment_hash") or c["is_ip"]:
        return None
    if c["is_shared_platform"] and not (c["indicator_type"] == "link_url" and c["exact_url_match"] and c["path_optin_on"]):
        return None
    if c["source"] == "malwarebazaar" and c["indicator_type"] == "attachment_hash":
        rule = "H1"
    elif c["source"] == "threatfox" and (c["confidence"] or 0) >= 75:
        rule = "H2"
    elif c["source"] == "virustotal" and (c["engine_count"] or 0) >= 10:
        rule = "H3"
    else:
        return None
    return {"rule": rule, "source": c["source"], "conflict": c["is_known_sender_or_own_domain"]}


def _reason_codes(route, findings):
    """The codes that support the route that names the tier (the convention in the cases file)."""
    eligible = [f for f in findings if REASON_TABLE[f["code"]].counts_as_reason and f["severity"] != "info"]
    medium_plus = [f for f in eligible if f["severity"] in ("medium", "high", "critical")]
    if route == "R1":
        picked = [f for f in eligible if f["class"] in FAMILY_CLASSES]
    elif route == "R2":
        picked = [f for f in findings if f["code"].endswith("_CHECK_FAILED") and f["severity"] == "high"]
    elif route == "R3":
        picked = medium_plus
    elif route == "R3B":
        picked = eligible
    elif route == "R4":
        picked = [f for f in findings if f["class"] == "content" and f["severity"] in ("high", "critical")] + [f for f in medium_plus if f["class"] != "content"]
    elif route == "R5":
        picked = [f for f in findings if f["class"] == "enrichment" and f["severity"] == "critical"] + [f for f in medium_plus if f["class"] != "enrichment"]
    elif route == "R6":
        return ["evidence_conflict"]
    else:
        return []
    return sorted({f["code"] for f in picked})


def _run_frozen_rules(predictor, inputs):
    findings = [{"code": f["code"], "severity": f["severity"], "module": BY_CODE[f["code"]].module} for f in inputs["findings"]]
    evidence = [e for e in (_survives(c) for c in inputs["hard_evidence_candidates"]) if e]
    gate = inputs["coverage_gate"]
    flags = inputs["t4_positive_flags"]
    t4_ok = (flags["trusted_aligned_dkim_or_dmarc_pass"] and flags["sender_on_known_list"] and gate["confidence"] >= gate["confidence_threshold"]
             and gate["enrichment_complete"] and not any(f["severity"] != "info" for f in findings))
    tier, route, sub = predictor.tier_for(findings, inputs["score"], gate["confidence"], evidence, t4_ok, inputs["blockers"])
    return tier, route, sub, sorted(e["rule"] for e in evidence if not e["conflict"]) if tier == "T1" else []


def test_every_case_agrees_with_the_frozen_rules_as_the_predictor_executes_them(predictor):
    mismatches = []
    for c in CASES:
        e = c["expected"]
        tier, route, sub, rules = _run_frozen_rules(predictor, c["inputs"])
        if (tier, route) != (e["tier"], e["route"]):
            mismatches.append((c["id"], "tier/route", (tier, route), (e["tier"], e["route"])))
        if e["needs_analyst_reason"] and not set(e["needs_analyst_reason"]) <= {sub}:
            mismatches.append((c["id"], "needs_analyst_reason", sub, e["needs_analyst_reason"]))
        if tier == "T1" and rules != sorted(h["rule"] for h in e["hard_evidence"]):
            mismatches.append((c["id"], "hard_evidence", rules, e["hard_evidence"]))
        if e["reason_codes"] is not None and _reason_codes(route if tier in ("T1", "T2") else "", c["inputs"]["findings"]) != e["reason_codes"]:
            mismatches.append((c["id"], "reason_codes", _reason_codes(route, c["inputs"]["findings"]), e["reason_codes"]))
    assert mismatches == []


# ---- V12: the property specification, as an oracle independent of the predictor -------------------------------------------------------------------------

# One eligible representative code per reason class, plus the trusted-failure code (class auth, the strong signal).
REPRESENTATIVES = {"auth": "AUTH_ALIGN_NONE_ALIGNED", "enrichment": "ENRICH_REPUTATION_HOST_SUSPICIOUS", "content": "CONTENT_URGENCY_LANGUAGE", "sender": "AUTH_IDENTITY_MACHINE_SENDER_BRAND",
                   "link": "CONTENT_LINK_REDIRECTOR", "claim": "AUTH_CLAIM_DECOY_LINKS", "strong": "AUTH_SPF_CHECK_FAILED"}
SCORES = (20.0, 40.0, 72.0)  # below the band, inside it, and at or above 70


def _types():
    return [(name, code, REASON_TABLE[code].cls, severity) for name, code in REPRESENTATIVES.items() for severity in SEVERITIES]


def _sets(max_size):
    for size in range(max_size + 1):
        yield from itertools.combinations_with_replacement(_types(), size)


def _named_route_satisfied(chosen, score):
    """V12's oracle: T2 if and only if one of R1 to R5 or R3B holds (no hard evidence is generated). Written from the frozen text, not from the predictor."""
    items = [(name, cls, sev) for name, _code, cls, sev in chosen]  # (representative name, class, produced severity)
    above = [t for t in items if t[2] != "info"]
    medium = [t for t in above if t[2] in ("medium", "high", "critical")]
    r1 = len({cls for _n, cls, _s in above if cls in FAMILY_CLASSES}) >= 2
    r2 = any(name == "strong" and sev == "high" for name, _cls, sev in above)
    content_floor = sum(1 for _n, cls, sev in items if cls == "content" and sev in ("high", "critical")) >= 2
    enrichment_floor = any(cls == "enrichment" and sev == "critical" for _n, cls, sev in items)
    r3 = 35.0 <= score < 70.0 and len({cls for _n, cls, _s in medium}) >= 2
    r3b = score >= 70.0
    r4 = content_floor and any(cls != "content" for _n, cls, _s in medium)
    r5 = enrichment_floor and any(cls != "enrichment" for _n, cls, _s in medium)
    return r1 or r2 or r3 or r3b or r4 or r5


def _inputs_for(chosen, score):
    return {"findings": [{"code": code, "severity": sev, "class": cls} for _n, code, cls, sev in chosen], "score": score,
            "contributions": {"auth_check": 0.0, "enrichment": 0.0, "content_analysis": 0.0}, "trusted_auth_failures": [], "hard_evidence_candidates": [], "blockers": [],
            "t4_positive_flags": {"trusted_aligned_dkim_or_dmarc_pass": False, "sender_on_known_list": False},
            "coverage_gate": {"confidence": 1.0, "confidence_threshold": 0.6, "enrichment_complete": True}}


def test_the_v12_oracle_agrees_with_the_predictor_on_every_generated_set_up_to_size_3_except_one_known_divergence(predictor):
    """Validates the specification itself now (size 3 keeps it fast; the property test below goes to size 4).

    KNOWN DIVERGENCE, reported to the owner and not resolved here: the frozen predictor counts the v1 content floor (two findings at severity high) by the MODULE that produced them
    (content_analysis), as v1 does; the contract, D16 and this oracle count by CLASS (content). They differ only for a link-class finding (built by content_analysis) at severity high, which no
    producer emits (the link kinds are low or medium), so the 856 baseline rows are unaffected. The interface gives `compute_tier` no module field, so the implementation counts by class."""
    disagreements = []
    for chosen in _sets(3):
        findings = [{"code": code, "severity": sev, "module": BY_CODE[code].module} for _n, code, _c, sev in chosen]
        for score in SCORES:
            tier, route, _sub = predictor.tier_for(findings, score, 1.0, [], False, [])
            if (tier == "T2") != _named_route_satisfied(chosen, score):
                disagreements.append((chosen, score, tier, route))

    def explained(item):
        chosen, _score, tier, route = item
        return tier == "T2" and route == "R4" and any(cls == "link" and sev in ("high", "critical") for _n, _code, cls, sev in chosen)

    assert [([(n, s) for n, _c, _cl, s in chosen], score, tier, route) for chosen, score, tier, route in disagreements if not explained((chosen, score, tier, route))] == []


# ---- the strict xfails: the implementation commit must remove these marks ------------------------------------------------------------------------------------

def _field(result, name):
    return result[name] if isinstance(result, dict) else getattr(result, name)


def _item(entry, name):
    return entry[name] if isinstance(entry, dict) else getattr(entry, name)


@pytest.mark.xfail(strict=True, raises=ImportError, reason="Phase B tier logic not built")
def test_compute_tier_gives_the_expected_tier_route_reasons_hard_evidence_and_blockers_for_every_case():
    from app.scoring.tiers import compute_tier

    mismatches = []
    for c in CASES:
        e = c["expected"]
        result = compute_tier(json.loads(json.dumps(c["inputs"])))
        got = {"tier": _field(result, "tier"), "route": _field(result, "route_id"), "blockers": sorted(_field(result, "blockers"))}
        want = {"tier": e["tier"], "route": e["route"], "blockers": e["blockers"]}
        if got != want:
            mismatches.append((c["id"], got, want))
        if e["reason_codes"] is not None and e["tier"] in ("T1", "T2"):
            if sorted({_item(r, "code") for r in _field(result, "reasons")}) != e["reason_codes"]:
                mismatches.append((c["id"], "reason_codes"))
        if sorted(_item(h, "rule") for h in _field(result, "hard_evidence")) != sorted(h["rule"] for h in e["hard_evidence"]):
            mismatches.append((c["id"], "hard_evidence"))
        reason = _field(result, "needs_analyst_reason") or []
        reason = {reason} if isinstance(reason, str) else set(reason)
        if not set(e["needs_analyst_reason"]) <= reason:
            mismatches.append((c["id"], "needs_analyst_reason"))
    assert mismatches == []


@pytest.mark.xfail(strict=True, raises=ImportError, reason="Phase B tier logic not built")
def test_v12_t2_if_and_only_if_a_named_route_is_satisfied_over_every_generated_finding_set_up_to_size_4():
    from app.scoring.tiers import compute_tier

    violations = []
    for chosen in _sets(4):
        for score in SCORES:
            result = compute_tier(_inputs_for(chosen, score))
            is_t2 = _field(result, "tier") == "T2"
            if is_t2 != _named_route_satisfied(chosen, score) or (is_t2 and _field(result, "route_id") not in ROUTES):
                violations.append(([(n, s) for n, _c, _cl, s in chosen], score, _field(result, "tier")))
                if len(violations) >= 20:
                    break
    assert violations == []
