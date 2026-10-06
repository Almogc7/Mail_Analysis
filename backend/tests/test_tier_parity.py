"""Parity checks (docs/PHASE_B_PREREGISTRATION.md): the class-based floors equal the frozen predictor (clarification C1), and compute_tier, fed by the input builder in scripts/check_tier_parity.py,
equals backend/tests/fixtures/predicted_tiers.json on every row (tier, route and T3 sub-reason).

The as-is clean rows run in-process. The full 856 rows need the seeds-ablated variants, which cannot be undone inside one process, so they run in a subprocess (about twenty seconds)."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from tests import eval as ev
from tests import regression_baseline as rb

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_tier_parity.py"


@pytest.fixture(scope="module")
def parity():
    spec = importlib.util.spec_from_file_location("check_tier_parity", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_class_based_recompute_and_compute_tier_equal_the_predictor_on_the_as_is_clean_rows(parity):
    try:
        outcome = parity.check(rb.FAST_VARIANTS)
    finally:
        ev.apply_mode("configured")
    assert outcome["rows"] == 214
    assert outcome["class_based_differs_from_module_based"] == []
    assert outcome["compute_tier_differs_from_prediction"] == []


def test_a_class_based_recompute_and_compute_tier_equal_the_predictor_on_all_856_rows():
    done = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=ROOT, timeout=900)
    assert done.returncode == 0, done.stdout[-2000:]
    assert "checked 856 rows; class-based differs from module-based: 0" in done.stdout
    assert "compute_tier differs from predicted_tiers.json (tier, route, T3 sub-reason): 0" in done.stdout


def test_the_candidate_builder_turns_provider_answers_into_contract_candidates_and_compute_tier_applies_the_rules(parity):
    """The baseline has no hard evidence, so the builder is checked here on shaped answers (the fixture shapes of the provider clients)."""
    from app.scoring.tiers import compute_tier

    digest = "a" * 64
    raw = {
        "evil.example": {"vt": {"status": "ok", "malicious": 12}, "urlscan": {"status": "ok"}, "threatfox": {"status": "ok", "matched": True, "confidence_level": 74}},
        "known.example": {"vt": {"status": "ok", "malicious": 0}, "threatfox": {"status": "ok", "matched": True, "confidence_level": 90}},
        "wiki.example/path/x": {"vt": {"status": "ok", "malicious": 3}},
        digest: {"vt": {"status": "ok", "malicious": 0}, "threatfox": {"status": "ok", "matched": False}, "malwarebazaar": {"status": "ok", "matched": True}},
        "shared.example": {"uninformative": {"platform": "x", "kind": "y"}},
        "internal.example": {"internal_host_not_sent": True},
    }
    candidates = parity.candidates_from_enrichment(raw, {"known.example"})
    def pick(indicator_type, source):
        return [c for c in candidates if (c["indicator_type"], c["source"]) == (indicator_type, source)]

    assert [c["engine_count"] for c in pick("link_host", "virustotal")] == [12]
    assert sorted(c["confidence"] for c in pick("link_host", "threatfox")) == [74, 90]
    (url,) = pick("link_url", "virustotal")
    assert url["exact_url_match"] and url["path_optin_on"] and url["engine_count"] == 3
    (mb,) = pick("attachment_hash", "malwarebazaar")
    assert mb["is_known_sender_or_own_domain"] is False
    assert len(candidates) == 5  # nothing for the uninformative or internal hosts, and nothing for a not-matched or zero-engine answer
    # the host at 12 engines is T1 (H3), the ThreatFox answer at 74 is below its threshold; the hash is T1 (H1)
    result = compute_tier({"hard_evidence_candidates": candidates})
    assert result["tier"] == "T1" and sorted(e["rule"] for e in result["hard_evidence"]) == ["H1", "H3"]
    known_only = [c for c in candidates if c["is_known_sender_or_own_domain"]]
    assert len(known_only) == 1 and known_only[0]["source"] == "threatfox"
    assert compute_tier({"hard_evidence_candidates": known_only})["route_id"] == "R6"
