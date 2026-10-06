"""The Phase B pre-registration's predicted tiers (scripts/predict_tiers.py, docs/PHASE_B_PREREGISTRATION.md): the committed file, the document's hashes and the written prediction must agree."""
import importlib.util
import json
from pathlib import Path

import pytest

from tests import eval as ev
from tests import regression_baseline as rb

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "PHASE_B_PREREGISTRATION.md"
PREDICTED = ROOT / "backend" / "tests" / "fixtures" / "predicted_tiers.json"


@pytest.fixture(scope="module")
def predictor():
    spec = importlib.util.spec_from_file_location("predict_tiers", ROOT / "scripts" / "predict_tiers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def committed():
    return json.loads(PREDICTED.read_text(encoding="utf-8"))["rows"]


def test_the_file_has_all_856_baseline_rows_and_the_same_v1_verdicts(committed):
    baseline = rb.load()
    assert set(committed) == set(baseline)
    assert [k for k in baseline if committed[k]["v1"] != baseline[k]["verdict"]] == []


def test_the_written_prediction_holds_for_every_row_and_no_row_changes_tier(predictor, committed):
    assert predictor.differences(committed) == []
    assert {r["tier"] for r in committed.values()} == {"T2", "T3", "T4"}  # no hard evidence in the baseline, so no T1
    assert {r["route"] for r in committed.values() if r["tier"] == "T2"} == {"R1", "R2"}  # R3, R3B, R4, R5 and R6 are exercised only by the specification cases


def test_the_as_is_clean_rows_recompute_to_the_committed_prediction(predictor, committed):
    try:
        fresh = predictor.compute(variants=rb.FAST_VARIANTS)
    finally:
        ev.apply_mode("configured")
    assert len(fresh) == 214
    assert [k for k, r in fresh.items() if committed[k] != r] == []


def test_the_documents_hashes_are_those_of_the_fixed_files(predictor):
    text = DOC.read_text(encoding="utf-8")
    for rel in ("backend/tests/fixtures/finding_codes_frozen.json", "backend/tests/fixtures/reason_classes_frozen.json",
                "backend/tests/fixtures/predicted_tiers.json", "scripts/predict_tiers.py"):
        digest = predictor.sha256_lf(ROOT / rel)
        assert f"`{digest}`" in text, f"{rel}: the sha256 in docs/PHASE_B_PREREGISTRATION.md is not the file's (a rule input changed: log it in section 6)"


def test_the_document_states_the_frozen_rules_it_must_and_the_deviation_cap():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("R3B", "medium or higher", "evidence_conflict", "Iteration count: 0 of 3", "Checks completed: N of M, K not checked",
                   "Queue priority (ordering aid, not a probability)", "`confidence_level >= 75`", "`malicious >= 10`", "not statistical independence"):
        assert needle in text, needle
