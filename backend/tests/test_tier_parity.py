"""Parity of the class-based floors with the frozen predictor (clarification C1 in docs/PHASE_B_PREREGISTRATION.md).

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


def test_a_class_based_recompute_equals_the_predictor_on_the_as_is_clean_rows(parity):
    try:
        outcome = parity.check(rb.FAST_VARIANTS)
    finally:
        ev.apply_mode("configured")
    assert outcome["rows"] == 214
    assert outcome["class_based_differs_from_module_based"] == []


def test_a_class_based_recompute_equals_the_predictor_on_all_856_rows():
    done = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=ROOT, timeout=900)
    assert done.returncode == 0, done.stdout[-2000:]
    assert "checked 856 rows; class-based differs from module-based: 0" in done.stdout
