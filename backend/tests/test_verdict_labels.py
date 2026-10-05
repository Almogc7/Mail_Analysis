"""The raw v1 verdict value `benign` is a frozen internal literal, never wording (docs/DESIGN_V2.md 2.1, V1). Every sentence that names a verdict goes through
app.verdict_labels.verdict_label. These tests prove the label map, the places that use it, and that no user-visible string, reason, indicator text, log line or LLM prompt carries the raw value."""
import importlib.util
import sys
import typing
from pathlib import Path

from app.contracts.analysis import Verdict
from app.contracts.findings import Finding, ModuleResult
from app.llm.prompting import build_prompt
from app.scoring.config import ScoringConfig
from app.scoring.overrides import apply_overrides
from app.verdict_labels import VERDICT_LABELS, verdict_label
from tests import eval as ev

ROOT = Path(__file__).resolve().parents[2]


def _load_lint():
    if "check_wording" in sys.modules:
        return sys.modules["check_wording"]
    spec = importlib.util.spec_from_file_location("check_wording", ROOT / "scripts" / "check_wording.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_wording"] = module
    spec.loader.exec_module(module)
    return module


cw = _load_lint()


# ---- the map ------------------------------------------------------------------------------------------------------------------------

def test_the_map_covers_exactly_the_v1_verdict_values_and_only_benign_changes():
    assert set(typing.get_args(Verdict)) == set(VERDICT_LABELS)
    assert verdict_label("benign") == "No indicators found"
    for value in ("malicious", "suspicious", "inconclusive"):
        assert verdict_label(value) == value  # these already read as words, so their text stays exactly as it was


def test_an_unknown_value_is_returned_unchanged_and_no_label_contains_a_banned_word():
    assert verdict_label("something_else") == "something_else"
    assert all(cw.find_banned(label) == [] for label in VERDICT_LABELS.values())


# ---- where it is used ---------------------------------------------------------------------------------------------------------------

def _floor_module():
    finding = Finding(module="auth_check", severity="high", title="t", description="d", evidence={}, weight=1.0)
    return {"auth_check": ModuleResult(module="auth_check", status="ok", findings=[finding], raw_data={})}


def test_the_low_confidence_reason_names_the_verdict_by_its_label_not_its_raw_value():
    bucket, applied = apply_overrides("benign", {}, {}, 0.3, 15.0, ScoringConfig())
    reason = next(o.reason for o in applied if o.rule == "low_confidence_inconclusive")
    assert bucket == "inconclusive" and reason.endswith("-- evidence is too incomplete to trust a 'No indicators found' call.")
    assert "benign" not in reason.lower()
    _, applied = apply_overrides("suspicious", {}, {}, 0.3, 15.0, ScoringConfig())
    assert next(o.reason for o in applied if o.rule == "low_confidence_inconclusive").endswith("to trust a 'suspicious' call.")


def test_the_floor_protection_effect_keeps_its_exact_text_for_a_flagged_verdict():
    _, applied = apply_overrides("suspicious", _floor_module(), {}, 0.3, 40.0, ScoringConfig())
    assert next(o.effect for o in applied if o.rule == "floor_protects_verdict") == "verdict stays suspicious"


def test_the_llm_prompt_says_no_indicators_found_and_never_contains_the_raw_value():
    ev.apply_mode("configured")
    result = ev.analyze(ev.FIXTURES / "benign" / "synthetic" / "11_nearmiss_pineapple_weekly.eml", "clean")
    assert result.verdict == "benign"  # the frozen v1 field keeps its value
    prompt = build_prompt(result)
    assert "Verdict: No indicators found (score=" in prompt
    assert "benign" not in prompt.lower()


# ---- nothing user-visible carries the raw value -----------------------------------------------------------------------------------------

def test_no_f_string_in_the_backend_interpolates_a_raw_verdict_value():
    refs, _ = cw.static_backend(ROOT)
    assert [f"{r.file}:{r.line}" for r in cw.possible_hits(refs)] == []


def test_no_string_literal_log_line_or_cli_output_in_the_backend_contains_the_word_benign():
    refs, _ = cw.static_backend(ROOT)
    hits = [h for h in cw.static_hits(refs, cw.load_allowlist()) if h.word == "benign"]
    assert [f"{h.where}: {h.text[:60]}" for h in hits] == []


def test_no_produced_finding_reason_indicator_text_evidence_block_or_prompt_contains_the_word_benign(tmp_path):
    """The pipeline over the committed fixtures (an empty folder replaces the local tuning corpus), STRICT and CONFIGURED, clean and unknown enrichment."""
    hits = cw.runtime_hits(cw.load_allowlist(), corpus_dir=tmp_path)
    assert [(h.path, h.kind) for h in hits if h.word == "benign"] == []
