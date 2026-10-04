"""The committed per-sample baseline: it holds the last accepted numbers, and the pipeline still reproduces it (phases A and D of
docs/DESIGN_V2.md must not move any verdict)."""
import pytest

from tests import eval as ev
from tests import regression_baseline as rb

FLAGGED = {"suspicious", "malicious"}
CORPUS_PRESENT = (ev.FIXTURES / "_local_corpus" / "tuning").exists()


@pytest.fixture(scope="module")
def recorded():
    return rb.load()


def _rows(recorded, variant, mode, source):
    prefix = f"{variant}/{mode}/{source}/"
    return [v for k, v in recorded.items() if k.startswith(prefix)]


def test_the_baseline_has_every_variant_mode_and_sample(recorded):
    assert len(recorded) == 856  # 4 variants x 2 modes x 107 samples
    for variant in ("clean/asis", "unknown/asis", "clean/ablated", "unknown/ablated"):
        for mode in ("strict", "configured"):
            assert len(_rows(recorded, variant, mode, "tuning_corpus")) == 75
            assert len(_rows(recorded, variant, mode, "synthetic")) == 31  # 5 malicious spoofs + 26 benign share the folder name
            assert len(_rows(recorded, variant, mode, "kvish")) == 1


@pytest.mark.parametrize("variant", ["clean/asis", "unknown/asis", "clean/ablated", "unknown/ablated"])
def test_the_last_accepted_numbers_are_the_ones_recorded(recorded, variant):
    strict = sum(r["verdict"] in FLAGGED for r in _rows(recorded, variant, "strict", "tuning_corpus"))
    configured = sum(r["verdict"] in FLAGGED for r in _rows(recorded, variant, "configured", "tuning_corpus"))
    assert (strict, configured) == (6, 22)  # tuning flagged 6/75 STRICT and 22/75 CONFIGURED
    for mode in ("strict", "configured"):
        assert [r["verdict"] for r in _rows(recorded, variant, mode, "kvish")] == ["suspicious"]  # Kvish as-is and ablated


def test_the_26_synthetic_benign_fixtures_are_all_recorded_below_suspicious_except_the_documented_one(recorded):
    names = sorted({k.rsplit("/", 1)[1] for k in recorded if k.startswith("clean/asis/strict/synthetic/")})
    benign_dir = {p.name for p in (ev.FIXTURES / "benign" / "synthetic").glob("*.eml")}
    assert len(benign_dir) == 26 and benign_dir <= set(names)
    flagged = {n for n in benign_dir if recorded[f"clean/asis/strict/synthetic/{n}"]["verdict"] in FLAGGED}
    assert flagged == {"22_newsletter_sender_differs_from_brand_link_domain_dkim.eml"}  # the documented false positive (D7)


def test_no_row_is_a_hold_out_sample(recorded):
    assert not any("holdout" in k.lower() for k in recorded)


def test_the_pipeline_still_reproduces_the_fixture_rows(tmp_path):
    """Recompute the fixtures (no corpus) for the clean, seeds-on variant in both modes and compare with the committed rows."""
    current = rb.compute(rb.FAST_VARIANTS, corpus_dir=tmp_path)
    assert len(current) == 64 and rb.differences(current, rb.load()) == []


@pytest.mark.skipif(not CORPUS_PRESENT, reason="the local tuning corpus is not on this machine (it is git-ignored)")
def test_the_pipeline_still_reproduces_the_tuning_rows():
    current = rb.compute(rb.FAST_VARIANTS)
    assert len(current) == 214 and rb.differences(current, rb.load()) == []
