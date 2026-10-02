"""Hold-out protection and reporting format of tests/eval.py."""
import shutil
from pathlib import Path

import pytest

import tests.eval as ev

SOURCE_FIXTURE = ev.FIXTURES / "benign" / "synthetic" / "05_spf_only_small_business.eml"
HOLDOUT_NAMES = ("deadbeefdeadbeef", "cafebabecafebabe")
TUNING_NAME = "0123456789abcdef"


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "_local_corpus"
    (root / "tuning").mkdir(parents=True)
    (root / "holdout").mkdir()
    shutil.copy(SOURCE_FIXTURE, root / "tuning" / f"{TUNING_NAME}.eml")
    for name in HOLDOUT_NAMES:
        shutil.copy(SOURCE_FIXTURE, root / "holdout" / f"{name}.eml")
    return root


@pytest.fixture
def analyzed(monkeypatch):
    """Records every path the eval hands to the pipeline."""
    seen: list[Path] = []
    real = ev.analyze

    def spy(path, mode):
        seen.append(Path(path))
        return real(path, mode)

    monkeypatch.setattr(ev, "analyze", spy)
    return seen


def _run(*argv):
    return ev.main(list(argv))


def test_normal_run_never_reads_the_holdout_directory(corpus, analyzed, capsys):
    _run("--corpus-dir", str(corpus), "--no-gate")
    out = capsys.readouterr().out
    assert not [p for p in analyzed if "holdout" in p.parts]
    assert any(p.parent.name == "tuning" for p in analyzed)  # the tuning split IS evaluated
    assert "hold-out present (2 files) -- not read" in out
    assert not any(n in out for n in HOLDOUT_NAMES)


def test_the_old_environment_variable_no_longer_unlocks_the_holdout(corpus, analyzed, monkeypatch, capsys):
    monkeypatch.setenv("EVAL_UNBLIND_HOLDOUT", "1")
    _run("--corpus-dir", str(corpus), "--no-gate")
    assert not [p for p in analyzed if "holdout" in p.parts]


def test_final_holdout_logs_before_and_after_and_prints_aggregates_only(corpus, analyzed, tmp_path, capsys):
    log = tmp_path / "HOLDOUT_LOG.md"
    assert _run("--final-holdout", "--corpus-dir", str(corpus), "--holdout-log", str(log)) == 0
    out = capsys.readouterr().out
    lines = [l for l in log.read_text(encoding="utf-8").splitlines() if l.startswith("- ")]
    assert len(lines) == 2
    assert "FINAL HOLD-OUT run started" in lines[0] and "n=2" in lines[0] and "UTC" in lines[0] and "HEAD" in lines[0]
    assert "result" in lines[1] and "flagged(strict)=" in lines[1]
    # only the hold-out set was evaluated, and nothing identifying leaks anywhere
    assert analyzed and all("holdout" in p.parts for p in analyzed)
    for secret in (*HOLDOUT_NAMES, "05_spf_only"):
        assert secret not in out and secret not in log.read_text(encoding="utf-8")
    assert "recall strict" in out and "aggregate only" in out
    assert "fixture" not in out.lower().split("aggregate")[0]  # no per-sample table


def test_the_start_line_is_written_even_if_evaluation_crashes(corpus, tmp_path, monkeypatch):
    log = tmp_path / "HOLDOUT_LOG.md"

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(ev, "_row_for", boom)
    with pytest.raises(RuntimeError):
        _run("--final-holdout", "--corpus-dir", str(corpus), "--holdout-log", str(log))
    lines = [l for l in log.read_text(encoding="utf-8").splitlines() if l.startswith("- ")]
    assert len(lines) == 1 and "started" in lines[0]


def test_each_final_run_appends(corpus, tmp_path):
    log = tmp_path / "HOLDOUT_LOG.md"
    _run("--final-holdout", "--corpus-dir", str(corpus), "--holdout-log", str(log))
    _run("--final-holdout", "--corpus-dir", str(corpus), "--holdout-log", str(log))
    text = log.read_text(encoding="utf-8")
    assert text.count("FINAL HOLD-OUT run started") == 2 and text.startswith("# Hold-out evaluation log")


def test_final_holdout_refuses_json_and_logs_nothing(corpus, tmp_path, capsys):
    log = tmp_path / "HOLDOUT_LOG.md"
    assert _run("--final-holdout", "--json", str(tmp_path / "o.json"), "--corpus-dir", str(corpus), "--holdout-log", str(log)) == 2
    assert not log.exists() and not (tmp_path / "o.json").exists()


def test_final_holdout_without_a_holdout_set_is_an_error_and_logs_nothing(tmp_path):
    log = tmp_path / "HOLDOUT_LOG.md"
    assert _run("--final-holdout", "--corpus-dir", str(tmp_path / "empty"), "--holdout-log", str(log)) == 1
    assert not log.exists()


def test_report_lists_recall_per_set_and_benign_per_source_with_no_pooled_precision(corpus, capsys):
    _run("--corpus-dir", str(corpus), "--no-gate")
    out = capsys.readouterr().out
    assert "Recall -- each malicious set reported on its own" in out
    for source in ("kvish", "synthetic", "tuning_corpus"):
        assert f"  {source}" in out
    assert "synthetic      0/15 flagged" in out and "NOT an accuracy claim" in out
    assert "_from_user     0/0 (none -- no real benign mail)" in out
    assert out.count("REAL-WORLD PRECISION IS NOT ESTABLISHED") == 1
    assert "SYNTHETIC ONLY" in out and "real-world precision is not established" in out
    assert "No combined precision/recall is printed" in out
    assert "precision=" not in out and "TP=" not in out
