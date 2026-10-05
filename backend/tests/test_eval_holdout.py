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
    text = log.read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.startswith("- ")]
    assert len(lines) == 3  # one start line, then one aggregate result line per mode
    assert "FINAL HOLD-OUT run started" in lines[0] and "n=2" in lines[0] and "UTC" in lines[0] and "HEAD" in lines[0]
    assert "modes=strict,configured" in lines[0]
    assert "mode=strict" in lines[1] and "mode=configured" in lines[2] and all("flagged=" in l and "inconclusive=" in l for l in lines[1:])
    # only the hold-out set was evaluated, and nothing identifying leaks anywhere
    assert analyzed and all("holdout" in p.parts for p in analyzed)
    for secret in (*HOLDOUT_NAMES, "05_spf_only"):
        assert secret not in out and secret not in text
    assert "STRICT" in out and "CONFIGURED" in out and "aggregate only" in out and "both modes, as pre-registered" in out
    assert "NOT representative of mail that passed a gateway" in out
    assert "fixture" not in out.lower().split("aggregate")[0]  # no per-sample table


def test_the_final_run_refuses_to_report_only_one_mode(corpus, tmp_path, capsys):
    log = tmp_path / "HOLDOUT_LOG.md"
    assert _run("--final-holdout", "--mode", "configured", "--corpus-dir", str(corpus), "--holdout-log", str(log)) == 2
    assert "both modes" in capsys.readouterr().err and not log.exists()


def test_the_two_mode_report_is_pre_registered_in_the_tracked_log_and_in_the_generated_header():
    tracked = ev.HOLDOUT_LOG.read_text(encoding="utf-8")
    for text in (tracked, ev._HOLDOUT_LOG_HEADER):
        assert "PRE-REGISTRATION" in text and "BOTH modes" in text and "STRICT" in text and "CONFIGURED" in text
        assert "never reported in only the" in text
    assert "written 2026-10-03, before any hold-out evaluation" in tracked
    # The hold-out was evaluated exactly once (2026-10-03) and is spent. A second logged start would be a run "tuned after
    # viewing hold-out" and must be labelled as such in the log; this test fails until someone does that deliberately.
    starts = tracked.count("FINAL HOLD-OUT run started")
    assert starts == 1, f"{starts} hold-out runs are logged; the hold-out is spent after the first"
    assert tracked.index("PRE-REGISTRATION OF THE FINAL HOLD-OUT RUN") < tracked.index("FINAL HOLD-OUT run started")
    assert "0f20c4be5a80872262b3be46c96caea8d8b7499f" in tracked  # the exact commit under test was pre-registered


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


def test_report_shows_both_modes_side_by_side_with_counts_per_set(corpus, capsys):
    _run("--corpus-dir", str(corpus), "--no-gate")
    out = capsys.readouterr().out
    assert "modes=strict,configured" in out and "STRICT" in out and "CONFIGURED" in out
    assert "NOT representative of mail that passed a gateway" in out
    assert "MALICIOUS SETS -- each reported alone" in out
    for source in ("kvish", "synthetic", "tuning_corpus"):
        assert f"  {source}" in out
    # every set is shown once per mode; malicious sets with flagged / inconclusive / MISSED, benign sets with all four verdicts
    assert out.count("      STRICT") >= 4 and out.count("      CONFIGURED") >= 4
    assert "missed" in out and "benign(legit)" not in out  # the 'benign' column on malicious sets is called 'missed'
    for word in ("flagged", "inconclusive", "suspicious", "malicious", "benign"):
        assert word in out
    assert "triage-queue cost" in out and "inconclusive rate" in out
    # plain statement that benign is mostly unreachable when nothing is trusted
    assert "UNREACHABLE by design" in out
    strict_benign = next(l for l in out.splitlines() if l.strip().startswith("STRICT") and l.strip().split()[1] == "benign")
    n = len(list((ev.FIXTURES / "benign" / "synthetic").glob("*.eml")))  # every synthetic benign fixture is inconclusive in STRICT
    known_false_positives = 1  # fixture 22, documented in test_claim_family.py (strict xfail); nothing else may be flagged
    assert "benign   0" in strict_benign and f"suspicious {known_false_positives:>3}" in strict_benign
    assert f"inconclusive {n - known_false_positives:>3}" in strict_benign and f"(flagged {known_false_positives}/{n})" in strict_benign


def test_a_single_mode_can_be_requested_for_quick_runs(corpus, capsys):
    _run("--mode", "strict", "--corpus-dir", str(corpus), "--no-gate")
    out = capsys.readouterr().out
    assert "modes=strict" in out and "      STRICT" in out and "      CONFIGURED" not in out


def test_benign_sources_are_labelled_synthetic_and_the_real_slot_is_visibly_empty(corpus, capsys):
    _run("--corpus-dir", str(corpus), "--no-gate")
    out = capsys.readouterr().out
    assert "SYNTHETIC ONLY" in out and "NOT an accuracy claim" in out
    assert "0/0 (none -- no real benign mail)" in out
    assert out.count("REAL-WORLD PRECISION IS NOT ESTABLISHED") == 1
    assert "No combined precision/recall is printed" in out and "precision=" not in out and "TP=" not in out


def test_configured_patterns_come_from_untracked_config_and_are_validated(monkeypatch):
    monkeypatch.delenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", raising=False)
    assert ev.configured_patterns() == ev.DEFAULT_CONFIGURED_PATTERNS and "default" in ev.configured_source()
    # the env var holds JSON, so each regex backslash is doubled in the string (as in .env.example)
    monkeypatch.setenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", r'["^gw\\.example\\.org$"]')
    assert ev.configured_patterns() == [r"^gw\.example\.org$"] and "untracked config" in ev.configured_source()
    monkeypatch.setenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", '"not a list"')
    with pytest.raises(ValueError):
        ev.configured_patterns()


def test_apply_mode_sets_exactly_what_each_mode_means(monkeypatch):
    import app.config as cfg

    monkeypatch.delenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", raising=False)
    ev.apply_mode("strict")
    assert cfg.TRUSTED_RECEIVER_PATTERNS == []
    ev.apply_mode("configured")
    assert cfg.TRUSTED_RECEIVER_PATTERNS == ev.DEFAULT_CONFIGURED_PATTERNS
    ev.apply_mode("strict")
    assert cfg.TRUSTED_RECEIVER_PATTERNS == []  # modes do not leak into each other


def test_final_holdout_reports_wilson_intervals_for_every_rate_and_the_signal_counts(corpus, analyzed, tmp_path, capsys):
    log = tmp_path / "log.md"
    assert _run("--final-holdout", "--corpus-dir", str(corpus), "--holdout-log", str(log)) == 0
    out = capsys.readouterr().out
    for label in ("flagged", "inconclusive", "missed"):
        assert out.count(f"      {label}") == 2  # once per mode
    assert out.count("95% CI") == 6 and "STRICT" in out and "CONFIGURED" in out
    assert "structural signals (samples)" in out
    assert "signals present" in out and "no signals" in out


def test_wilson_interval_matches_known_values():
    lo, hi = ev.wilson(6, 75)
    assert round(100 * lo, 1) == 3.7 and round(100 * hi, 1) == 16.4
    lo, hi = ev.wilson(22, 75)
    assert round(100 * lo, 1) == 20.2 and round(100 * hi, 1) == 40.4
    assert ev.wilson(0, 75)[0] == 0.0 and round(100 * ev.wilson(0, 75)[1], 1) == 4.9
    assert ev.wilson(75, 75)[1] == 1.0 and ev.wilson(0, 0) is None
    assert ev.fmt_rate(0, 0) == "n/a" and ev.fmt_rate(6, 75).startswith("6/75 = 8.0% [95% CI 3.7-16.4%]")


def test_the_eval_does_not_flood_stderr_with_per_message_enrichment_warnings_and_restores_the_level(corpus, capsys):
    import logging

    from app.logging_config import configure_logging

    configure_logging()
    before = logging.getLogger("app").level
    _run("--corpus-dir", str(corpus), "--no-gate", "--enrichment", "unknown")
    captured = capsys.readouterr()
    assert "UNKNOWN (no answer), which is not the same as 'nothing found'" not in captured.err and "enrichment:" not in captured.err  # the tables are readable
    assert "STRICT" in captured.out  # and the report itself is unchanged
    assert logging.getLogger("app").level == before
