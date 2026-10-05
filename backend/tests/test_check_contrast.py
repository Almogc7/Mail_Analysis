"""Tests for scripts/check_contrast.py: the guard must pass on the documented tokens and must detect and name a failing pair."""
import copy
import importlib.util
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
spec = importlib.util.spec_from_file_location("check_contrast", SCRIPTS / "check_contrast.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


def test_ratio_matches_known_values():
    assert cc.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert cc.contrast("#ffffff", "#ffffff") == pytest.approx(1.0)
    assert cc.contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)  # the classic just-below-AA grey


def test_documented_tokens_pass():
    checked, failures = cc.check(cc.TOKENS)
    assert failures == []
    assert checked == 72  # 36 pairs per theme: 12 text, 18 colour+tint, 2 filled, 4 ring/border


def test_table_has_every_required_token_in_both_themes():
    for theme in ("dark", "light"):
        assert [n for n in cc.REQUIRED if n not in cc.TOKENS[theme]] == []


def test_a_failing_text_pair_is_detected_and_named():
    tokens = copy.deepcopy(cc.TOKENS)
    tokens["dark"]["text-muted"] = "#6b7684"  # the old muted grey, about 3.9:1 on the panel
    _, failures = cc.check(tokens)
    assert any("[dark] --text-muted (#6b7684) on --bg-panel (#11151c)" in f and "need 4.5:1" in f for f in failures)
    assert all(f.startswith("FAIL [dark]") for f in failures)  # the light theme is untouched


def test_a_failing_severity_on_its_tint_is_detected():
    tokens = copy.deepcopy(cc.TOKENS)
    tokens["light"]["sev-high-tint"] = "#a8400f"  # tint equal to the text colour: ratio 1:1
    _, failures = cc.check(tokens)
    assert any("[light] --sev-high (#a8400f) on --sev-high-tint (#a8400f): 1.00:1" in f for f in failures)


def test_a_weak_focus_ring_or_control_border_fails_at_3_to_1():
    tokens = copy.deepcopy(cc.TOKENS)
    tokens["light"]["focus"] = "#9fb3c8"
    tokens["dark"]["border-control"] = "#2b3542"  # the decorative border, about 1.5:1
    _, failures = cc.check(tokens)
    assert any("[light] --focus" in f and "need 3:1" in f for f in failures)
    assert any("[dark] --border-control" in f and "need 3:1" in f for f in failures)


def test_filled_badge_text_is_checked():
    tokens = copy.deepcopy(cc.TOKENS)
    tokens["dark"]["bg-root"] = "#ff6b78"  # text colour equal to the critical fill
    _, failures = cc.check(tokens)
    assert any("--bg-root (#ff6b78) on --sev-critical" in f for f in failures)


def test_a_missing_token_is_reported_not_skipped():
    tokens = copy.deepcopy(cc.TOKENS)
    del tokens["dark"]["verdict-inconclusive-tint"]
    _, failures = cc.check(tokens)
    assert any("missing token" in f and "--verdict-inconclusive-tint" in f for f in failures)


def _css(tokens):
    def block(t):
        return "".join(f"  --{k}: {v};\n" for k, v in t.items())
    return f":root {{\n{block(tokens['dark'])}}}\n@media (prefers-color-scheme: light) {{\n  :root {{\n{block(tokens['light'])}  }}\n}}\n"


def test_theme_css_with_all_tokens_is_parsed_and_used(tmp_path, monkeypatch):
    css = tmp_path / "theme.css"
    css.write_text(_css(cc.TOKENS), encoding="utf-8")
    assert cc.parse_theme_css(css.read_text(encoding="utf-8")) == cc.TOKENS
    source, themes = cc.load_tokens(css)
    assert "theme.css" in source and themes == cc.TOKENS


def test_theme_css_with_a_bad_token_fails_the_check(tmp_path):
    broken = copy.deepcopy(cc.TOKENS)
    broken["light"]["text-secondary"] = "#aaaaaa"
    css = tmp_path / "theme.css"
    css.write_text(_css(broken), encoding="utf-8")
    _, themes = cc.load_tokens(css)
    _, failures = cc.check(themes)
    assert any("[light] --text-secondary (#aaaaaa)" in f for f in failures)


def test_incomplete_theme_css_falls_back_to_the_table(tmp_path):
    css = tmp_path / "theme.css"
    css.write_text(":root { --bg-root: #0b0e13; }\n", encoding="utf-8")
    assert cc.parse_theme_css(css.read_text(encoding="utf-8")) is None
    source, themes = cc.load_tokens(css)
    assert "TOKENS table" in source and themes is cc.TOKENS


def test_main_exit_codes(capsys, monkeypatch):
    assert cc.main(["--table"]) == 0
    assert "check_contrast: OK" in capsys.readouterr().out
    bad = copy.deepcopy(cc.TOKENS)
    bad["dark"]["text-secondary"] = "#555555"
    monkeypatch.setattr(cc, "TOKENS", bad)
    assert cc.main(["--table"]) == 1
    err = capsys.readouterr().err
    assert "FAILED" in err and "--text-secondary (#555555)" in err
