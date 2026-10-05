"""Tests for scripts/check_contrast.py: it reads frontend/src/theme.css, passes on the real tokens, and detects and names a failing pair
or a missing token. There is no built-in fallback table."""
import copy
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_contrast.py"
spec = importlib.util.spec_from_file_location("check_contrast", SCRIPT)
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

REAL = cc.load_tokens()  # parsed from the real frontend/src/theme.css


def _css(tokens, comment=""):
    def block(t):
        return "".join(f"  --{k}: {v};\n" for k, v in t.items())
    return f"{comment}:root {{\n{block(tokens['dark'])}}}\n@media (prefers-color-scheme: light) {{\n  :root {{\n{block(tokens['light'])}  }}\n}}\n"


def test_ratio_matches_known_values():
    assert cc.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert cc.contrast("#ffffff", "#ffffff") == pytest.approx(1.0)
    assert cc.contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)  # the classic just-below-AA grey


def test_the_real_theme_css_passes():
    assert cc.THEME_CSS == Path(__file__).resolve().parents[2] / "frontend" / "src" / "theme.css"
    assert cc.missing_tokens(REAL) == []
    checked, failures = cc.check(REAL)
    assert failures == []
    assert checked == 72  # 36 pairs per theme: 12 text, 18 colour+tint, 2 filled, 4 ring/border


def test_main_passes_on_the_real_theme_css_and_names_it(capsys):
    assert cc.main([]) == 0
    out = capsys.readouterr().out
    assert "check_contrast: OK (72 pairs, source: frontend/src/theme.css)" in out


def test_there_is_no_fallback_table():
    assert not hasattr(cc, "TOKENS")
    source = SCRIPT.read_text(encoding="utf-8")
    assert "TOKENS" not in source and "TODO" not in source


def test_the_corrected_light_control_border_is_in_theme_css():
    assert REAL["light"]["border-control"] == "#848d97"


def test_a_failing_text_pair_is_detected_and_named():
    tokens = copy.deepcopy(REAL)
    tokens["dark"]["text-muted"] = "#6b7684"  # the old muted grey, about 3.9:1 on the panel
    _, failures = cc.check(tokens)
    assert any("[dark] --text-muted (#6b7684) on --bg-panel (#11151c)" in f and "need 4.5:1" in f for f in failures)
    assert all(f.startswith("FAIL [dark]") for f in failures)  # the light theme is untouched


def test_a_failing_severity_on_its_tint_is_detected():
    tokens = copy.deepcopy(REAL)
    tokens["light"]["sev-high-tint"] = "#a8400f"  # tint equal to the text colour: ratio 1:1
    _, failures = cc.check(tokens)
    assert any("[light] --sev-high (#a8400f) on --sev-high-tint (#a8400f): 1.00:1" in f for f in failures)


def test_a_weak_focus_ring_or_control_border_fails_at_3_to_1():
    tokens = copy.deepcopy(REAL)
    tokens["light"]["focus"] = "#9fb3c8"
    tokens["dark"]["border-control"] = "#2b3542"  # the decorative border, about 1.5:1
    _, failures = cc.check(tokens)
    assert any("[light] --focus" in f and "need 3:1" in f for f in failures)
    assert any("[dark] --border-control" in f and "need 3:1" in f for f in failures)


def test_filled_badge_text_is_checked():
    tokens = copy.deepcopy(REAL)
    tokens["dark"]["bg-root"] = "#ff6b78"  # text colour equal to the critical fill
    _, failures = cc.check(tokens)
    assert any("--bg-root (#ff6b78) on --sev-critical" in f for f in failures)


def test_a_missing_token_is_reported_for_the_right_theme():
    tokens = copy.deepcopy(REAL)
    del tokens["dark"]["verdict-inconclusive-tint"]
    del tokens["light"]["focus"]
    assert cc.missing_tokens(tokens) == ["[dark] --verdict-inconclusive-tint", "[light] --focus"]
    _, failures = cc.check(tokens)
    assert any("missing token" in f and "--verdict-inconclusive-tint" in f for f in failures)


def test_parser_round_trips_the_real_tokens(tmp_path):
    parsed = cc.parse_theme_css(_css(REAL))
    assert parsed["dark"] == REAL["dark"] and parsed["light"] == REAL["light"]


def test_comments_are_ignored_even_when_they_quote_the_light_block_opening():
    comment = '/* the light block is written exactly "@media (prefers-color-scheme: light) {" and --fake: #123456; */\n'
    parsed = cc.parse_theme_css(_css(REAL, comment))
    assert parsed["dark"] == REAL["dark"] and "fake" not in parsed["dark"] and "fake" not in parsed["light"]


def test_a_rule_after_the_light_block_does_not_leak_into_it():
    css = _css(REAL) + "@media print { :root { --extra: #000000; } }\n"
    parsed = cc.parse_theme_css(css)
    assert "extra" in parsed["dark"] and "extra" not in parsed["light"]


def test_non_hex_values_are_not_tokens():
    parsed = cc.parse_theme_css(":root { --a: var(--b); --c: #fff; --d: #0b0e13; }")
    assert parsed["dark"] == {"d": "#0b0e13"} and parsed["light"] == {}


def _main_with_css(monkeypatch, tmp_path, text):
    css = tmp_path / "frontend" / "src" / "theme.css"
    css.parent.mkdir(parents=True)
    css.write_text(text, encoding="utf-8")
    monkeypatch.setattr(cc, "ROOT", tmp_path)
    monkeypatch.setattr(cc, "THEME_CSS", css)
    return cc.main([])


def test_main_fails_clearly_when_theme_css_lacks_tokens_and_does_not_fall_back(monkeypatch, tmp_path, capsys):
    assert _main_with_css(monkeypatch, tmp_path, ":root { --bg-root: #0b0e13; }\n") == 1
    err = capsys.readouterr().err
    assert "FAILED" in err and "is missing" in err
    assert "missing [dark] --text-primary" in err and "missing [light] --bg-root" in err
    assert "OK" not in err


def test_main_fails_when_theme_css_is_absent(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cc, "ROOT", tmp_path)
    monkeypatch.setattr(cc, "THEME_CSS", tmp_path / "frontend" / "src" / "theme.css")
    assert cc.main([]) == 1
    assert "not found" in capsys.readouterr().err


def test_main_lists_the_failing_pair_when_a_token_is_too_weak(monkeypatch, tmp_path, capsys):
    bad = copy.deepcopy(REAL)
    bad["dark"]["text-secondary"] = "#555555"
    assert _main_with_css(monkeypatch, tmp_path, _css(bad)) == 1
    err = capsys.readouterr().err
    assert "FAILED" in err and "[dark] --text-secondary (#555555) on --bg-panel (#11151c)" in err
