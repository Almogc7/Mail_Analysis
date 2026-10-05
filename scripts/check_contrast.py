#!/usr/bin/env python3
"""Contrast guard for the colour tokens in docs/UI_DESIGN.md (WCAG 2.x relative luminance).

Reads the tokens from frontend/src/theme.css (dark in :root, light inside the opt-in rule ':root[data-theme="light"] {')
and asserts, for both themes:
  - body, secondary and muted text >= 4.5:1 on the panel, root, raised and muted surfaces
  - every severity and verdict-tier colour >= 4.5:1 on the panel and on its own tint token
  - the text of a filled badge or band (--bg-root on the critical and malicious colours) >= 4.5:1
  - the focus ring and the control border >= 3:1 on the panel and the root surface (the surfaces they sit on)

It fails with a readable message listing every failing pair, and also when theme.css lacks a required token. There is no
built-in fallback table: a token that is not in theme.css is an error.

Format expected in theme.css: one "--name: #rrggbb;" declaration per token; CSS comments are ignored; the light block is
written exactly ':root[data-theme="light"] {'. A missing light block fails the check (every light token is then reported missing).

Usage:  check_contrast.py              check frontend/src/theme.css
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THEME_CSS = ROOT / "frontend" / "src" / "theme.css"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
TIERS = ["malicious", "suspicious", "inconclusive", "none-found"]
SURFACES = ["bg-panel", "bg-root", "bg-panel-raised", "bg-muted"]
TEXTS = ["text-primary", "text-secondary", "text-muted"]

REQUIRED = (
    SURFACES + TEXTS + ["border-control", "focus"]
    + [f"sev-{s}" for s in SEVERITIES] + [f"sev-{s}-tint" for s in SEVERITIES]
    + [f"verdict-{t}" for t in TIERS] + [f"verdict-{t}-tint" for t in TIERS]
)


def _channel(c: int) -> float:
    s = c / 255
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def pairs() -> list[tuple[str, str, float]]:
    """(foreground token, background token, minimum ratio) for every assertion."""
    out: list[tuple[str, str, float]] = []
    for t in TEXTS:
        out += [(t, s, 4.5) for s in SURFACES]
    for name in [f"sev-{s}" for s in SEVERITIES] + [f"verdict-{t}" for t in TIERS]:
        out += [(name, "bg-panel", 4.5), (name, f"{name}-tint", 4.5)]
    # Filled critical badge and filled malicious band: --bg-root text on the colour.
    out += [("bg-root", "sev-critical", 4.5), ("bg-root", "verdict-malicious", 4.5)]
    out += [(tok, s, 3.0) for tok in ("focus", "border-control") for s in ("bg-panel", "bg-root")]
    return out


def check(themes: dict[str, dict[str, str]]) -> tuple[int, list[str]]:
    """(number of pairs checked, readable failure lines)."""
    failures: list[str] = []
    checked = 0
    for theme, tokens in themes.items():
        for fg, bg, need in pairs():
            missing = [n for n in (fg, bg) if n not in tokens]
            if missing:
                failures.append(f"FAIL [{theme}] missing token(s): {', '.join('--' + m for m in missing)}")
                continue
            checked += 1
            ratio = contrast(tokens[fg], tokens[bg])
            if ratio < need:
                failures.append(
                    f"FAIL [{theme}] --{fg} ({tokens[fg]}) on --{bg} ({tokens[bg]}): {ratio:.2f}:1, need {need:g}:1"
                )
    return checked, failures


_DECL = re.compile(r"--([\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;")
_COMMENT = re.compile(r"/[*].*?[*]/", re.S)
_LIGHT_OPEN = ':root[data-theme="light"] {'


def _light_block(text: str) -> tuple[int, int] | None:
    """(start, end) of the light opt-in rule, matched by braces. None when absent."""
    start = text.find(_LIGHT_OPEN)
    if start < 0:
        return None
    depth = 0
    for i in range(start + len(_LIGHT_OPEN) - 1, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return start, i + 1
    return start, len(text)


def parse_theme_css(text: str) -> dict[str, dict[str, str]]:
    """Dark tokens from outside the light block, light tokens from inside it. Comments are ignored."""
    text = _COMMENT.sub("", text)
    block = _light_block(text)
    if block is None:
        return {"dark": dict(_DECL.findall(text)), "light": {}}
    start, end = block
    return {"dark": dict(_DECL.findall(text[:start] + text[end:])), "light": dict(_DECL.findall(text[start:end]))}


def missing_tokens(themes: dict[str, dict[str, str]]) -> list[str]:
    return [f"[{theme}] --{name}" for theme in ("dark", "light") for name in REQUIRED if name not in themes.get(theme, {})]


def load_tokens(css_path: Path = THEME_CSS) -> dict[str, dict[str, str]]:
    return parse_theme_css(css_path.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    name = str(THEME_CSS.relative_to(ROOT)).replace("\\", "/")
    if not THEME_CSS.is_file():
        print(f"check_contrast: FAILED ({name} not found)", file=sys.stderr)
        return 1
    themes = load_tokens(THEME_CSS)
    missing = missing_tokens(themes)
    if missing:
        print(f"check_contrast: FAILED ({name} is missing {len(missing)} required token(s))", file=sys.stderr)
        for m in missing:
            print("  - missing " + m, file=sys.stderr)
        return 1
    checked, failures = check(themes)
    if failures:
        print(f"check_contrast: FAILED ({len(failures)} failing, source: {name})", file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        return 1
    print(f"check_contrast: OK ({checked} pairs, source: {name})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
