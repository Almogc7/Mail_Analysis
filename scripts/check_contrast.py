#!/usr/bin/env python3
"""Contrast guard for the colour tokens in docs/UI_DESIGN.md (WCAG 2.x relative luminance).

Asserts, for both the dark and the light theme:
  - body, secondary and muted text >= 4.5:1 on the panel, root, raised and muted surfaces
  - every severity and verdict-tier colour >= 4.5:1 on the panel and on its own tint token
  - the text of a filled badge or band (--bg-root on the critical and malicious colours) >= 4.5:1
  - the focus ring and the control border >= 3:1 on the panel and the root surface (the surfaces they sit on)

On failure it prints each failing pair with both colours and the ratio, and exits 1.

Token source: frontend/src/theme.css when it already defines every token below (dark in :root, light inside
@media (prefers-color-scheme: light)); otherwise the TOKENS table below.
TODO: the new tokens are not implemented in theme.css yet. When they are, this script switches to theme.css by itself;
delete the TOKENS table at that point.

Usage:  check_contrast.py              check the tokens (theme.css if complete, else the table)
        check_contrast.py --table      force the table
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

# Same values as docs/UI_DESIGN.md. Tints are the 15% mix of the colour over the panel, written out as hex.
TOKENS: dict[str, dict[str, str]] = {
    "dark": {
        "bg-root": "#0b0e13", "bg-panel": "#11151c", "bg-panel-raised": "#171c25", "bg-muted": "#1a1f29",
        "text-primary": "#e6edf3", "text-secondary": "#a3adb9", "text-muted": "#8b96a3",
        "border-control": "#6b7684", "focus": "#4fe1ff",
        "sev-critical": "#ff6b78", "sev-high": "#ff8f60", "sev-medium": "#ffb347", "sev-low": "#5cc8f0", "sev-info": "#a3adb9",
        "sev-critical-tint": "#35222a", "sev-high-tint": "#352726", "sev-medium-tint": "#352d22",
        "sev-low-tint": "#1c303c", "sev-info-tint": "#272c34",
        "verdict-malicious": "#ff6b78", "verdict-suspicious": "#ffb347", "verdict-inconclusive": "#7fb0ff",
        "verdict-none-found": "#a3adb9",
        "verdict-malicious-tint": "#35222a", "verdict-suspicious-tint": "#352d22", "verdict-inconclusive-tint": "#222c3e",
        "verdict-none-found-tint": "#272c34",
    },
    "light": {
        "bg-root": "#f6f8fa", "bg-panel": "#ffffff", "bg-panel-raised": "#f0f3f6", "bg-muted": "#e8ecf0",
        "text-primary": "#1f2328", "text-secondary": "#4a5560", "text-muted": "#59636e",
        "border-control": "#848d97", "focus": "#0a5c86",
        "sev-critical": "#b3202e", "sev-high": "#a8400f", "sev-medium": "#7a4f00", "sev-low": "#0a5c86", "sev-info": "#4a5560",
        "sev-critical-tint": "#f4dee0", "sev-high-tint": "#f2e2db", "sev-medium-tint": "#ebe5d9",
        "sev-low-tint": "#dae7ed", "sev-info-tint": "#e4e6e7",
        "verdict-malicious": "#b3202e", "verdict-suspicious": "#7a4f00", "verdict-inconclusive": "#1d4fa8",
        "verdict-none-found": "#4a5560",
        "verdict-malicious-tint": "#f4dee0", "verdict-suspicious-tint": "#ebe5d9", "verdict-inconclusive-tint": "#dde5f2",
        "verdict-none-found-tint": "#e4e6e7",
    },
}


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
_LIGHT_BLOCK = re.compile(r"@media\s*\(\s*prefers-color-scheme\s*:\s*light\s*\)\s*\{(.*)\}", re.S)


def parse_theme_css(text: str) -> dict[str, dict[str, str]] | None:
    """Dark tokens from the top-level rules, light tokens from the prefers-color-scheme: light block.
    Returns None unless both themes define every required token."""
    m = _LIGHT_BLOCK.search(text)
    light = dict(_DECL.findall(m.group(1))) if m else {}
    dark = dict(_DECL.findall(text[:m.start()] + text[m.end():] if m else text))
    if all(name in theme for theme in (dark, light) for name in REQUIRED):
        return {"dark": dark, "light": light}
    return None


def load_tokens(css_path: Path = THEME_CSS, force_table: bool = False) -> tuple[str, dict[str, dict[str, str]]]:
    if not force_table and css_path.is_file():
        parsed = parse_theme_css(css_path.read_text(encoding="utf-8"))
        if parsed:
            return str(css_path.relative_to(ROOT)) if css_path.is_relative_to(ROOT) else str(css_path), parsed
    return "TOKENS table in scripts/check_contrast.py (theme.css does not define the new tokens yet)", TOKENS


def main(argv: list[str]) -> int:
    source, themes = load_tokens(force_table="--table" in argv)
    checked, failures = check(themes)
    if failures:
        print(f"check_contrast: FAILED ({len(failures)} failing, source: {source})", file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        return 1
    print(f"check_contrast: OK ({checked} pairs, source: {source})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
