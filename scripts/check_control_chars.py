#!/usr/bin/env python3
"""Pre-commit guard: reject stray control characters in text files.

Rejects bytes 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F and 0x7F -- everything below 0x20 except
TAB, LF and CR -- plus 0x7F. This catches a class of editing accident where an escape
sequence such as backslash-b is turned into a literal backspace inside a regex, which
silently changes what the pattern matches and is invisible in a diff.

Only the location (file:line:col) and the byte value are printed, never file content.

Usage:  check_control_chars.py            scan the working tree (tracked + untracked, not ignored)
        check_control_chars.py --staged   scan staged content (used by .githooks/pre-commit)
        check_control_chars.py PATH...    scan the given files

Binary files are skipped: a known binary suffix, or a NUL byte in the first 8 KB.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".pdf", ".zip",
    ".gz", ".msg", ".pyc", ".db", ".sqlite",
}
_ALLOWED = {0x09, 0x0A, 0x0D}
_BAD = frozenset(b for b in range(0x20) if b not in _ALLOWED) | {0x7F}


def is_binary(path: str, data: bytes) -> bool:
    return Path(path).suffix.lower() in BINARY_SUFFIXES or b"\0" in data[:8192]


def find_control_chars(data: bytes) -> list[tuple[int, int, int]]:
    """[(line, column, byte_value)] for every disallowed byte; 1-based line/column."""
    found: list[tuple[int, int, int]] = []
    line, col = 1, 0
    for b in data:
        col += 1
        if b == 0x0A:
            line, col = line + 1, 0
        elif b in _BAD:
            found.append((line, col, b))
    return found


def _staged() -> list[tuple[str, bytes]]:
    names = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")
    return [
        (n, subprocess.run(["git", "show", f":{n}"], cwd=ROOT, capture_output=True, check=True).stdout)
        for n in names if n
    ]


def _worktree() -> list[tuple[str, bytes]]:
    names = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")
    return [(n, (ROOT / n).read_bytes()) for n in names if n and (ROOT / n).is_file()]


def scan(files: list[tuple[str, bytes]]) -> list[str]:
    problems = []
    for name, data in files:
        if is_binary(name, data):
            continue
        for line, col, byte in find_control_chars(data)[:5]:
            problems.append(f"{name}:{line}:{col}: control character 0x{byte:02x}")
    return problems


def main(argv: list[str]) -> int:
    if "--staged" in argv:
        files = _staged()
    elif argv:
        files = [(a, Path(a).read_bytes()) for a in argv]
    else:
        files = _worktree()
    problems = scan(files)
    if problems:
        print("check_control_chars: FAILED (control characters outside TAB/LF/CR)", file=sys.stderr)
        for p in problems:
            print("  - " + p, file=sys.stderr)
        return 1
    print("check_control_chars: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
