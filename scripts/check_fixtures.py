#!/usr/bin/env python3
"""Pre-commit guard: fail if test fixtures leak internal data.

Checks every file under backendd/tests (and frontend/src/test) for ALL of the rules below, and
backend source/scripts/docs (DENYLIST_ONLY_PATHS) for rule 1 only:
  1. any pattern in the UNTRACKED local denylist (.denylist.local, repo root);
  2. RFC1918 IPv4 addresses (10/8, 172.16/12, 192.168/16);
  3. PUBLIC (globally routable) IPv4 addresses other than those listed in the tracked
     allowlist backend/tests/fixtures/allowed_ips.txt -- documentation ranges
     (192.0.2/24, 198.51.100/24, 203.0.113/24) are always fine; anything else, including
     real mail-relay/gateway IPs, must be explicitly approved there (attacker infra only);
  4. email addresses on domains that are not RFC-reserved (example.com/.net/.org,
     *.example, *.test, *.invalid, *.localhost) unless the exact address is listed in the
     tracked allowlist backend/tests/fixtures/allowed_addresses.txt (public attacker
     infrastructure kept on purpose in malicious fixtures).

.eml files are also parsed, and decoded headers (RFC 2047) and decoded text parts are
scanned -- a leak inside a base64 body is invisible to a raw-bytes scan.

Usage:  check_fixtures.py            scan the working tree
        check_fixtures.py --staged   scan staged content (used by .githooks/pre-commit)

Fail-closed: a missing .denylist.local is an error (set CHECK_FIXTURES_ALLOW_NO_DENYLIST=1
to run only checks 2-3, e.g. in CI or a fresh clone).
"""
from __future__ import annotations

import email
import email.policy
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = ("backend/tests", "frontend/src/test")  # every rule below applies here
# Source, scripts, docs and config: ONLY the denylist applies (an organisation name in tracked
# code or docs leaks exactly like one in a fixture). The IP/email rules would be noise here.
DENYLIST_ONLY_PATHS = ("backend/app", "backend/requirements.txt", "backend/.env.example", "scripts", ".githooks",
                       "docs", "README.md", "frontend/src", "frontend/README.md")
DENYLIST = ROOT / ".denylist.local"
ALLOWED_ADDRESSES = ROOT / "backend/tests/fixtures/allowed_addresses.txt"
ALLOWED_IPS = ROOT / "backend/tests/fixtures/allowed_ips.txt"
SKIP_PARTS = {"__pycache__", "_local_corpus"}  # _local_corpus is gitignored raw data
SKIP_SUFFIXES = {".pyc", ".png", ".jpg", ".gif"}

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# IPv6 candidates (validated with ipaddress afterwards, so clock times like 07:49:29 are ignored).
_IPV6 = re.compile(r"(?<![0-9A-Za-z])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)")
_RESERVED_SUFFIXES = ("example.com", "example.net", "example.org")
_RESERVED_TLDS = {"example", "test", "invalid", "localhost"}


def _reserved_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in _RESERVED_SUFFIXES or d.endswith(tuple("." + s for s in _RESERVED_SUFFIXES)):
        return True
    return d.rsplit(".", 1)[-1] in _RESERVED_TLDS


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _texts_for(name: str, data: bytes) -> list[str]:
    """Every textual view of a file: raw (utf-8 and utf-16 for .msg), plus decoded MIME."""
    views = [data.decode("utf-8", "replace"), data.decode("latin-1")]
    if name.lower().endswith(".msg"):
        views.append(data.decode("utf-16le", "ignore"))
    if name.lower().endswith(".eml"):
        try:
            msg = email.message_from_bytes(data, policy=email.policy.default)
            for hname, hval in msg.items():
                views.append(f"{hname}: {hval}")
            for part in msg.walk():
                if part.get_content_maintype() == "text":
                    try:
                        views.append(part.get_content())
                    except Exception:
                        pass
        except Exception:
            pass
    return views


def _in_scope(name: str) -> tuple[bool, bool]:
    """(scanned, full_rules)."""
    p = Path(name)
    if set(p.parts) & SKIP_PARTS or p.suffix.lower() in SKIP_SUFFIXES:
        return False, False
    if name.startswith(SCAN_DIRS):
        return True, True
    if name.startswith(DENYLIST_ONLY_PATHS) or name in DENYLIST_ONLY_PATHS:
        return True, False
    return False, False


def _files(staged: bool) -> list[tuple[str, bytes, bool]]:
    """[(path, content, full_rules)]"""
    result: list[tuple[str, bytes, bool]] = []
    if staged:
        names = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8").split("\0")
        for n in filter(None, names):
            scanned, full = _in_scope(n)
            if scanned:
                blob = subprocess.run(["git", "show", f":{n}"], cwd=ROOT, capture_output=True, check=True).stdout
                result.append((n, blob, full))
        return result
    names = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")
    for n in filter(None, names):
        scanned, full = _in_scope(n)
        if scanned and (ROOT / n).is_file():
            result.append((n, (ROOT / n).read_bytes(), full))
    return result


def main(argv: list[str]) -> int:
    staged = "--staged" in argv
    problems: list[str] = []

    deny_raw = _load_lines(DENYLIST)
    if not DENYLIST.exists():
        if os.environ.get("CHECK_FIXTURES_ALLOW_NO_DENYLIST") == "1":
            print("check_fixtures: WARNING .denylist.local missing -- denylist check skipped", file=sys.stderr)
        else:
            problems.append(
                f"{DENYLIST.name} not found. Create it (untracked) with one case-insensitive regex per line, "
                "or set CHECK_FIXTURES_ALLOW_NO_DENYLIST=1 to skip that check."
            )
    deny = []
    for pat in deny_raw:
        try:
            deny.append((pat, re.compile(pat, re.IGNORECASE)))
        except re.error as exc:
            problems.append(f"invalid regex in {DENYLIST.name}: {pat!r} ({exc})")

    allowed = {a.lower() for a in _load_lines(ALLOWED_ADDRESSES)}
    allowed_ips = set(_load_lines(ALLOWED_IPS))

    if staged:
        names = subprocess.run(["git", "diff", "--cached", "--name-only", "-z"], cwd=ROOT,
                               capture_output=True, check=True).stdout.decode().split("\0")
        if DENYLIST.name in names:
            problems.append(f"{DENYLIST.name} is staged -- it must never be committed")

    for name, data, full_rules in _files(staged):
        seen: set[tuple[str, str]] = set()

        def flag(kind: str, what: str) -> None:
            if (kind, what) not in seen:
                seen.add((kind, what))
                # Never echo the matched denylist text itself into logs/CI output.
                problems.append(f"{name}: {kind}" + (f" ({what})" if kind != "denylist match" else f" (pattern #{what})"))

        for view in _texts_for(name, data):
            for i, (pat, rx) in enumerate(deny, 1):
                if rx.search(view):
                    flag("denylist match", str(i))
            if not full_rules:
                continue
            for m in _IPV4.finditer(view):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if ip.is_private and not ip.is_loopback and not ip.is_link_local:
                    # 192.0.2/24, 198.51.100/24, 203.0.113/24 are not "private" in the RFC1918 sense
                    nets = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
                    if any(ip in n for n in nets):
                        flag("RFC1918 address", m.group(1))
                elif ip.is_global and str(ip) not in allowed_ips:
                    flag("public IP not in allowed_ips.txt", m.group(1))
            for m in _IPV6.finditer(view):
                try:
                    ip6 = ipaddress.IPv6Address(m.group(1))
                except ValueError:  # e.g. a 3-group clock time like 07:49:29
                    continue
                if ip6.is_global and str(ip6) not in allowed_ips:
                    flag("public IPv6 not in allowed_ips.txt", m.group(1))
            for m in _EMAIL.finditer(view):
                addr, domain = m.group(0), m.group(1)
                if not _reserved_domain(domain) and addr.lower() not in allowed:
                    flag("non-reserved email address", addr)

    if problems:
        print("check_fixtures: FAILED", file=sys.stderr)
        for p in problems:
            print("  - " + p, file=sys.stderr)
        return 1
    print("check_fixtures: OK")
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv[1:]))
