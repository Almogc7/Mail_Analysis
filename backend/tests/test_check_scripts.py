"""Unit tests for the pre-commit guards in scripts/ (they are the last line of defence
against leaking internal data or committing corrupted regexes, so they get tests too)."""
import importlib.util
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cc = _load("check_control_chars")
cf = _load("check_fixtures")


# ---- check_control_chars ----------------------------------------------------------------

@pytest.mark.parametrize("byte", [0x00, 0x01, 0x08, 0x0B, 0x0C, 0x0E, 0x1B, 0x1F, 0x7F])
def test_control_chars_are_found(byte):
    data = b"line one\nre.compile(r'" + bytes([byte]) + b"word')\n"
    assert cc.find_control_chars(data) == [(2, 14, byte)]


def test_tab_lf_cr_are_allowed():
    assert cc.find_control_chars(b"a\tb\r\nc\n") == []


def test_backspace_from_a_botched_backslash_b_is_caught_with_location_only():
    problems = cc.scan([("app/x.py", b"X = re.compile(r\"" + bytes([8]) + b"with\\s+(\\w+)\")\n")])
    assert problems == ["app/x.py:1:18: control character 0x08"]  # position and byte, never content


def test_binary_files_are_skipped():
    assert cc.scan([("fixtures/sample.msg", bytes([0, 8, 1]))]) == []
    assert cc.scan([("img.png", bytes([8]))]) == []
    assert cc.scan([("blob.dat", b"\0\x08binary")]) == []  # NUL in the first 8 KB => binary


def test_unicode_text_is_not_flagged():
    assert cc.find_control_chars("שלום ​ world €".encode("utf-8")) == []


def test_working_tree_is_clean():
    assert cc.scan(cc._worktree()) == []


# ---- check_fixtures: IPv6 and IPv4 rules --------------------------------------------------

def _flagged_ips(text, allowed=()):
    out = []
    for m in cf._IPV4.finditer(text):
        import ipaddress

        ip = ipaddress.ip_address(m.group(1))
        if ip.is_global and str(ip) not in allowed:
            out.append(str(ip))
    for m in cf._IPV6.finditer(text):
        import ipaddress

        try:
            ip6 = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            continue
        if ip6.is_global and str(ip6) not in allowed:
            out.append(str(ip6))
    return out


def test_public_ipv6_in_spf_record_text_is_found():
    assert _flagged_ips("v=spf1 ip6:2a02:408:7722:1:77:222:61:245 ~all") == ["2a02:408:7722:1:77:222:61:245"]


def test_documentation_ipv6_clock_times_and_mac_like_text_are_not_flagged():
    text = "from x ([2001:db8::1]) Sat, 26 Sep 2026 07:49:29 +0300 id 15.2.1748.24 aa:bb:cc"
    assert _flagged_ips(text) == []


def test_allowlisted_public_ips_pass_and_others_fail():
    other = ".".join(("8", "8", "4", "4"))  # built at runtime: fixtures/tests must not contain real public IP literals
    assert _flagged_ips(f"client 77.222.61.245 and {other}", allowed={"77.222.61.245"}) == [other]


def test_documentation_ranges_pass():
    assert _flagged_ips("192.0.2.5 198.51.100.7 203.0.113.9") == []


@pytest.mark.parametrize(
    "domain,reserved",
    [("example.com", True), ("mail.example.org", True), ("a.b.example.net", True), ("host.example", True),
     ("x.test", True), ("corp.invalid", True), ("paypal.com", False), ("example.com.evil.io", False), ("example.fr", False)],
)
def test_reserved_domain_rule(domain, reserved):
    assert cf._reserved_domain(domain) is reserved


# ---- check_fixtures: scope (which files get which rules) ----------------------------------------

@pytest.mark.parametrize(
    "path,expected",
    [
        ("backend/tests/fixtures/x.eml", (True, True)),
        ("backend/tests/test_x.py", (True, True)),
        ("frontend/src/test/fixtures.ts", (True, True)),
        ("backend/app/shared/brands.py", (True, False)),  # denylist only
        ("scripts/check_fixtures.py", (True, False)),
        ("README.md", (True, False)),
        ("docs/notes.md", (True, False)),
        ("frontend/src/App.tsx", (True, False)),
        ("backend/.env.example", (True, False)),
        ("backend/tests/fixtures/_local_corpus/tuning/a.eml", (False, False)),  # raw local data, gitignored
        ("docs/screenshots/summary-card.png", (False, False)),
        ("backend/app/__pycache__/x.pyc", (False, False)),
        ("frontend/package-lock.json", (False, False)),
    ],
)
def test_scope_rules(path, expected):
    assert cf._in_scope(path) == expected


# ---- embedded repositories (a corpus clone dropped inside the project) ---------------------------------

import subprocess  # noqa: E402


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={**__import__("os").environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"})


@pytest.fixture
def repo_with_embedded_clone(tmp_path, monkeypatch):
    repo = tmp_path / "outer"
    inner = repo / "corpus_clone"
    inner.mkdir(parents=True)
    _git(inner, "init", "-q")
    (inner / "a.eml").write_text("Subject: x\n\nbody\n")
    _git(inner, "add", "-A")
    _git(inner, "commit", "-q", "-m", "c")
    _git(repo, "init", "-q")
    (repo / "notes.txt").write_text("plain text\n")
    _git(repo, "add", "-A")  # stages notes.txt AND the embedded repository (a gitlink)
    monkeypatch.setattr(cc, "ROOT", repo)
    monkeypatch.setattr(cf, "ROOT", repo)
    return repo


def test_staged_entries_report_the_gitlink_mode(repo_with_embedded_clone):
    modes = dict((path, mode) for mode, path in cc._staged_entries())
    assert modes["corpus_clone"] == "160000" and modes["notes.txt"] == "100644"


def test_control_char_hook_no_longer_crashes_on_a_staged_embedded_repo(repo_with_embedded_clone):
    # Regression: this raised CalledProcessError ('git show :corpus_clone') and killed the hook.
    scanned = cc._staged()
    assert [name for name, _ in scanned] == ["notes.txt"]
    assert cc.scan(scanned) == []


def test_leak_guard_rejects_a_staged_embedded_repository(repo_with_embedded_clone, monkeypatch, capsys):
    monkeypatch.setenv("CHECK_FIXTURES_ALLOW_NO_DENYLIST", "1")
    assert cf.main(["--staged"]) == 1
    err = capsys.readouterr().err
    assert "corpus_clone" in err and "embedded git repository" in err
