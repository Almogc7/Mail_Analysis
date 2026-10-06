"""The organisation's own-domain list (app/config.py): an untracked, git-ignored JSON list, empty by default, matched by registrable domain; the tracked example holds reserved domains only."""
import json
import re
import subprocess
from pathlib import Path

import pytest

from app import config
from app.shared.matching import domain_matches_any

ROOT = Path(__file__).resolve().parents[2]
RESERVED = re.compile(r"(^|\.)(example\.(com|net|org)|[a-z0-9-]+\.(example|test|invalid))$")


def _load(monkeypatch, tmp_path, content=None, env=True):
    file = tmp_path / "own.json"
    if content is not None:
        file.write_text(content, encoding="utf-8")
    monkeypatch.setenv("OWN_DOMAINS_FILE", str(file) if env else "")
    return config._load_own_domains()


def test_a_missing_file_gives_an_empty_list(monkeypatch, tmp_path):
    assert _load(monkeypatch, tmp_path) == frozenset()


def test_the_default_path_is_backend_own_domains_local_json_and_the_list_is_empty_when_that_file_is_absent(monkeypatch):
    monkeypatch.delenv("OWN_DOMAINS_FILE", raising=False)
    default = ROOT / "backend" / "own_domains.local.json"
    if not default.exists():
        assert config._load_own_domains() == frozenset()
    assert isinstance(config.OWN_DOMAINS, frozenset)


def test_domains_are_lower_cased_and_stripped_of_surrounding_dots(monkeypatch, tmp_path):
    assert _load(monkeypatch, tmp_path, json.dumps({"domains": ["Example.COM", ".example.org.", " corp.example.net "]})) == frozenset({"example.com", "example.org", "corp.example.net"})


@pytest.mark.parametrize("content", ["not json", "[]", '{"domains": "example.com"}', '{"domains": [1]}', '{"domains": [""]}', '{"other": []}'])
def test_a_malformed_file_is_refused_with_a_clear_error(monkeypatch, tmp_path, content):
    with pytest.raises(ValueError, match="own.json"):
        _load(monkeypatch, tmp_path, content)


def test_the_known_sender_loader_behaves_as_before(monkeypatch, tmp_path):
    file = tmp_path / "known.json"
    monkeypatch.setenv("KNOWN_SENDERS_FILE", str(file))
    assert config._load_known_sender_domains() == frozenset()
    file.write_text(json.dumps({"domains": ["Supplier.EXAMPLE.com."]}), encoding="utf-8")
    assert config._load_known_sender_domains() == frozenset({"supplier.example.com"})
    file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="known.json"):
        config._load_known_sender_domains()


def test_matching_is_by_registrable_domain_so_a_subdomain_matches_and_a_lookalike_does_not():
    own = ["example.com", "corp.example.org"]
    assert domain_matches_any("example.com", own)
    assert domain_matches_any("mail.example.com", own)
    assert domain_matches_any("a.b.example.com", own)
    assert domain_matches_any("MAIL.Example.COM.", own)
    assert not domain_matches_any("example.com.evil.example.net", own)
    assert not domain_matches_any("notexample.com", own)
    assert not domain_matches_any("example.co", own)
    assert not domain_matches_any("192.0.2.7", own)  # an IP has no registrable domain
    assert not domain_matches_any(None, own) and not domain_matches_any("example.com", [])


def test_the_real_file_is_git_ignored_and_the_example_is_tracked_with_reserved_domains_only():
    ignored = subprocess.run(["git", "check-ignore", "backend/own_domains.local.json"], cwd=ROOT, capture_output=True, text=True)
    assert ignored.returncode == 0, "backend/own_domains.local.json must be in .gitignore"
    not_ignored = subprocess.run(["git", "check-ignore", "backend/own_domains.local.example.json"], cwd=ROOT, capture_output=True, text=True)
    assert not_ignored.returncode == 1, "the example file must be tracked"
    example = json.loads((ROOT / "backend" / "own_domains.local.example.json").read_text(encoding="utf-8"))
    assert example["domains"] and all(RESERVED.search(d) for d in example["domains"]), example


def test_the_file_name_is_mentioned_in_the_env_example_and_the_readme():
    assert "own_domains.local.json" in (ROOT / "backend" / ".env.example").read_text(encoding="utf-8")
    assert "own_domains.local.json" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "OWN_DOMAINS_FILE" in (ROOT / "backend" / ".env.example").read_text(encoding="utf-8")
