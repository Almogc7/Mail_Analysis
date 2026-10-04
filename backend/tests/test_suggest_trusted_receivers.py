"""scripts/suggest_trusted_receivers.py, and the .env.example values it feeds."""
import importlib.util
import json
import re
from pathlib import Path

import pytest

from app.auth_check.spf_dkim_dmarc import evaluate_authentication
from app.parser import parse_email_file
from tests.eval import FIXTURES

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("suggest_trusted_receivers", ROOT / "scripts" / "suggest_trusted_receivers.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

NEWSLETTER = FIXTURES / "benign" / "synthetic" / "01_newsletter_esp_click_tracking.eml"


def _eml(tmp_path, headers: str, name="m.eml") -> Path:
    path = tmp_path / name
    path.write_text(headers + "Subject: SECRET-SUBJECT-LINE\nTo: t@example.com\nMIME-Version: 1.0\nContent-Type: text/plain\n\nbody SECRET-BODY\n", encoding="utf-8")
    return path


def test_it_suggests_the_gateway_named_in_the_header_that_is_also_a_hop(capsys):
    assert tool.main([str(NEWSLETTER)]) == 0
    out = capsys.readouterr().out
    assert "mx.example.org" in out and "hop 1 of 1" in out and "dkim=pass, dmarc=pass, spf=pass" in out
    assert 'TRUSTED_RECEIVER_PATTERNS=["^mx\\\\.example\\\\.org$"]' in out
    assert "removes or overwrites" in out and "Never trust a host that is the sender's own server" in out


def test_the_suggested_line_is_valid_json_and_really_makes_the_results_trusted(capsys):
    tool.main([str(NEWSLETTER)])
    line = next(l for l in capsys.readouterr().out.splitlines() if l.strip().startswith("TRUSTED_RECEIVER_PATTERNS="))
    patterns = json.loads(line.split("=", 1)[1])
    assert patterns == [r"^mx\.example\.org$"]
    parsed = parse_email_file(NEWSLETTER.read_bytes(), NEWSLETTER.name)
    auth = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain, patterns, headers=parsed.headers)
    assert auth["dkim"]["evaluated"] and auth["dkim"]["result"] == "pass" and auth["header_present"] is True
    untrusted = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain, [], headers=parsed.headers)
    assert not untrusted["dkim"]["evaluated"]


def test_a_header_host_that_is_not_a_hop_does_not_qualify_and_nothing_is_suggested(tmp_path, capsys):
    path = _eml(tmp_path, "Received: from a.example.net (a.example.net [192.0.2.1]) by mx.example.org with ESMTP; Tue, 08 Sep 2026 09:12:03 +0000\n"
                          "Authentication-Results: elsewhere.example.net; spf=pass smtp.mailfrom=x.example.com\nFrom: A <a@x.example.com>\n")
    assert tool.main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "NOT a hop of this message" in out and "Nothing to suggest" in out and "TRUSTED_RECEIVER_PATTERNS=" not in out


def test_it_prints_host_names_only_never_subject_body_or_addresses(tmp_path, capsys):
    path = _eml(tmp_path, "Received: from a.example.net (a.example.net [192.0.2.1]) by mx.example.org with ESMTP; Tue, 08 Sep 2026 09:12:03 +0000\n"
                          "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=x.example.com\nFrom: Secret Person <secret.person@x.example.com>\n")
    tool.main([str(path)])
    out = capsys.readouterr().out
    for private in ("SECRET-SUBJECT-LINE", "SECRET-BODY", "secret.person", "Secret Person", "192.0.2.1"):
        assert private not in out


def test_a_file_without_authentication_headers_is_reported_plainly(tmp_path, capsys):
    path = _eml(tmp_path, "Received: from a.example.net (a.example.net [192.0.2.1]) by mx.example.org with ESMTP; Tue, 08 Sep 2026 09:12:03 +0000\nFrom: A <a@x.example.com>\n")
    assert tool.main([str(path)]) == 1
    assert "no Authentication-Results or Received-SPF header found" in capsys.readouterr().out


def test_no_arguments_prints_the_usage_and_exits_2(capsys):
    assert tool.main([]) == 2
    assert "suggest_trusted_receivers.py reported_mail.eml" in capsys.readouterr().out


def test_several_files_count_how_often_each_host_qualifies(capsys):
    assert tool.main([str(NEWSLETTER), str(NEWSLETTER)]) == 0
    assert "in 2 of 2 file(s)" in capsys.readouterr().out


def test_anchoring_escapes_dots_so_a_lookalike_host_cannot_match():
    pattern = re.compile(tool.anchored("mx.example.org"))
    assert pattern.search("mx.example.org")
    for lookalike in ("mxxexample.org", "mx.example.org.evil.test", "evil-mx.example.org"):
        assert not pattern.search(lookalike)


# ---- the env example must actually load ---------------------------------------------------------------------------------

ENV_EXAMPLE = (ROOT / "backend" / ".env.example").read_text(encoding="utf-8")


@pytest.mark.parametrize("key", ["TRUSTED_RECEIVER_PATTERNS", "GATEWAY_BANNER_PATTERNS", "GATEWAY_SUBJECT_TAG_PATTERNS"])
def test_the_examples_in_env_example_are_valid_json_regex_lists(key):
    """A single backslash in these JSON values crashed the app at import. The examples must be pasteable as they are."""
    line = next(l for l in ENV_EXAMPLE.splitlines() if l.startswith(f"# {key}="))
    value = json.loads(line.split("=", 1)[1])
    assert isinstance(value, list) and value and all(isinstance(v, str) for v in value)
    for pattern in value:
        re.compile(pattern)


def test_env_example_warns_about_the_double_backslash():
    assert "every backslash is written twice" in ENV_EXAMPLE
