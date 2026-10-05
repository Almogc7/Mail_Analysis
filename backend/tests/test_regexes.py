"""Behavioural tests for every regex that contains an escape sequence, plus a meta-test that
keeps the registry complete.

Why: a regex whose backslash-b was silently turned into a literal backspace (or a lost
escape) keeps compiling and just stops matching, which in a detection tool means a silent
blind spot. Each pattern is exercised on inputs it must match and inputs it must not.

Adding a regex with an escape anywhere in backend/app or scripts/ WITHOUT adding it here
fails test_registry_covers_every_regex_with_escapes. Changing its flags fails the flag check.
Findall semantics: [] = no match; one group -> list of strings; several -> list of tuples.
"""
import ast
import importlib
import importlib.util
import re
from pathlib import Path

import pytest

from app.llm import prompting as _P

I, S = re.IGNORECASE, re.DOTALL
BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent

# (pattern literal exactly as written in the source, flags, [(input, expected findall)])
REGISTRY = [
    (r"^\s*(spf|dkim|dmarc)\s*=", I, [
        ("spf=pass; dkim=pass", ["spf"]), ("  DKIM = pass", ["DKIM"]),
        ("mx.example.org; spf=pass", []), ("x-spf=1", []), ("", [])]),
    (r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", I, [
        ("mx; spf=pass dkim = FAIL", [("spf", "pass"), ("dkim", "FAIL")]),
        ("xdmarc=pass", []), ("dmarc=none", [("dmarc", "none")]), ("spf pass", [])]),
    (r"```(?:json)?\s*(.*?)\s*```", S, [
        ('```json\n{"a": 1}\n```', ['{"a": 1}']), ("``` plain ```", ["plain"]), ("no fences", [])]),
    (r"\{.*\}", S, [
        ('x {"a": {"b": 1}} y', ['{"a": {"b": 1}}']), ("{\n}", ["{\n}"]), ("no braces", [])]),
    (r"^(?P<name>.*?)\s*<(?P<addr>[^<>]+)>\s*$", 0, [
        ("Alice Example <a@example.com>", [("Alice Example", "a@example.com")]),
        ("<a@example.com>", [("", "a@example.com")]), ("a@example.com", []), ("A <>", [])]),
    (r"""https?://[^\s<>\"']+""", 0, [
        ("see https://x.example.com/a?b=1 now", ["https://x.example.com/a?b=1"]),
        ("<http://y.example.org/z> end", ["http://y.example.org/z"]),
        ("\"https://q.example.net/r\" 'https://s.example.net/t'", ["https://q.example.net/r", "https://s.example.net/t"]),
        ("ftp://nope.example.com", []), ("https://", [])]),
    (r"from\s+(\S+)", I, [
        ("from mx.example.com (x)", ["mx.example.com"]), ("FROM\n\tHost.example.org by", ["Host.example.org"]), ("none here", [])]),
    (r"\bby\s+(\S+)", I, [
        ("from a by b.example.com", ["b.example.com"]), ("standby x", []), ("BY\n m.example.org", ["m.example.org"])]),
    (r"\bwith\s+([A-Za-z0-9_\-]+)", I, [
        ("by x with ESMTPS id 1", ["ESMTPS"]), ("with local (Exim", ["local"]), ("sandwith x", []),
        ("with Microsoft SMTP", ["Microsoft"]), ("with cipher ECDHE", ["cipher"])]),
    (r"\(envelope-from\s+<?([^>)\s]*)>?\)", I, [
        ("(envelope-from <a@example.com>)", ["a@example.com"]), ("(envelope-from a@example.com)", ["a@example.com"]),
        ("(envelope-from <>)", [""]), ("envelope-from <a@example.com>", [])]),
    (r"\bfrom\s+(.*?)(?:\s+by\s|$)", I | S, [
        ("from h (h [192.0.2.4]) by m with", ["h (h [192.0.2.4])"]), ("from h\n (x)\n by m", ["h\n (x)"]),
        ("from only-host", ["only-host"]), ("by m", [])]),
    (r"[\[(]\s*(?:IPv6:)?([0-9A-Fa-f:.]{3,45})\s*[\])]", 0, [
        ("(192.0.2.33)", ["192.0.2.33"]), ("h ([192.0.2.1])", ["192.0.2.1"]), ("[IPv6:2001:db8::1]", ["2001:db8::1"]),
        ("[ 198.51.100.7 ]", ["198.51.100.7"]), ("(helo=x)", []), ("(ab)", [])]),
    (r"\(Postfix, from userid \d+\)", I, [
        ("by h (Postfix, from userid 1000)", ["(Postfix, from userid 1000)"]), ("(Postfix, from userid x)", []),
        ("(postfix, FROM USERID 5)", ["(postfix, FROM USERID 5)"])]),
    (r"^\s*([A-Za-z]+)", 0, [(" Pass (x)", ["Pass"]), ("softfail", ["softfail"]), ("(x)", []), ("", [])]),
    (r"\(\s*([^\s:()]+)\s*:", 0, [
        ("Pass (esa.example.net: domain of", ["esa.example.net"]), ("( mx.example.org : x", ["mx.example.org"]),
        ("(no colon)", [])]),
    (r'([A-Za-z][\w-]*)\s*=\s*("[^"]*"|[^;\s]+)', 0, [
        ('identity=mailfrom; client-ip=192.0.2.4; x-record-text="v=spf1 ip4:192.0.2.4 ~all"',
         [("identity", "mailfrom"), ("client-ip", "192.0.2.4"), ("x-record-text", '"v=spf1 ip4:192.0.2.4 ~all"')]),
        ("receiver = mx.example.org;", [("receiver", "mx.example.org")]), ("no equals", [])]),
    (r"[\t\r\n]", 0, [("a\tb\r\nc", ["\t", "\r", "\n"]), ("a b", []), ("a\\tb", [])]),
    (r"\(Authenticated sender:|\bauthenticated\b", I, [
        ("(Authenticated sender: bob)", ["(Authenticated sender:"]), ("with authenticated smtp", ["authenticated"]),
        ("unauthenticated", []), ("none", [])]),
    (r"\bTLS|/TLS/", I, [
        ("using TLSv1.2", ["TLS"]), ("ESMTP/TLS/ECDHE", ["/TLS/"]), ("version=TLS1_2", ["TLS"]),
        ("MTLSX", []), ("plain", [])]),
    (r"[^\W_]+", 0, [
        ("Pay-Pal_2 שלום", ["Pay", "Pal", "2", "שלום"]), ("___", []), ("", [])]),
    (r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", 0, [
        ("ip=192.0.2.9,", ["192.0.2.9"]), ("192.0.2.1", ["192.0.2.1"]), ("192.0.2.4.5", []), ("15.2.1748.24", []),
        ("a 192.0.2.4 b 192.0.2.8", ["192.0.2.4", "192.0.2.8"])]),
    (r"(?<![0-9A-Za-z])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])", 0, [
        ("ip6:2a02:408:7722:1:77:222:61:245 ~all", ["2a02:408:7722:1:77:222:61:245"]), ("[2001:db8::1]", ["2001:db8::1"]),
        ("plain text", [])]),
    (r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)", 0, [
        ("a.b+c@mail.example.com", ["mail.example.com"]), ("x@localhost", []), ("no at here", []),
        ("<u-1@sub-d.example.org>", ["sub-d.example.org"])]),

    # ---- app/llm/prompting.py tokenizer (keyed by the module's own literal, so the meta-test stays exact) ----
    (_P._URL_RE.pattern, I, [
        ("see https://evil.example.net/a?b=1 now", ["https://evil.example.net/a?b=1"]),
        ("(http://x.example.org/y) and 'https://q.example.org/z'", ["http://x.example.org/y", "https://q.example.org/z"]),
        ("ftp://nope.example.com no url", [])]),
    (_P._EMAIL_RE.pattern, 0, [
        ("a.b+c@mail.example.com,", ["a.b+c@mail.example.com"]), ("x@localhost", []), ("no at sign", [])]),
    (_P._FILE_RE.pattern, I, [
        ("Invoice_JohnSmith.pdf and a.TXT", ["Invoice_JohnSmith.pdf", "a.TXT"]),
        ("report.pdfx", []), ("notes.html", ["notes.html"]), ("no file here", [])]),
    (_P._IPV4_RE.pattern, 0, [
        ("from 192.0.2.7 to 198.51.100.9", ["192.0.2.7", "198.51.100.9"]), ("1.2.3.4.5", []), ("v15.2.1748.24", [])]),
    (_P._IPV6_RE.pattern, 0, [
        ("from 2001:db8::1 via [2001:db8:0:0:0:0:0:2]", ["2001:db8::1", "2001:db8:0:0:0:0:0:2"]),
        ("clock 07:49:29", ["07:49:29"]), ("plain text", [])]),
    (_P._HASH_RE.pattern, 0, [
        ("sha " + "ab" * 32 + " end", ["ab" * 32]), ("short " + "ab" * 15 + "a", []), ("deadbeef", [])]),
    (_P._HOST_RE.pattern, 0, [
        ("vh319.sweb.ru and Mail.Example.COM.", ["vh319.sweb.ru", "Mail.Example.COM"]),
        ("e.g. word and 15.2.1748.24", []), ("one-label", [])]),
    (_P._INTERNAL_NAME_RE.pattern, 0, [
        ("MAILGW-NODE7 and ABC-12", ["MAILGW-NODE7", "ABC-12"]), ("abc-DEF and X-YY and Plain-Name", [])]),
    # scripts/check_contrast.py: a colour token declaration in theme.css
    (r"--([\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", 0, [
        ("--bg-root: #0b0e13;", [("bg-root", "#0b0e13")]), ("--x:#FFFFFF ;", [("x", "#FFFFFF")]),
        ("--a: #111111; --b: #222222;", [("a", "#111111"), ("b", "#222222")]),
        ("--x: #fff;", []), ("--x: var(--y);", []), ("color: #0b0e13;", []), ("--x: #0b0e1;", [])]),
]

REGISTRY_BY_PATTERN = {pat: flags for pat, flags, _ in REGISTRY}
CASE_IDS = [pat[:40] for pat, _, _ in REGISTRY]


@pytest.mark.parametrize("pattern,flags,cases", REGISTRY, ids=CASE_IDS)
def test_pattern_behaviour(pattern, flags, cases):
    rx = re.compile(pattern, flags)
    for text, expected in cases:
        assert rx.findall(text) == expected, (pattern, text)


def _regex_literals():
    """{literal: [where, ...]} for the first argument of every re.* call that is a plain string."""
    found = {}
    funcs = {"compile", "search", "match", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
    for root in (BACKEND / "app", ROOT / "scripts"):
        for path in sorted(root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "re"
                    and node.func.attr in funcs
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    found.setdefault(node.args[0].value, []).append(f"{path.name}:{node.lineno}")
    return found


def test_registry_covers_every_regex_with_escapes():
    in_code = _regex_literals()
    missing = {p: w for p, w in in_code.items() if "\\" in p and p not in REGISTRY_BY_PATTERN}
    stale = [p for p in REGISTRY_BY_PATTERN if p not in in_code]
    assert not missing, f"regexes with escapes lack tests in tests/test_regexes.py: {missing}"
    assert not stale, f"registry entries no longer present in code (update the registry): {stale}"


def test_no_regex_literal_contains_a_control_character():
    # e.g. backslash-b mangled into a literal backspace. Checked on every regex-call literal.
    for pattern, where in _regex_literals().items():
        bad = [c for c in pattern if ord(c) < 0x20]
        assert not bad, f"{where[0]}: regex literal contains control char {hex(ord(bad[0]))}"


def _module_level_patterns():
    mods = [importlib.import_module(m) for m in (
        "app.auth_check.spf_dkim_dmarc", "app.parser.msg_parser", "app.parser.normalize",
        "app.parser.preprocess", "app.shared.matching", "app.llm.prompting")]
    spec = importlib.util.spec_from_file_location("check_fixtures_for_regex_test", ROOT / "scripts" / "check_fixtures.py")
    cf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cf)
    mods.append(cf)
    for mod in mods:
        for name, value in vars(mod).items():
            if isinstance(value, re.Pattern) and "\\" in value.pattern:
                yield f"{mod.__name__}.{name}", value


def test_compiled_module_patterns_use_the_flags_the_registry_tests():
    seen = 0
    for qualname, rx in _module_level_patterns():
        assert rx.pattern in REGISTRY_BY_PATTERN, f"{qualname} is not in the registry"
        assert (rx.flags & ~re.UNICODE) == REGISTRY_BY_PATTERN[rx.pattern], f"{qualname}: flags differ from the tested flags"
        seen += 1
    assert seen >= 15  # guards against the discovery above silently finding nothing
