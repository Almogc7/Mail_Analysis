"""Tolerant From/Reply-To extraction (app/parser/addresses.py + eml_parser integration)."""
import email
import email.policy
from pathlib import Path

import pytest

from app.auth_check import run_auth_check
from app.contracts.findings import ModuleResult
from app.parser import parse_email_file
from app.parser.addresses import AMBIGUITY_PREFIX, parse_address_header
from app.parser.eml_parser import _to_raw_addresses
from app.scoring import run_scoring
from tests.eval import FIXTURES, analyze


def _one(raw):
    r = parse_address_header(raw)
    return r.addresses, r.reasons


# ---- the extractor ----------------------------------------------------------------------------------

def test_unquoted_comma_in_the_display_name_keeps_the_angle_bracket_address():
    addrs, reasons = _one("PayPal, Inc. <support@evil.example.net>")
    assert addrs == [("PayPal, Inc.", "support@evil.example.net")] and reasons == ["unquoted comma in the display name"]


def test_a_quoted_comma_is_not_ambiguous():
    assert _one('"Doe, John" <j@x.example.org>') == ([("Doe, John", "j@x.example.org")], [])


def test_encoded_word_containing_an_encoded_comma_is_not_ambiguous():
    assert _one("=?utf-8?Q?Doe=2C_John?= <a@x.example.com>") == ([("Doe, John", "a@x.example.com")], [])


def test_encoded_word_display_is_decoded():
    (name, addr), = parse_address_header("=?utf-8?B?15PXldeT?= <a@x.example.com>").addresses
    assert name == "דוד" and addr == "a@x.example.com"


def test_unquoted_comma_inside_non_latin_display_names():
    assert _one("שלום, עולם <a@x.example.com>") == ([("שלום, עולם", "a@x.example.com")], ["unquoted comma in the display name"])


def test_multiple_addresses_primary_is_the_first_and_domains_are_counted():
    r = parse_address_header("A <a@x.example.com>, B <b@y.example.org>")
    assert r.primary == ("A", "a@x.example.com") and r.domains == ["x.example.com", "y.example.org"]
    assert r.reasons == ["multiple addresses (2, 2 distinct domains)"]


def test_multiple_addresses_on_one_domain_say_so():
    assert parse_address_header("a@x.example.com, b@x.example.com").reasons == ["multiple addresses (2, 1 distinct domain)"]


def test_group_syntax_lists_the_members():
    r = parse_address_header("Team: a@x.example.com, b@y.example.org;")
    assert [a for _, a in r.addresses] == ["a@x.example.com", "b@y.example.org"] and "group syntax" in r.reasons


def test_an_empty_group_has_no_address():
    r = parse_address_header("Undisclosed recipients:;")
    assert r.addresses == [] and "group syntax" in r.reasons and "no address found" in r.reasons


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("< a@x.example.com >", "a@x.example.com"),
        ("Name <a@x.example.com>>", "a@x.example.com"),
        ("a@x.example.com (Display Name)", "a@x.example.com"),
        ("a@x.example.com", "a@x.example.com"),
        ('"Sm\\"ith" <a@x.example.com>', "a@x.example.com"),
        ('"support@paypal.com" <x@evil.example.net>', "x@evil.example.net"),  # the angle address is the sender
        ("Foo; Bar <a@x.example.com>", "a@x.example.com"),
    ],
)
def test_the_address_in_angle_brackets_is_the_sender(raw, expected):
    assert parse_address_header(raw).primary[1] == expected


def test_a_comment_style_display_name_is_used():
    assert parse_address_header("a@x.example.com (Display Name)").primary == ("Display Name", "a@x.example.com")


@pytest.mark.parametrize("raw", ['Unclosed "quote <a@x.example.com>', "Name (unclosed <a@x.example.com>", "Name <a@x.example.com"])
def test_unterminated_quotes_comments_and_brackets_do_not_hide_the_address(raw):
    r = parse_address_header(raw)
    assert r.primary[1] == "a@x.example.com" and "unbalanced quote, comment or angle bracket" in r.reasons


@pytest.mark.parametrize("raw,reason", [("nobody", "no address found"), ("", "empty header"), (None, "empty header")])
def test_no_address_is_reported_not_invented(raw, reason):
    r = parse_address_header(raw)
    assert r.addresses == [] and reason in r.reasons


def test_the_quoted_address_inside_a_display_name_never_becomes_the_sender():
    r = parse_address_header('"PayPal <ceo@paypal.com>" <x@evil.example.net>')
    assert r.primary[1] == "x@evil.example.net"


# ---- through the real parser ---------------------------------------------------------------------------

def _eml(frm, extra="", subject="s", body="hello"):
    raw = (f"From: {frm}\r\nTo: Test <recipient@example.com>\r\nSubject: {subject}\r\nDate: Mon, 21 Sep 2026 10:00:00 +0000\r\n"
           f"Message-ID: <m@x.example.com>\r\nMIME-Version: 1.0\r\n{extra}Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n")
    return raw.encode("utf-8")


def _parse(frm, **kw):
    return parse_email_file(_eml(frm, **kw), "x.eml")


def test_the_malformed_from_that_blinded_22_percent_of_the_corpus_now_has_a_domain():
    parsed = _parse("PayPal, Inc. <support@evil.example.net>")
    assert parsed.from_.address == "support@evil.example.net" and parsed.from_.domain == "evil.example.net"
    assert parsed.from_.display_name == "PayPal, Inc."
    warning = next(w for w in parsed.parse_warnings if w.startswith(f"{AMBIGUITY_PREFIX}:from:"))
    assert "unquoted comma" in warning and "recovered from the angle brackets" in warning


def test_recovering_the_domain_unlocks_the_sender_checks_that_were_blind():
    # the whole point: the brand claim in the display name is now visible against the real sender domain. On its own it is
    # one family (claim), so it is inconclusive, not flagged...
    alone = analyze_bytes(_eml("PayPal, Inc. <support@evil.example.net>"))
    titles = [f.title for f in alone.findings]
    assert "Possible display-name spoofing of 'paypal'" in titles and "From header parse ambiguity" in titles
    assert alone.verdict == "needs_review"
    # ...and with corroboration from another family (a machine-provisioned sender) it floors
    corroborated = analyze_bytes(_eml("PayPal, Inc. <vnz73mailr@vh319.hosting.example.net>"))
    assert corroborated.verdict == "suspicious"
    assert any(o.rule == "structural_corroboration_floor" for o in corroborated.scoring.applied_overrides)


def analyze_bytes(raw: bytes):
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.eml"
        path.write_bytes(raw)
        return analyze(path, "clean")


def test_the_ambiguity_finding_is_informational_and_never_scores_on_its_own():
    messy = analyze_bytes(_eml("Smith, John <john@benign.example.org>"))
    clean = analyze_bytes(_eml('"Smith, John" <john@benign.example.org>'))
    finding = next(f for f in messy.findings if f.title == "From header parse ambiguity")
    assert finding.severity == "low" and finding.weight == 0.0
    assert "does not affect the score by itself" in finding.description
    # the finding changes neither score nor verdict; both are inconclusive (no positive evidence), never flagged
    assert messy.verdict == clean.verdict and messy.score == clean.score
    assert messy.verdict == "needs_review" and messy.verdict not in ("suspicious", "malicious")
    assert not any(f.title == "From header parse ambiguity" for f in clean.findings)


def test_the_finding_alone_cannot_trigger_any_floor():
    parsed = _parse("Smith, John <john@benign.example.org>")
    auth = run_auth_check(parsed)
    quiet = [ModuleResult(module=m, status="ok", findings=[], raw_data={}) for m in ("enrichment", "content_analysis")]
    outcome = run_scoring([auth, *quiet])
    assert not any(o.rule.endswith("_floor") for o in outcome.breakdown.applied_overrides)
    assert outcome.verdict not in ("suspicious", "malicious")
    assert sum(f.weight for f in auth.findings if f.title == "From header parse ambiguity") == 0.0


def test_multiple_from_addresses_use_the_first_and_flag_it():
    parsed = _parse("A <a@x.example.com>, B <b@y.example.org>")
    assert parsed.from_.address == "a@x.example.com"
    assert any("multiple addresses (2, 2 distinct domains)" in w for w in parsed.parse_warnings)


def test_group_syntax_in_from_uses_the_first_member_and_flags_it():
    parsed = _parse("Team: a@x.example.com, b@y.example.org;")
    assert parsed.from_.address == "a@x.example.com" and any("group syntax" in w for w in parsed.parse_warnings)


def test_encoded_word_display_names_stay_clean_and_unflagged():
    parsed = _parse("=?utf-8?Q?Doe=2C_John?= <a@x.example.com>")
    assert parsed.from_.display_name == "Doe, John" and parsed.from_.domain == "x.example.com"
    assert not [w for w in parsed.parse_warnings if w.startswith(AMBIGUITY_PREFIX)]


def test_a_malformed_reply_to_is_recovered_and_flagged_but_gets_no_from_finding():
    parsed = _parse('"Clean Sender" <a@x.example.com>', extra="Reply-To: Support, Team <help@elsewhere.example.org>\r\n")
    assert parsed.reply_to[0].domain == "elsewhere.example.org"
    assert any(w.startswith(f"{AMBIGUITY_PREFIX}:reply-to:") for w in parsed.parse_warnings)
    assert "From header parse ambiguity" not in [f.title for f in run_auth_check(parsed).findings]


def test_a_list_of_to_recipients_is_not_ambiguous():
    raw = _eml('"Clean" <a@x.example.com>').replace(b"To: Test <recipient@example.com>", b"To: A <a@example.com>, B <b@example.org>")
    parsed = parse_email_file(raw, "x.eml")
    assert len(parsed.to) == 2 and not [w for w in parsed.parse_warnings if w.startswith(AMBIGUITY_PREFIX)]


def test_raw_utf8_display_names_with_commas_do_not_break_extraction():
    raw = "From: שלום, עולם <a@x.example.com>\r\nTo: t@example.com\r\nSubject: s\r\n\r\nb\r\n".encode("utf-8")
    parsed = parse_email_file(raw, "x.eml")
    assert parsed.from_.domain == "x.example.com" and parsed.from_.display_name == "שלום, עולם"


def test_a_missing_from_header_does_not_crash():
    raw = b"To: t@example.com\r\nSubject: s\r\n\r\nb\r\n"
    parsed = parse_email_file(raw, "x.eml")
    assert parsed.from_.address is None and not parsed.parse_warnings


# ---- no regression on well-formed mail ----------------------------------------------------------------------

def _all_eml():
    return sorted(p for p in FIXTURES.rglob("*.eml") if "_local_corpus" not in p.parts) + sorted((FIXTURES / "samples").glob("*.eml"))


@pytest.mark.parametrize("path", _all_eml(), ids=lambda p: p.name)
def test_every_committed_eml_parses_its_addresses_exactly_as_the_strict_parser_does(path):
    raw = path.read_bytes()
    parsed = parse_email_file(raw, path.name)
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    for header, got in (("to", parsed.to), ("cc", parsed.cc), ("reply-to", parsed.reply_to)):
        strict = _to_raw_addresses(msg, header)
        assert [(a.address or "").lower() for a in strict] == [(a.address or "").lower() for a in got], header
    strict_from = _to_raw_addresses(msg, "from")
    if strict_from:
        assert (strict_from[0].address or "").lower() == (parsed.from_.address or "").lower()
        assert strict_from[0].display_name == parsed.from_.display_name


@pytest.mark.parametrize("path", sorted((FIXTURES / "benign" / "synthetic").glob("*.eml")) + sorted((FIXTURES / "malicious").glob("*.eml")), ids=lambda p: p.name)
def test_well_formed_fixtures_produce_no_ambiguity_warning(path):
    parsed = parse_email_file(path.read_bytes(), path.name)
    assert not [w for w in parsed.parse_warnings if w.startswith(AMBIGUITY_PREFIX)]
