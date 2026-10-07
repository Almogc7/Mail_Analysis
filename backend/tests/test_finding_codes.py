"""The finding-code registry (app/finding_codes.py, docs/DESIGN_V2.md D22): one stable, content-free code per kind of finding. These tests pin the registry's own rules and the contract;
the tests that tie the producers to the registry are further down."""
import ast
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.contracts.findings import Finding
from app.finding_codes import BY_CODE, CODE_PATTERN, MODULE_PREFIX, REGISTRY, code

BACKEND = Path(__file__).resolve().parents[1]
APP = BACKEND / "app"
FROZEN = BACKEND / "tests" / "fixtures" / "finding_codes_frozen.json"
V1_BANNED_TOKENS = {"SAFE", "CLEAN", "LEGIT", "BENIGN", "HARMLESS"}  # the V1 word ban, as underscore-separated tokens (a code has no spaces)


# ---- the registry's own rules ----------------------------------------------------------------------------------------------------------

def test_every_code_matches_the_pattern_and_carries_its_modules_prefix():
    for kind in REGISTRY:
        assert CODE_PATTERN.match(kind.code), kind.code
        assert kind.module in MODULE_PREFIX, kind.code
        assert kind.code.startswith(MODULE_PREFIX[kind.module]), kind.code


def test_there_are_no_duplicate_codes():
    codes = [k.code for k in REGISTRY]
    assert len(codes) == len(set(codes)) == len(BY_CODE)


def test_no_code_contains_a_word_the_v1_ban_forbids():
    assert [k.code for k in REGISTRY if V1_BANNED_TOKENS & set(k.code.split("_"))] == []


def test_every_kind_has_a_valid_default_severity_and_a_consistent_family_and_signal():
    for kind in REGISTRY:
        assert kind.severity in {"info", "low", "medium", "high", "critical"}, kind.code
        assert kind.family in {None, "sender", "link", "claim"}, kind.code
        if kind.family is not None:
            assert kind.signal, f"{kind.code}: a structural family needs its signal id"
        if kind.signal is not None:
            assert re.match("^[SLC][0-9][a-z]?$", kind.signal), kind.code


def test_descriptions_are_templates_never_real_values():
    """Every quoted part of a description is a <placeholder>; no address, URL, host or IP literal appears."""
    for kind in REGISTRY:
        assert not re.search("https?://|@|[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}", kind.description), kind.code
        for quoted in re.findall("(?<![A-Za-z])'([^']*)'(?![A-Za-z])", kind.description):  # a possessive apostrophe (brand's) is not a quote mark
            assert "<" in quoted and ">" in quoted, f"{kind.code}: the quoted part '{quoted}' is not a placeholder"


def test_a_retired_code_stays_in_the_registry_with_a_note():
    assert all(k.note.strip() for k in REGISTRY if k.retired)


def test_code_returns_a_registered_code_and_rejects_anything_else():
    assert code("AUTH_SPF_CHECK_FAILED") == "AUTH_SPF_CHECK_FAILED"
    for bad in ("AUTH_SPF_CHECK_FAILD", "auth_spf_check_failed", ""):
        with pytest.raises(KeyError):
            code(bad)


# ---- codes are frozen -------------------------------------------------------------------------------------------------------------------

def test_the_registry_equals_the_frozen_snapshot_so_a_rename_or_a_new_code_is_a_deliberate_edit_of_both():
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))["codes"]
    current = {k.code: {"module": k.module, "family": k.family, "signal": k.signal} for k in REGISTRY}
    assert sorted(set(frozen) - set(current)) == [], "a frozen code was removed or renamed: keep it with retired=True and a note, and add a NEW code"
    assert sorted(set(current) - set(frozen)) == [], "a code is not in tests/fixtures/finding_codes_frozen.json: add it there in the same commit"
    changed = [c for c in frozen if frozen[c] != current[c]]
    assert changed == [], f"the module, family or signal of a frozen code changed (that is a different meaning: use a new code): {changed}"


# ---- the contract ------------------------------------------------------------------------------------------------------------------------

def _finding(**over):
    base = dict(module="auth_check", severity="info", title="t", description="d")
    base.update(over)
    return Finding(**base)


def test_the_code_field_is_optional_additive_and_defaults_to_none():
    assert _finding().code is None
    old_shape = {"module": "auth_check", "severity": "low", "title": "t", "description": "d", "evidence": {}, "weight": 1.0}
    assert Finding.model_validate(old_shape).code is None  # an older result without the field still parses


def test_the_contract_accepts_a_well_formed_code_and_rejects_a_malformed_one():
    assert _finding(code="AUTH_SPF_CHECK_FAILED").code == "AUTH_SPF_CHECK_FAILED"
    for bad in ("auth_spf", "ABC", "AUTH-SPF-FAILED", "AUTH SPF FAILED", "1AUTH_SPF", "A" * 70, "AUTH_SPF_É"):
        with pytest.raises(ValidationError):
            _finding(code=bad)


# ---- the producers ----------------------------------------------------------------------------------------------------------------------

def _construction_sites_without_a_code():
    """{relative file: [line, ...]} of every Finding(...) call in backend/app that does not pass `code=`."""
    missing: dict[str, list[int]] = {}
    for path in sorted(APP.rglob("*.py")):
        rel = path.relative_to(BACKEND).as_posix()
        if rel == "app/contracts/findings.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and (getattr(node.func, "id", None) == "Finding" or getattr(node.func, "attr", None) == "Finding"):
                if not any(kw.arg == "code" for kw in node.keywords):  # a **kwargs call cannot be verified, so it counts as missing
                    missing.setdefault(rel, []).append(node.lineno)
    return missing


def test_every_finding_construction_site_passes_a_code():
    assert _construction_sites_without_a_code() == {}, "a Finding is built without code= (a new kind of finding needs a registry entry and a code first)"


# ---- the codes that actually come out ---------------------------------------------------------------------------------------------------

def _corpus_findings():
    """Every finding of every fixture and tuning-corpus message (collect(None) never reads the hold-out), in both modes and both enrichment settings."""
    from tests import eval as ev

    found = []
    for mode in ev.MODES:
        ev.apply_mode(mode)
        for enrichment in ("clean", "disabled"):
            for path, _label, _source in ev.collect(None):
                found.extend(ev.analyze(path, enrichment).findings)
    ev.apply_mode("configured")
    return found


@pytest.fixture(scope="module")
def corpus_findings():
    return _corpus_findings()


@pytest.mark.slow
def test_every_code_produced_over_the_fixtures_and_the_tuning_corpus_is_registered_and_matches_its_kind(corpus_findings):
    assert corpus_findings, "the corpus produced no findings at all"
    problems = []
    for f in corpus_findings:
        kind = BY_CODE.get(f.code or "")
        if kind is None:
            problems.append(("unregistered or missing code", f.module, f.code))
            continue
        if kind.module != f.module:
            problems.append(("module", f.code, f.module))
        if f.severity != kind.severity and not kind.severity_varies:
            problems.append(("severity", f.code, f.severity))
        if f.evidence.get("structural") is True and (f.evidence.get("family"), f.evidence.get("signal")) != (kind.family, kind.signal):
            problems.append(("family/signal", f.code))
    assert problems == [], sorted(set(problems))  # no titles or evidence in the message: they can hold a host from a real sample


@pytest.mark.slow
def test_the_same_kind_gets_the_same_code_whatever_its_title_says(corpus_findings):
    """Titles that carry an indicator (a host, a hash, a brand) differ from message to message; their code must not.
    The shared-platform, internal-host and provider-gap kinds share the 'Enrichment incomplete for <x>' title shape on purpose (scoring reads the
    prefix), so for them the title cannot name the kind: that is what the code is for. Every other title maps to exactly one code."""
    titles_by_code: dict[str, set[str]] = {}
    for f in corpus_findings:
        titles_by_code.setdefault(f.code, set()).add(f.title)
    codes_by_title: dict[str, set[str]] = {}
    for code_, titles in titles_by_code.items():
        for title in titles:
            codes_by_title.setdefault(title, set()).add(code_)
    shared_shape = "Enrichment incomplete for "
    assert sum(1 for t, cs in codes_by_title.items() if len(cs) > 1 and not t.startswith(shared_shape)) == 0  # a count only: a title can hold a real host
    assert any(len(titles) > 1 for titles in titles_by_code.values()), "the corpus never varied a title under one code"


def test_the_same_kind_gets_the_same_code_with_different_brands_and_hosts():
    from app.content_analysis import _brand_impersonation_finding
    from app.enrichment import _internal_finding

    a = _brand_impersonation_finding([{"brand": "Zorblaxbank", "anchor_text": "x", "domain": "one.example"}])
    b = _brand_impersonation_finding([{"brand": "Quuxpay", "anchor_text": "y", "domain": "two.example"}])
    assert a.title != b.title and a.code == b.code == "CONTENT_BRAND_LINK_MISMATCH"
    h1, h2 = _internal_finding("alpha.corp.example"), _internal_finding("beta.corp.example")
    assert h1.title != h2.title and h1.code == h2.code == "ENRICH_INCOMPLETE_INTERNAL_HOST"


def test_no_code_contains_a_value_taken_from_the_message():
    """A message with a distinctive brand, host and address: none of it may appear in any code that comes out."""
    from app.contracts.email import EmailAddress, ExtractedUrl, ParsedEmail
    from tests import eval as ev

    marker_brand, marker_host, marker_local = "Zqvxbrandmark", "zqvxhostmark.example", "zqvxaddrmark"
    parsed = ParsedEmail(
        source_format="eml",
        from_=EmailAddress(address=f"{marker_local}@{marker_host}", domain=marker_host, display_name=f"{marker_brand} Support"),
        subject=f"{marker_brand} account notice",
        body_text=f"Dear customer, {marker_brand} says act immediately: verify your account now at https://{marker_host}/x",
        urls=[ExtractedUrl(url=f"https://{marker_host}/x", source="body_text", anchor_text=f"{marker_brand}.com")],
        raw_size_bytes=100,
    )
    ev.apply_mode("configured")
    findings = ev.analyze_parsed(parsed, "clean").findings
    assert findings and all(f.code for f in findings)
    haystack = " ".join(f.code for f in findings).lower()
    for marker in (marker_brand, marker_host, marker_local, "zqvx"):
        assert marker.lower() not in haystack
    assert all(CODE_PATTERN.match(f.code) for f in findings)


def test_no_registered_code_contains_a_known_brand_a_platform_name_or_a_host_label():
    from app.shared.brands import KNOWN_BRANDS

    tokens = {t for code_ in BY_CODE for t in code_.lower().split("_")}
    brand_words = {w for name in KNOWN_BRANDS for w in re.split("[^a-z0-9]+", name.lower()) if len(w) >= 4}
    assert sorted(tokens & brand_words) == []
