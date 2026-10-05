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

# Files that still construct a Finding without a code. Each producer commit removes its files from this set; it ends empty.
NOT_YET = {
    "app/content_analysis/__init__.py", "app/content_analysis/links.py",
}


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


def test_every_finding_construction_site_passes_a_code_except_the_files_not_yet_converted():
    missing = _construction_sites_without_a_code()
    unexpected = {f: lines for f, lines in missing.items() if f not in NOT_YET}
    assert unexpected == {}, f"a Finding is built without code=: {unexpected}"
    converted_but_listed = sorted(f for f in NOT_YET if f not in missing)
    assert converted_but_listed == [], f"these files are fully converted: remove them from NOT_YET: {converted_but_listed}"
