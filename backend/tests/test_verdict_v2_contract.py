"""The verdict_v2 and checks_completed contract and its fixed wording (app/contracts/analysis.py, app/verdict_v2_text.py): additive, content-free, and the V1 word ban applies to every string."""
import json
import re
import typing
from pathlib import Path

import pytest

from app import verdict_v2_text as T
from app.contracts.analysis import AnalysisResult, ChecksCompleted, TierKey, V2Blocker, V2HardEvidence, V2Reason, VerdictV2
from app.finding_codes import BY_CODE
from app.reason_classes import REASON_TABLE

ROOT = Path(__file__).resolve().parents[2]
BANNED = re.compile(r"\b(safe|clean|legit|benign|harmless)\b", re.IGNORECASE)
BLOCKERS = json.loads((ROOT / "backend" / "tests" / "fixtures" / "blocker_codes_frozen.json").read_text(encoding="utf-8"))["codes"]
DETAILS = json.loads((ROOT / "backend" / "tests" / "fixtures" / "blocker_details_frozen.json").read_text(encoding="utf-8"))["details"]


def _all_strings() -> list[str]:
    out = list(T.TIER_LABELS.values()) + list(T.PSEUDO_REASON_TEXT.values()) + list(T.HARD_EVIDENCE_TEXT.values()) + list(T.DETAIL_TEXT.values())
    for text, how in T.BLOCKER_TEXT.values():
        out += [text, how]
    out += list(T.BLOCKER_HOW_TO_CLEAR_BY_DETAIL.values())
    return out


# ---- the labels -------------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_the_four_labels_are_exactly_the_pre_registered_ones():
    assert T.TIER_LABELS == {"confirmed_malicious": "Confirmed malicious", "suspicious": "Suspicious", "needs_analyst": "Needs analyst", "no_indicators_found": "No indicators found"}
    assert set(T.TIER_KEYS.values()) == set(typing.get_args(TierKey)) == set(T.TIER_LABELS)
    assert T.TIER_KEYS == {"T1": "confirmed_malicious", "T2": "suspicious", "T3": "needs_analyst", "T4": "no_indicators_found"}
    assert T.tier_label("no_indicators_found") == "No indicators found"


def test_no_string_of_verdict_v2_contains_a_word_the_v1_ban_forbids():
    assert [s for s in _all_strings() if BANNED.search(s)] == []
    assert [d.description for d in BY_CODE.values() if BANNED.search(d.description)] == []  # the registry templates reused as reason text


# ---- the wording is complete and content-free -----------------------------------------------------------------------------------------------------------------------

def test_every_blocker_code_has_a_text_and_a_how_to_clear_and_every_detail_has_a_phrase():
    assert set(T.BLOCKER_TEXT) == set(BLOCKERS)
    assert all(text.strip() and how.strip() for text, how in T.BLOCKER_TEXT.values())
    assert set(T.DETAIL_TEXT) == set(DETAILS)


def test_blocker_text_adds_the_detail_phrase_and_the_receiver_how_to_clear_depends_on_the_detail():
    text, how = T.blocker_text("static_analysis_off", "pdf")
    assert text.endswith("(a PDF)") and how
    plain, _ = T.blocker_text("qr_not_decoded", None)
    assert "(" not in plain
    _t, configured = T.blocker_text("no_trusted_receiver_hop", "not_configured")
    _t, matching = T.blocker_text("no_trusted_receiver_hop", "no_matching_hop")
    assert "TRUSTED_RECEIVER_PATTERNS" in configured and configured != matching


def test_every_pseudo_reason_has_text_and_a_kind_and_every_hard_evidence_rule_has_text():
    assert set(T.PSEUDO_REASON_TEXT) == set(T.PSEUDO_REASON_KIND)
    assert set(T.PSEUDO_REASON_KIND.values()) <= {"score", "evidence_conflict", "gap", "positive_evidence"}
    assert set(T.HARD_EVIDENCE_TEXT) == {"H1", "H2", "H3"}


def test_the_fixed_strings_carry_no_placeholder_address_url_or_ip():
    for text in _all_strings():
        assert not re.search(r"<[^>]+>|https?://|@|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", text), text


def test_every_finding_reason_text_comes_from_the_content_free_registry_template_never_from_a_title():
    counting = [code for code, entry in REASON_TABLE.items() if entry.counts_as_reason]
    assert counting
    for code in counting:
        assert BY_CODE[code].description.strip()  # the text a finding reason will use: a registry template (placeholders, no real value)


# ---- the models ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

def test_the_models_accept_a_full_verdict_and_reject_an_unknown_tier_or_rule():
    verdict = VerdictV2(
        tier="suspicious", label="Suspicious", route="R1",
        reasons=[V2Reason(kind="finding", code="AUTH_CLAIM_DECOY_LINKS", text="x", evidence_ref="3")],
        hard_evidence=[V2HardEvidence(code="H2", indicator="hxxps://evil[.]example", source="threatfox")],
        blockers=[V2Blocker(code="shared_platform", text="x", how_to_clear="y")], needs_analyst_reason=None, priority=None)
    assert verdict.model_dump()["tier"] == "suspicious" and verdict.blockers[0].detail is None
    with pytest.raises(Exception):
        VerdictV2(tier="malicious", label="x", route="R1")
    with pytest.raises(Exception):
        V2HardEvidence(code="H4", indicator="x", source="y")
    with pytest.raises(Exception):
        V2Reason(kind="opinion", code="x", text="y")


def test_checks_completed_has_the_four_counts():
    assert set(ChecksCompleted(completed=7, total=10, not_checked=3, by_design=3).model_dump()) == {"completed", "total", "not_checked", "by_design"}


def test_the_new_fields_are_optional_and_additive_so_an_older_result_still_parses_and_the_v1_fields_are_unchanged():
    from app.contracts.email import EmailAddress, ParsedEmail

    old = AnalysisResult(parsed_email=ParsedEmail(source_format="eml", from_=EmailAddress(), raw_size_bytes=1))
    assert old.verdict_v2 is None and old.checks_completed is None
    assert set(AnalysisResult.model_fields) >= {"verdict", "score", "confidence", "scoring", "findings", "module_results", "llm_opinion", "indicators", "evidence", "coverage_report"}
    assert AnalysisResult.model_fields["verdict"].annotation == typing.Optional[typing.Literal["malicious", "suspicious", "benign", "inconclusive"]]


def test_the_frontend_types_declare_only_optional_fields_for_verdict_v2():
    types = (ROOT / "frontend" / "src" / "types.ts").read_text(encoding="utf-8")
    assert "verdict_v2?: VerdictV2 | null" in types and "checks_completed?: ChecksCompleted | null" in types
    for tier in ("confirmed_malicious", "suspicious", "needs_analyst", "no_indicators_found"):
        assert f"'{tier}'" in types
    assert not re.search(r"^\s+verdict_v2: ", types, re.MULTILINE), "verdict_v2 must stay optional"
