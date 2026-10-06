"""The reason-class table (app/reason_classes.py, docs/DESIGN_V2.md D16 and D22): data plus the rules that pin it. Only scoring/tiers.py uses it."""
import ast
import json
from pathlib import Path

from app.finding_codes import BY_CODE, REGISTRY
from app.reason_classes import CLASSES, REASON_CLASS, REASON_TABLE, UNTAGGED_CLASSES

BACKEND = Path(__file__).resolve().parents[1]
FROZEN = BACKEND / "tests" / "fixtures" / "reason_classes_frozen.json"
SCORING = BACKEND / "app" / "scoring"


def test_the_closed_set_of_classes_is_exactly_the_six_of_d22():
    assert CLASSES == ("auth", "enrichment", "content", "sender", "link", "claim")
    assert set(UNTAGGED_CLASSES) == {"auth", "enrichment", "content"}


def test_every_registry_code_has_a_class_and_no_class_exists_for_an_unknown_code():
    assert sorted(set(BY_CODE) - set(REASON_CLASS)) == [], "a finding code has no reason class"
    assert sorted(set(REASON_CLASS) - set(BY_CODE)) == [], "a reason class exists for a code that is not in the registry"
    assert len(REASON_CLASS) == len(REGISTRY)  # a dict key is unique, so one entry per code means exactly one class


def test_every_class_is_in_the_closed_set():
    assert [c for c, cls in REASON_CLASS.items() if cls not in CLASSES] == []


def test_a_code_with_a_family_tag_takes_that_tag_as_its_class_whatever_module_builds_it():
    tagged = [k for k in REGISTRY if k.family is not None]
    assert tagged, "the registry has no family-tagged kinds"
    assert [k.code for k in tagged if REASON_CLASS[k.code] != k.family] == []


def test_a_code_without_a_family_tag_takes_auth_enrichment_or_content():
    assert [k.code for k in REGISTRY if k.family is None and REASON_CLASS[k.code] not in UNTAGGED_CLASSES] == []


def test_no_untagged_code_is_given_a_family_class_and_no_family_class_is_given_to_an_untagged_code():
    family_classes = {"sender", "link", "claim"}
    assert [k.code for k in REGISTRY if k.family is None and REASON_CLASS[k.code] in family_classes] == []


def test_the_table_equals_the_frozen_snapshot_so_a_change_is_a_deliberate_edit_of_both():
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))["codes"]
    current = {c: {"class": e.cls, "counts_as_reason": e.counts_as_reason, "reason": e.reason} for c, e in REASON_TABLE.items()}
    assert sorted(set(frozen) - set(current)) == [], "a frozen code left the table"
    assert sorted(set(current) - set(frozen)) == [], "a code is not in tests/fixtures/reason_classes_frozen.json: add it there in the same commit"
    assert [c for c in frozen if frozen[c] != current[c]] == [], "a class, flag or reason changed: edit the snapshot in the same commit, on purpose"


# ---- eligibility: which kinds may ever count as a reason -----------------------------------------------------------------------------------

# Named, so a change is a decision: kinds that are never reasons although their severity is above info (a gap, a parse note, an untrusted claim).
NEVER_REASONS_ABOVE_INFO = {
    "AUTH_FROM_HEADER_AMBIGUOUS",                 # parse note, weight 0
    "ENRICH_SKIPPED_PER_EMAIL_LIMIT",             # gap: not looked up
    "AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED",         # authentication result below the trust boundary
    "AUTH_DKIM_FAILURE_CLAIMED_UNTRUSTED",
    "AUTH_DMARC_FAILURE_CLAIMED_UNTRUSTED",
    "AUTH_ALIGN_NONE_ALIGNED_FALLBACK",           # the compared domain came from a header the sender writes, not from the trusted result
}
# Gaps and notes by name (all info severity except where listed above): never eligible.
GAPS_AND_NOTES = {
    "AUTH_SPF_NOT_EVALUATED", "AUTH_DKIM_NOT_EVALUATED", "AUTH_DMARC_NOT_EVALUATED", "AUTH_UNTRUSTED_CLAIMS_IGNORED",
    "AUTH_SPF_TRUSTED_RESULT_BELOW_HOP", "AUTH_DKIM_TRUSTED_RESULT_BELOW_HOP", "AUTH_DMARC_TRUSTED_RESULT_BELOW_HOP",
    "ENRICH_INCOMPLETE_PROVIDER_NO_RESULT", "ENRICH_INCOMPLETE_INTERNAL_HOST", "ENRICH_INCOMPLETE_SHARED_PLATFORM", "ENRICH_PROVIDERS_NO_USABLE_ANSWER",
    "CONTENT_LANGUAGE_UNSUPPORTED", "CONTENT_LANGUAGE_NO_TEXT", "CONTENT_LANGUAGE_UNDETERMINED",
} | NEVER_REASONS_ABOVE_INFO


def test_every_code_has_the_flag_and_a_short_content_free_reason():
    for code, entry in REASON_TABLE.items():
        assert isinstance(entry.counts_as_reason, bool), code
        assert 10 <= len(entry.reason) <= 160, code
        assert not any(ch in entry.reason for ch in "<>@\\"), f"{code}: the reason must be plain text without values or placeholders"


def test_info_default_kinds_are_never_eligible():
    info_default = [k.code for k in REGISTRY if k.severity == "info" and not k.severity_varies]
    assert info_default, "the registry has no info-default kinds"
    assert [c for c in info_default if REASON_TABLE[c].counts_as_reason] == []


def test_a_kind_whose_severity_varies_may_count_because_the_router_applies_the_above_info_rule_to_the_produced_severity():
    varying = {k.code for k in REGISTRY if k.severity_varies}
    assert varying == {"AUTH_SPF_CHECK_FAILED", "AUTH_DKIM_CHECK_FAILED", "AUTH_DMARC_CHECK_FAILED", "ENRICH_REPUTATION_HOST_SUSPICIOUS",
                       "ENRICH_REPUTATION_HASH_KNOWN_MALICIOUS", "CONTENT_URGENCY_LANGUAGE"}
    assert all(REASON_TABLE[c].counts_as_reason for c in varying)  # their severity is never info, so the kind may count; the produced severity decides each case


def test_gaps_notes_and_untrusted_claims_are_never_eligible_by_name():
    assert sorted(GAPS_AND_NOTES - set(REASON_TABLE)) == [], "a named gap or note is not a code in the table"
    assert [c for c in sorted(GAPS_AND_NOTES) if REASON_TABLE[c].counts_as_reason] == []


def test_the_exclusions_are_exactly_the_info_default_kinds_plus_the_named_above_info_ones():
    info_default = {k.code for k in REGISTRY if k.severity == "info" and not k.severity_varies}
    not_counting = {c for c, e in REASON_TABLE.items() if not e.counts_as_reason}
    assert not_counting == info_default | NEVER_REASONS_ABOVE_INFO
    assert NEVER_REASONS_ABOVE_INFO.isdisjoint(info_default)
    assert info_default <= GAPS_AND_NOTES | {"AUTH_ALL_METHODS_PASSED", "AUTH_ALIGN_SPF_ALIGNED", "AUTH_ALIGN_SPF_OTHER_DOMAIN",
                                             "AUTH_ALIGN_DKIM_ALIGNED", "AUTH_ALIGN_DKIM_OTHER_DOMAIN", "AUTH_CLAIM_BODY_BRAND_MENTION"}


def test_an_excluded_kind_says_why():
    for code, entry in REASON_TABLE.items():
        if not entry.counts_as_reason:
            assert any(word in entry.reason.lower() for word in ("info severity", "gap", "parse note", "untrusted claim", "message-controlled")), code


# ---- only scoring/tiers.py uses the table, and nothing uses the tier function yet --------------------------------------------------------------------

def _imports_module(source: str, name: str) -> bool:
    """True if the module imports a module called `name` in any spelling: absolute, from-package, or relative."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[-1] == name for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[-1] == name:
                return True
            if any(alias.name == name for alias in node.names):
                return True
    return False


def _imports_the_table(source: str) -> bool:
    return _imports_module(source, "reason_classes")


def test_the_import_check_recognises_every_spelling_of_the_import():
    for source in ("import app.reason_classes", "from app.reason_classes import REASON_CLASS", "from app import reason_classes",
                   "from .. import reason_classes", "from ..reason_classes import CLASSES", "import app.reason_classes as rc"):
        assert _imports_the_table(source), source
    assert not _imports_the_table("from app.finding_codes import code")
    assert _imports_module("from app.scoring.tiers import compute_tier", "tiers") and _imports_module("from app.scoring import tiers", "tiers")
    assert not _imports_module("from app.scoring.config import ScoringConfig", "tiers")


def test_exactly_the_tier_function_and_the_two_v2_builders_import_the_reason_class_table():
    files = sorted((BACKEND / "app").rglob("*.py"))
    assert files, "backend/app has no modules: the path is wrong"
    importers = [p.relative_to(BACKEND).as_posix() for p in files if _imports_the_table(p.read_text(encoding="utf-8"))]
    assert importers == ["app/scoring/tiers.py", "app/scoring/v2_inputs.py", "app/scoring/v2_verdict.py"]


def test_only_the_pipeline_imports_the_tier_function():
    """verdict_v2 is computed in api/pipeline.py and nowhere else; the frontend only has the optional types (no component uses verdict_v2 until the UI step)."""
    files = sorted((BACKEND / "app").rglob("*.py"))
    assert [p.relative_to(BACKEND).as_posix() for p in files if _imports_module(p.read_text(encoding="utf-8"), "tiers")] == ["app/api/pipeline.py"]
    frontend = BACKEND.parent / "frontend" / "src"
    users = [p.relative_to(frontend).as_posix() for p in frontend.rglob("*") if p.suffix in (".ts", ".tsx") and "verdict_v2" in p.read_text(encoding="utf-8", errors="ignore")]
    assert users == ["types.ts"], "only the optional types in types.ts may mention verdict_v2: no component uses it until the UI step"


def test_the_trusted_and_the_fallback_none_aligned_kinds_are_split_by_where_the_compared_domain_came_from():
    trusted, fallback = REASON_TABLE["AUTH_ALIGN_NONE_ALIGNED"], REASON_TABLE["AUTH_ALIGN_NONE_ALIGNED_FALLBACK"]
    assert (trusted.cls, trusted.counts_as_reason) == ("auth", True)
    assert (fallback.cls, fallback.counts_as_reason) == ("auth", False)
    assert BY_CODE["AUTH_ALIGN_NONE_ALIGNED"].severity == BY_CODE["AUTH_ALIGN_NONE_ALIGNED_FALLBACK"].severity == "medium"
