"""The reason-class table (app/reason_classes.py, docs/DESIGN_V2.md D16 and D22): data plus the rules that pin it. No scoring code uses it yet."""
import ast
import json
from pathlib import Path

from app.finding_codes import BY_CODE, REGISTRY
from app.reason_classes import CLASSES, REASON_CLASS, UNTAGGED_CLASSES

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
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))["classes"]
    assert sorted(set(frozen) - set(REASON_CLASS)) == [], "a frozen code left the table"
    assert sorted(set(REASON_CLASS) - set(frozen)) == [], "a code is not in tests/fixtures/reason_classes_frozen.json: add it there in the same commit"
    assert [c for c in frozen if frozen[c] != REASON_CLASS[c]] == [], "a class changed: edit the snapshot in the same commit, on purpose"


# ---- nothing under scoring/ uses the table yet -----------------------------------------------------------------------------------------

def _imports_the_table(source: str) -> bool:
    """True if the module imports app.reason_classes in any spelling: absolute, from-app, or relative."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[-1] == "reason_classes" or alias.name.endswith("reason_classes") for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[-1] == "reason_classes":
                return True
            if any(alias.name == "reason_classes" for alias in node.names):
                return True
    return False


def test_the_import_check_recognises_every_spelling_of_the_import():
    for source in ("import app.reason_classes", "from app.reason_classes import REASON_CLASS", "from app import reason_classes",
                   "from .. import reason_classes", "from ..reason_classes import CLASSES", "import app.reason_classes as rc"):
        assert _imports_the_table(source), source
    assert not _imports_the_table("from app.finding_codes import code")


def test_nothing_under_scoring_imports_the_reason_class_table_yet():
    files = sorted(SCORING.rglob("*.py"))
    assert files, "scoring/ has no modules: the path is wrong"
    assert [p.relative_to(BACKEND).as_posix() for p in files if _imports_the_table(p.read_text(encoding="utf-8"))] == []
