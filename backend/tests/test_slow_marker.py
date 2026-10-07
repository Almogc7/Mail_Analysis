"""The slow marker (backend/pytest.ini, backend/conftest.py): registered, skipped by the fast default, run by --run-slow, and carried by exactly the tests that are meant to have it."""
import ast
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

# The tests that take about fifteen seconds or more. A change to this set is a deliberate edit here and in the test files.
EXPECTED_SLOW = {
    ("test_verdict_v2_pipeline.py", "test_all_856_rows_give_the_predicted_tier_and_route_through_the_real_pipeline"),
    ("test_tier_parity.py", "test_a_class_based_recompute_and_compute_tier_equal_the_predictor_on_all_856_rows"),
    ("test_wording_enforced.py", "test_the_runtime_scan_over_the_local_tuning_corpus_finds_nothing"),
    ("test_finding_codes.py", "test_every_code_produced_over_the_fixtures_and_the_tuning_corpus_is_registered_and_matches_its_kind"),
    ("test_finding_codes.py", "test_the_same_kind_gets_the_same_code_whatever_its_title_says"),
}


def _slow_tests() -> set[tuple[str, str]]:
    found = set()
    for path in sorted((BACKEND / "tests").glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef) and any(ast.unparse(d) == "pytest.mark.slow" for d in node.decorator_list):
                found.add((path.name, node.name))
    return found


def test_the_marker_is_registered_in_the_pytest_config():
    text = (BACKEND / "pytest.ini").read_text(encoding="utf-8")
    assert "markers" in text and "slow:" in text


def test_exactly_the_intended_tests_carry_the_slow_marker():
    assert _slow_tests() == EXPECTED_SLOW


def test_the_conftest_skips_slow_tests_by_default_and_runs_them_with_the_option_or_the_environment():
    source = (BACKEND / "conftest.py").read_text(encoding="utf-8")
    assert '"--run-slow"' in source and 'RUN_SLOW' in source and 'item.add_marker(skip)' in source


def test_the_readme_documents_both_commands():
    readme = (BACKEND.parent / "README.md").read_text(encoding="utf-8")
    assert "pytest --run-slow" in readme and "the FAST default" in readme and "the FULL run" in readme
    assert "known-sender conflict by design of the harness" in readme
