"""The slow marker (backend/pytest.ini, backend/conftest.py): registered, skipped by the fast default, run by --run-slow, and carried by exactly the tests that are meant to have it."""
import ast
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

# The tests that take more than about five seconds (the call, or the setup of a fixture they share). A change to this set is a deliberate edit here and in the test files.
EXPECTED_SLOW = {
    ("test_verdict_v2_pipeline.py", "test_all_856_rows_give_the_predicted_tier_and_route_through_the_real_pipeline"),
    ("test_tier_parity.py", "test_a_class_based_recompute_and_compute_tier_equal_the_predictor_on_all_856_rows"),
    ("test_wording_enforced.py", "test_the_runtime_scan_over_the_local_tuning_corpus_finds_nothing"),
    ("test_finding_codes.py", "test_every_code_produced_over_the_fixtures_and_the_tuning_corpus_is_registered_and_matches_its_kind"),
    ("test_finding_codes.py", "test_the_same_kind_gets_the_same_code_whatever_its_title_says"),
    ("test_report_blocker_inputs.py", "test_the_report_prints_aggregates_only_and_no_content"),
    ("test_report_blocker_inputs.py", "test_the_report_counts_the_receiver_blocker_on_every_message_in_strict"),
    ("test_verdict_v2_pipeline.py", "test_every_existing_section_of_the_real_pipeline_output_is_byte_identical_to_the_snapshot_taken_before_verdict_v2"),
    ("test_verdict_v2_pipeline.py", "test_the_as_is_clean_rows_give_the_predicted_tier_and_route_through_the_real_pipeline"),
    ("test_verdict_v2_pipeline.py", "test_v2_t4_never_comes_with_a_blocker"),
    ("test_verdict_v2_pipeline.py", "test_v3_and_v15_confirmed_malicious_only_with_hard_evidence_each_with_an_indicator_and_a_source"),
    ("test_verdict_v2_pipeline.py", "test_v14_every_tier_has_a_non_empty_reasons_list_or_hard_evidence_and_every_reason_has_text"),
    ("test_verdict_v2_pipeline.py", "test_the_label_matches_the_tier_and_the_priority_is_set_only_for_needs_analyst"),
    ("test_verdict_v2_pipeline.py", "test_v16_a_parser_failure_never_gives_no_indicators_found"),
    ("test_verdict_v2_pipeline.py", "test_print_the_tier_counts_by_mode_for_the_report"),
    ("test_verdict_v2_pipeline.py", "test_every_string_of_verdict_v2_on_the_live_output_passes_the_v1_word_ban"),
    ("test_regression_baseline.py", "test_the_pipeline_still_reproduces_the_recorded_tier_columns_for_the_tuning_rows"),
    ("test_regression_baseline.py", "test_the_pipeline_still_reproduces_the_tuning_rows"),
    ("test_v2_inputs.py", "test_the_positive_flags_agree_with_the_v1_gap_list_on_every_fixture_and_tuning_message_in_both_modes"),
    ("test_blockers_end_to_end.py", "test_the_counts_equal_the_step_9_report_except_for_the_documented_receiver_fix"),
    ("test_blockers_end_to_end.py", "test_the_adapter_equals_the_report_script_on_every_fixture_and_tuning_message_in_both_modes"),
    ("test_tier_parity.py", "test_a_class_based_recompute_and_compute_tier_equal_the_predictor_on_the_as_is_clean_rows"),
    ("test_predicted_tiers.py", "test_the_as_is_clean_rows_recompute_to_the_committed_prediction"),
    ("test_verdict_v2_unavailable.py", "test_every_fixture_in_both_modes_says_ok"),
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
