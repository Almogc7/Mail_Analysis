"""The V1 word-ban lint (scripts/check_wording.py) is REPORT ONLY. These tests prove the lint finds what it must and exempts what it must; they do NOT
assert that the repository is free of banned words (it is not yet: the wording cleanup comes next), and nothing here can make the suite fail on a hit."""
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_wording.py"
spec = importlib.util.spec_from_file_location("check_wording", SCRIPT)
cw = importlib.util.module_from_spec(spec)
sys.modules["check_wording"] = cw  # dataclasses with postponed annotations look the module up by name
spec.loader.exec_module(cw)

HAS_NODE = shutil.which("node") is not None and (ROOT / "frontend" / "node_modules" / "typescript").is_dir()


def words(refs, in_scope_only=True):
    return sorted({(r.kind, w) for r in refs if r.in_scope or not in_scope_only for w in cw.find_banned(r.text)})


# ---- the rule: whole words, case-insensitive ----------------------------------------------------------------------------------

@pytest.mark.parametrize("word", ["safe", "clean", "legit", "benign", "harmless"])
def test_each_banned_word_is_found_in_any_case_and_next_to_punctuation(word):
    for text in (f"it is {word}", f"It Is {word.upper()}.", f"({word.capitalize()}):", f"a {word}, b", f"not {word}!"):
        assert cw.find_banned(text) == [word], text


@pytest.mark.parametrize("text", [
    "not evidence of safety", "this is unsafe", "cleanse the list", "cleaning up", "a legitimate sender", "benignly", "harmlessly", "safety verdict",
    "no_clean_here", "safe_links_key", "disclean", "Safelinks",
])
def test_safety_and_other_longer_words_are_not_matched(text):
    assert cw.find_banned(text) == []


def test_a_hyphen_is_a_word_boundary_so_a_css_hook_would_match_which_is_why_class_names_are_exempt_by_context():
    assert cw.find_banned("verdict-benign") == ["benign"]


def test_several_banned_words_in_one_string_are_all_reported_in_order():
    assert cw.find_banned("not clean, not safe and not Benign") == ["clean", "safe", "benign"]


# ---- scope: backend strings ------------------------------------------------------------------------------------------------------

LOGGING_SOURCE = '''
import logging
logger = logging.getLogger("x")
def f(n):
    logger.warning("the rest is UNKNOWN, not clean (%s)", n)
'''


def test_a_banned_word_in_a_log_call_is_found_in_any_module_even_out_of_scope():
    refs, _ = cw.py_string_refs(LOGGING_SOURCE, "backend/app/parser/x.py", in_scope_file=False)
    assert ("log message", "clean") in words(refs)


def test_a_banned_word_in_finding_text_is_found():
    src = 'def f():\n    return Finding(title="Looks fine", description="This is not a clean header and the sender is legit.", severity="low")\n'
    refs, _ = cw.py_string_refs(src, "backend/app/auth_check/x.py", True)
    assert words(refs) == [("api text (description)", "clean"), ("api text (description)", "legit")]


def test_a_banned_word_in_a_print_and_in_an_http_error_is_found():
    src = 'def f():\n    print("suspected false negatives (disagreed benign verdicts)")\n    raise HTTPException(status_code=400, detail="that is not safe")\n'
    kinds = words(cw.py_string_refs(src, "backend/app/feedback.py", True)[0])
    assert ("cli output", "benign") in kinds and ("api error", "safe") in kinds


def test_prose_in_a_finding_producing_module_is_found_even_without_a_keyword():
    refs, _ = cw.py_string_refs('NOTE = "No source gave a usable answer, so this is UNKNOWN, not clean."\n', "backend/app/indicators.py", True)
    assert words(refs) == [("prose literal", "clean")]


def test_docstrings_and_comments_are_not_strings_of_the_program():
    src = '"""Module text that says clean and safe."""\n# a comment that says benign\ndef f():\n    """Docstring: legit and harmless."""\n    return 1\n'
    refs, tokens = cw.py_string_refs(src, "backend/app/auth_check/x.py", True)
    assert refs == [] and tokens == []


def test_exception_messages_and_out_of_scope_prose_are_listed_but_not_in_scope():
    src = 'def f():\n    raise ValueError("this value is not clean")\nX = "this config note says safe enough"\n'
    in_scope = cw.py_string_refs(src, "backend/app/parser/x.py", False)[0]
    assert all(not r.in_scope for r in in_scope) and len(in_scope) == 2
    raised = cw.py_string_refs(src, "backend/app/auth_check/x.py", True)[0]
    assert [r.in_scope for r in raised if r.kind == "exception message"] == [False]


def test_single_word_tokens_are_exempt_but_counted_not_silently_dropped():
    src = 'VERDICT = "benign"\nKEYS = {"harmless": 1}\nOTHER = "ordinary"\n'
    refs, tokens = cw.py_string_refs(src, "backend/app/scoring/x.py", True)
    assert refs == [] and sorted(t.text for t in tokens) == ["benign", "harmless"]


def test_an_fstring_that_interpolates_a_verdict_value_is_flagged_because_benign_can_appear_at_runtime():
    src = 'def f(bucket):\n    return f"too incomplete to trust a {bucket} call."\n'
    refs, _ = cw.py_string_refs(src, "backend/app/scoring/overrides.py", True)
    possible = cw.possible_hits(refs)
    assert len(possible) == 1 and "{bucket}" in possible[0].text
    assert cw.static_hits(refs, frozenset()) == []  # it is reported in its own section, not as a literal hit


# ---- exemptions: the allowlist, by exact string ----------------------------------------------------------------------------------

def test_an_allowlisted_negated_disclaimer_passes_by_exact_string_only():
    text = "This proves who signed it, not that the content is safe."
    ref = [cw.StringRef("backend/app/auth_check/x.py", 1, "api text (description)", text)]
    assert len(cw.static_hits(ref, frozenset())) == 1
    allowed = frozenset({cw.normalise(text)})
    assert cw.static_hits(ref, allowed) == []
    assert cw.static_hits([cw.StringRef("f", 1, "api text (description)", text + " Really.")], allowed) != []  # a near-miss is still a hit
    assert cw.static_hits([cw.StringRef("f", 1, "api text (description)", "  " + text.replace(" ", "   ") + " ")], allowed) == []  # whitespace is normalised


def test_the_shipped_allowlist_is_valid_json_and_empty_until_the_cleanup_decides():
    data = json.loads((ROOT / "scripts" / "wording_allowlist.json").read_text(encoding="utf-8"))
    assert data["allowed_exact_strings"] == [] and cw.load_allowlist() == frozenset()


def test_a_missing_allowlist_file_means_no_exemptions(tmp_path):
    assert cw.load_allowlist(tmp_path / "nope.json") == frozenset()


# ---- scope: the produced payload, and the V18 idea (provider field names only inside the raw-data block) -------------------------

def payload(**over):
    base = {"verdict": "inconclusive", "findings": [], "module_results": [], "scoring": {"applied_overrides": []}, "coverage_report": [], "indicators": {"indicators": []},
            "evidence": {"links": [], "attachments": [], "images": [], "sender": {}, "hop_timeline": []}, "parsed_email": {"subject": "a clean safe benign legit message"}}
    base.update(over)
    return base


def test_the_provider_field_name_passes_inside_the_raw_data_block_but_the_same_word_in_a_label_or_reason_fails():
    inside = payload(module_results=[{"module": "enrichment", "raw_data": {"example.org": {"virustotal": {"harmless": 3, "note": "harmless"}}}, "findings": []}])
    assert cw.scan_payload(inside) == []
    in_label = payload(findings=[{"title": "Looks harmless to me", "description": "d", "evidence": {}}])
    assert [(h.path, h.word) for h in cw.scan_payload(in_label)] == [("findings[*].title", "harmless")]
    in_reason = payload(scoring={"applied_overrides": [{"rule": "r", "effect": "e", "reason": "The result is harmless."}]})
    assert [(h.path, h.word) for h in cw.scan_payload(in_reason)] == [("scoring.applied_overrides[*].reason", "harmless")]


def test_a_banned_word_used_as_a_field_name_outside_the_raw_data_block_fails():
    hits = cw.scan_payload(payload(coverage_report=[{"area": "x", "harmless": 1}]))
    assert [(h.kind, h.word) for h in hits] == [("field name", "harmless")]


def test_message_content_is_never_a_hit_and_the_frozen_v1_value_is_exempt():
    assert cw.scan_payload(payload()) == []  # the subject says clean safe benign legit: it is the sender's text
    assert cw.scan_payload(payload(verdict="benign")) == []
    assert cw.scan_payload(payload(indicators={"indicators": [{"value": "safe.example", "filename": "clean.pdf", "note": "fine"}]})) == []
    links = {"links": [{"url": "x", "host": "safe.example", "display_text": "a clean offer", "platform": None}], "attachments": [], "images": [], "sender": {}, "hop_timeline": []}
    assert cw.scan_payload(payload(evidence=links)) == []
    assert [h.word for h in cw.scan_payload(payload(verdict="a benign verdict"))] == ["benign"]  # only the exact v1 literal is exempt


def test_an_application_note_next_to_message_content_still_fails():
    hits = cw.scan_payload(payload(indicators={"indicators": [{"value": "x", "note": "UNKNOWN, not clean."}]}))
    assert [(h.path, h.word) for h in hits] == [("indicators.indicators[*].note", "clean")]


def test_a_finding_evidence_value_is_reported_withheld_because_it_may_hold_message_text():
    hits = cw.scan_payload(payload(findings=[{"title": "t", "description": "d", "evidence": {"platform": "Microsoft Safe Links", "k": "ok"}}]))
    assert [(h.kind, h.word, h.text) for h in hits] == [("finding evidence value (withheld)", "safe", "")]


def test_the_allowlist_applies_to_payload_strings_too():
    p = payload(findings=[{"title": "t", "description": "It does not show the message is safe.", "evidence": {}}])
    assert len(cw.scan_payload(p)) == 1
    assert cw.scan_payload(p, frozenset({cw.normalise("It does not show the message is safe.")})) == []


def test_a_runtime_hit_prints_the_template_with_quoted_message_text_masked_and_digits_masked():
    template = cw.mask_template("'secret-host.example' is on a list. It is UNKNOWN, not clean (17 hosts).", "clean")
    assert "secret-host" not in template and "17" not in template and "clean" in template


# ---- the text sent to the language model -----------------------------------------------------------------------------------------

def test_the_prompt_exempts_the_v1_verdict_literal_but_not_a_banned_word_in_a_title():
    assert cw.scan_prompt("Verdict: benign (score=3/100)\nFindings (titles only):\n(none)") == []
    hits = cw.scan_prompt("Verdict: inconclusive (score=3/100)\n[auth_check/low] The header is not clean")
    assert [(h.kind, h.word) for h in hits] == [("llm prompt", "clean")]


# ---- scope: the frontend (needs node and the TypeScript compiler that the frontend already depends on) -----------------------------

TSX = '''
export function A() {
  const x: 'benign' | 'other' = 'other'
  console.warn('Heads up: this is not clean data')
  return (
    <div className="verdict benign" key="clean now" title="A safe place to look">
      <p>This message is legit and harmless</p>
      <span aria-label="Mark as clean">ok</span>
      {/* a comment about clean mail */}
      {x === 'benign' ? 'yes' : 'no'}
    </div>
  )
}
'''


@pytest.mark.skipif(not HAS_NODE, reason="node or the frontend TypeScript package is not installed")
def test_frontend_labels_text_titles_aria_labels_and_console_messages_are_found_and_internal_tokens_are_not(tmp_path):
    src = tmp_path / "src"
    (src / "test").mkdir(parents=True)
    (src / "Sample.tsx").write_text(TSX, encoding="utf-8")
    (src / "Sample.test.tsx").write_text("const t = 'a clean and safe test string'\n", encoding="utf-8")
    (src / "test" / "helper.ts").write_text("export const h = 'a clean and safe helper string'\n", encoding="utf-8")
    refs, tokens, warning = cw.frontend_refs(ROOT, src)
    assert warning == ""
    found = sorted({(r.kind, w) for r in refs for w in cw.find_banned(r.text)})
    assert found == [("attribute aria-label", "clean"), ("attribute title", "safe"), ("jsx text", "harmless"), ("jsx text", "legit"), ("log message", "clean")]
    assert [t.text for t in tokens] == ["benign"]  # the comparison literal: counted as an exempt token, not a hit
    assert not any("Sample.test" in r.file or "helper" in r.file for r in refs)  # tests and the test/ helper folder are not scanned


@pytest.mark.skipif(not HAS_NODE, reason="node or the frontend TypeScript package is not installed")
def test_the_real_frontend_scan_runs_and_returns_something():
    refs, tokens, warning = cw.frontend_refs(ROOT)
    assert warning == "" and len(refs) > 50


# ---- proposals ------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("now, proposed", [
    ("It is UNKNOWN, not clean.", "It is UNKNOWN, not a pass."),
    ("Common in benign mail; it adds a little", "Common in ordinary mail; it adds a little"),
    ("it does not make the content safe.", "it does not show that the content can be trusted."),
    ("(disagreed 'benign' verdicts)", "(disagreed 'No indicators found' verdicts)"),
    ("evidence is too incomplete to trust a benign call.", "evidence is too incomplete to trust a 'No indicators found' call."),
    ("which is not the same as clean.", "which is not the same as a pass."),
])
def test_proposals_keep_the_meaning_and_remove_the_banned_word(now, proposed):
    out, basis = cw.propose(now)
    assert out == proposed and basis == "rule" and cw.find_banned(out) == []


def test_a_product_name_is_a_decision_not_a_mechanical_replacement():
    out, basis = cw.propose("Hosted on Microsoft Safe Links.")
    assert basis.startswith("decision") and cw.find_banned(out) == []


def test_a_string_without_a_specific_rule_falls_back_and_is_marked_for_review():
    out, basis = cw.propose("The sender is legit")
    assert basis == "review" and cw.find_banned(out) == []


# ---- the tests-that-assert lookup --------------------------------------------------------------------------------------------------

def test_only_assertion_like_lines_count_as_tests_that_assert_a_string(tmp_path):
    tests = tmp_path / "backend" / "tests"
    tests.mkdir(parents=True)
    (tests / "test_x.py").write_text('# the text says not clean here\n"""docstring: it is UNKNOWN, not clean"""\nassert "UNKNOWN, not clean" in text\n', encoding="utf-8")
    hit = cw.Hit("static", "f:1", "api text", "clean", "It is UNKNOWN, not clean.")
    cw.find_tests(tmp_path, [hit])
    assert hit.tests == ["backend/tests/test_x.py:3"]


# ---- report only ------------------------------------------------------------------------------------------------------------------------

def test_the_report_runs_on_the_repository_without_failing_even_though_hits_exist(capsys):
    assert cw.main(["--static", "--no-tests"]) == 0
    out = capsys.readouterr().out
    assert "REPORT ONLY" in out and "static hit(s)" in out


def test_strict_mode_exits_nonzero_only_when_a_hit_exists(tmp_path, capsys):
    app = tmp_path / "backend" / "app" / "auth_check"
    app.mkdir(parents=True)
    (app / "x.py").write_text('def f():\n    return Finding(description="This is not a clean header.")\n', encoding="utf-8")
    assert cw.main(["--static", "--no-tests", "--strict"], root=tmp_path) == 1
    (app / "x.py").write_text('def f():\n    return Finding(description="This is a malformed header.")\n', encoding="utf-8")
    assert cw.main(["--static", "--no-tests", "--strict"], root=tmp_path) == 0
    assert cw.main(["--static", "--no-tests"], root=tmp_path) == 0
    capsys.readouterr()


def test_the_lint_is_not_wired_into_the_pre_commit_hook():
    hook = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    assert "check_wording" not in hook
