"""Mutation tests on the sanitized Kvish fixture ONLY. Descriptive, not tuned: they pin down what the verdict depends on,
so a later change that alters the dependence shows up here. The table is in tests/KVISH_MUTATIONS.md."""
import pytest

from app.parser import parse_email_file
from tests import kvish_mutations as km
from tests.eval import FLAGGED

ALL = km.cases()


@pytest.fixture(scope="module")
def parsed():
    return parse_email_file(km.FIXTURE.read_bytes(), km.FIXTURE.name)


@pytest.fixture
def ablated(monkeypatch):
    from app.content_analysis import brand_impersonation
    from app.shared import brands

    monkeypatch.delitem(brands.KNOWN_BRANDS, "kvish6", raising=False)
    monkeypatch.delitem(brand_impersonation._BRAND_PATTERNS, "kvish6", raising=False)


def _ids(case):
    label, _, sender, origin = case
    return f"{origin}-{sender}-{label}"


@pytest.mark.parametrize("case", ALL, ids=_ids)
def test_the_verdict_is_flagged_exactly_when_two_families_fire_and_both_modes_agree(case, parsed, ablated):
    label, combo, sender, origin = case
    strict = km.run_case(parsed, combo, sender, "strict", origin)
    configured = km.run_case(parsed, combo, sender, "configured", origin)
    assert strict[0] == configured[0]  # no trusted authentication result exists in this fixture, so trust mode is irrelevant
    verdict, signals, families = strict
    assert (verdict in FLAGGED) == (len(families) >= 2), (verdict, signals)


def test_the_unmodified_fixture_is_flagged_with_and_without_the_seeds(parsed, ablated):
    verdict, signals, families = km.run_case(parsed, (), "as_is", "strict")
    assert verdict == "suspicious" and {"sender", "link", "claim"} <= set(families)


@pytest.mark.parametrize("sender", km.SENDERS)
def test_who_the_sender_appears_to_be_never_changes_the_verdict_while_the_origin_hop_is_a_local_submission(sender, parsed, ablated):
    for label, combo, s, origin in ALL:
        if origin == "local_submission" and s == sender:
            baseline = km.run_case(parsed, combo, "as_is", "strict", "local_submission")[0]
            assert km.run_case(parsed, combo, sender, "strict", "local_submission")[0] == baseline, label


def test_with_the_local_submission_origin_any_single_link_or_claim_signal_is_enough(parsed, ablated):
    for combo in (("no_display_name",), ("direct_cta",), ("no_hotlinked_images",), ("no_display_name", "direct_cta"),
                  ("no_display_name", "no_hotlinked_images"), ("direct_cta", "no_hotlinked_images")):
        assert km.run_case(parsed, combo, "as_is", "strict")[0] == "suspicious", combo


def test_remove_every_content_feature_and_only_the_local_submission_remains(parsed, ablated):
    verdict, signals, families = km.run_case(parsed, km.CONTENT_MUTATIONS, "as_is", "strict")
    assert (verdict, signals, families) == ("inconclusive", ["S2"], ["sender"])


def test_the_local_submission_hop_is_the_load_bearing_signal(parsed, ablated):
    """Replace only the origin hop with authenticated SMTP and the verdict now needs the link or claim signals to carry it."""
    nothing_left = km.run_case(parsed, km.CONTENT_MUTATIONS, "as_is", "strict", "authenticated_smtp")
    assert nothing_left == ("inconclusive", [], [])  # no structural signal at all
    flagged = [c for c in ALL if c[3] == "authenticated_smtp" and km.run_case(parsed, c[1], c[2], "strict", c[3])[0] in FLAGGED]
    assert len(flagged) == 8 and len(flagged) < sum(1 for c in ALL if c[3] == "local_submission")


@pytest.mark.parametrize("with_seeds,expected", [(True, 32), (False, 29)])
def test_how_many_of_the_48_mutations_still_reach_suspicious(with_seeds, expected, parsed, request):
    if not with_seeds:
        request.getfixturevalue("ablated")
    n = sum(km.run_case(parsed, c[1], c[2], "strict", c[3])[0] in FLAGGED for c in ALL)
    assert n == expected, n
