"""Verdicts for the committed eval fixtures (offline, stub-clean providers)."""
from pathlib import Path

import pytest

from tests.eval import FIXTURES, analyze

FLAGGED = {"malicious", "suspicious"}


def _files(sub):
    return sorted((FIXTURES / sub).glob("*.eml"))


SINGLE_FAMILY_CLAIMS = {"s01_exact_brand_nonbrand_domain.eml", "s02_homoglyph_cyrillic.eml", "s04_leet_variant.eml", "s05_multiword_brand.eml"}
TWO_FAMILY_CLAIMS = {"s03_freemail_sender.eml"}  # claim + sender (a free mailbox)


@pytest.mark.parametrize("path", [p for p in _files("malicious/synthetic") if p.name in SINGLE_FAMILY_CLAIMS], ids=lambda p: p.name)
def test_display_name_only_spoofs_are_one_family_and_do_not_floor_alone(path: Path):
    """docs/DETECTION_DESIGN.md: a brand/display-name claim is MEDIUM and floors only with a second family. These
    positives carry the claim and nothing else, so they are inconclusive."""
    result = analyze(path, "clean")
    assert result.verdict == "needs_review"
    assert any(f.title.startswith("Possible display-name spoofing") and f.severity == "medium" for f in result.findings)
    assert not any(o.rule.endswith("_floor") for o in result.scoring.applied_overrides)


@pytest.mark.parametrize("path", [p for p in _files("malicious/synthetic") if p.name in TWO_FAMILY_CLAIMS], ids=lambda p: p.name)
def test_a_brand_claim_on_a_free_mailbox_is_two_families_and_floors(path: Path):
    result = analyze(path, "clean")
    assert result.verdict == "suspicious"
    floor = next(o for o in result.scoring.applied_overrides if o.rule == "structural_corroboration_floor")
    assert "claim" in floor.reason and "sender" in floor.reason and "C1" in floor.reason and "S3" in floor.reason


def test_every_synthetic_positive_is_classified_in_exactly_one_group():
    names = {p.name for p in _files("malicious/synthetic")}
    assert names == SINGLE_FAMILY_CLAIMS | TWO_FAMILY_CLAIMS and not (SINGLE_FAMILY_CLAIMS & TWO_FAMILY_CLAIMS)


@pytest.mark.parametrize("path", _files("benign/synthetic"), ids=lambda p: p.name)
def test_synthetic_benign_never_reaches_malicious(path: Path):
    assert analyze(path, "clean").verdict != "malicious"


@pytest.mark.parametrize("path", sorted((FIXTURES / "benign/synthetic").glob("1[1-5]_nearmiss_*.eml")), ids=lambda p: p.name)
def test_near_miss_display_names_are_not_flagged(path: Path):
    result = analyze(path, "clean")
    assert result.verdict not in FLAGGED, [f.title for f in result.findings]
