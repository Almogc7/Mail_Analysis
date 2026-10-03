"""Verdicts for the committed eval fixtures (offline, stub-clean providers)."""
from pathlib import Path

import pytest

from tests.eval import FIXTURES, analyze

FLAGGED = {"malicious", "suspicious"}


def _files(sub):
    return sorted((FIXTURES / sub).glob("*.eml"))


SINGLE_FAMILY_CLAIMS = {"s01_exact_brand_nonbrand_domain.eml", "s02_homoglyph_cyrillic.eml", "s03_freemail_sender.eml",
                        "s04_leet_variant.eml", "s05_multiword_brand.eml"}


@pytest.mark.parametrize("path", _files("malicious/synthetic"), ids=lambda p: p.name)
def test_display_name_only_spoofs_are_one_family_and_do_not_floor_alone(path: Path):
    """docs/DETECTION_DESIGN.md: a brand/display-name claim is MEDIUM and floors only with a second family. These
    positives carry the claim and nothing else, so they are inconclusive. (s03's freemail sender becomes a second
    family when the sender-family signals land.)"""
    assert path.name in SINGLE_FAMILY_CLAIMS
    result = analyze(path, "clean")
    assert result.verdict == "needs_review"
    assert any(f.title.startswith("Possible display-name spoofing") and f.severity == "medium" for f in result.findings)
    assert not any(o.rule.endswith("_floor") for o in result.scoring.applied_overrides)


@pytest.mark.parametrize("path", _files("benign/synthetic"), ids=lambda p: p.name)
def test_synthetic_benign_never_reaches_malicious(path: Path):
    assert analyze(path, "clean").verdict != "malicious"


@pytest.mark.parametrize("path", sorted((FIXTURES / "benign/synthetic").glob("1[1-5]_nearmiss_*.eml")), ids=lambda p: p.name)
def test_near_miss_display_names_are_not_flagged(path: Path):
    result = analyze(path, "clean")
    assert result.verdict not in FLAGGED, [f.title for f in result.findings]
