"""Verdicts for the committed eval fixtures (offline, stub-clean providers)."""
from pathlib import Path

import pytest

from tests.eval import FIXTURES, analyze

FLAGGED = {"malicious", "suspicious"}


def _files(sub):
    return sorted((FIXTURES / sub).glob("*.eml"))


@pytest.mark.parametrize("path", _files("malicious/synthetic"), ids=lambda p: p.name)
def test_display_name_spoof_positives_are_flagged(path: Path):
    assert analyze(path, "clean").verdict in FLAGGED


@pytest.mark.parametrize("path", _files("benign/synthetic"), ids=lambda p: p.name)
def test_synthetic_benign_never_reaches_malicious(path: Path):
    assert analyze(path, "clean").verdict != "malicious"


@pytest.mark.parametrize("path", sorted((FIXTURES / "benign/synthetic").glob("1[1-5]_nearmiss_*.eml")), ids=lambda p: p.name)
def test_near_miss_display_names_are_not_flagged(path: Path):
    result = analyze(path, "clean")
    assert result.verdict not in FLAGGED, [f.title for f in result.findings]
