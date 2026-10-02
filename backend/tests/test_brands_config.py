"""Brand data layers: generic (tracked), seeds (labelled), local (untracked, org-specific)."""
import json

import pytest

from app.shared import brands
from app.shared.brands import GENERIC_BRANDS, SEED_BRAND_NAMES, SEED_BRANDS, build_known_brands, load_local_brands


def test_tracked_brand_data_contains_no_organisation_specific_entries():
    # The owner's employer is configured locally; the public repo must not carry it.
    tracked = {**GENERIC_BRANDS, **SEED_BRANDS}
    org = "fi" + "bi"  # built at runtime: the literal name must not appear in tracked files
    assert org not in tracked
    assert not any(org in d for domains in tracked.values() for d in domains)


def test_seeds_are_labelled_and_separable():
    assert SEED_BRAND_NAMES == {"kvish6"}
    assert SEED_BRAND_NAMES.isdisjoint(GENERIC_BRANDS)
    without_seeds = {k: v for k, v in build_known_brands(None).items() if k not in SEED_BRAND_NAMES}
    assert "kvish6" not in without_seeds and "paypal" in without_seeds


def test_local_file_extends_and_overrides(tmp_path):
    f = tmp_path / "brands.local.json"
    f.write_text(json.dumps({"Acme Corp": ["Acme.Example"], "paypal": ["paypal.example"]}), encoding="utf-8")
    merged = build_known_brands(f)
    assert merged["acme corp"] == ["acme.example"]  # lower-cased
    assert merged["paypal"] == ["paypal.example"]  # local wins
    assert merged["kvish6"] == ["kvish6.co.il"]  # seeds still present


def test_missing_local_file_is_fine(tmp_path):
    assert load_local_brands(tmp_path / "nope.json") == {}


@pytest.mark.parametrize("content", ["not json", "[1, 2]", '{"a": "b"}', '{"a": [1]}'])
def test_malformed_local_file_raises_instead_of_being_ignored(tmp_path, content):
    f = tmp_path / "brands.local.json"
    f.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        load_local_brands(f)


def test_env_var_overrides_default_path(tmp_path, monkeypatch):
    f = tmp_path / "elsewhere.json"
    f.write_text('{"acme corp": ["acme.example"]}', encoding="utf-8")
    monkeypatch.setenv("LOCAL_BRANDS_FILE", str(f))
    assert load_local_brands() == {"acme corp": ["acme.example"]}


def test_fuzzy_threshold_constant_is_gone():
    assert not hasattr(brands, "FUZZY_MATCH_THRESHOLD")
