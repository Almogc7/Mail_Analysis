"""The first-party scorer reproduces, exactly, outputs recorded from the implementation it was copied from (765 cases, including the
config block), so the numbers behind every enrichment finding are unchanged. No other repository is needed to run this."""
import dataclasses
import json
from pathlib import Path

import pytest

from app.enrichment.providers.scoring import RiskScorer, ScoreConfig

GOLDEN = json.loads((Path(__file__).parent / "fixtures" / "provider_golden.json").read_text(encoding="utf-8"))


def test_the_default_config_equals_the_recorded_one():
    assert dataclasses.asdict(ScoreConfig()) == GOLDEN["score_config"]
    assert dataclasses.asdict(ScoreConfig.from_env()) == GOLDEN["score_config"]


def test_the_golden_set_is_the_size_it_was_recorded_at():
    assert len(GOLDEN["cases"]) == 765


def test_every_recorded_case_is_reproduced_exactly():
    mismatches = []
    for index, case in enumerate(GOLDEN["cases"]):
        kwargs = dict(vt=case["vt"], config=ScoreConfig(), threatfox=case["threatfox"], malwarebazaar=case["malwarebazaar"])
        if case["urlscan"] is not None:
            kwargs["urlscan"] = case["urlscan"]
        got = RiskScorer.explain(case["ioc_type"], **kwargs)
        if got != dict(case["expected"], config=GOLDEN["score_config"]):
            mismatches.append(index)
    assert mismatches == []


def test_a_provider_that_did_not_answer_contributes_nothing_it_is_unknown_not_clean():
    for status in ("disabled", "failed", "rate_limited", "invalid_response", "not_applicable"):
        result = RiskScorer.explain("domain", vt={"status": status, "malicious": 99}, threatfox={"status": status, "matched": True},
                                    urlscan={"status": status, "total_results": 99}, malwarebazaar={"status": status, "matched": True})
        assert result["total"] == 0 and result["components"] == []
        assert result["source_statuses"]["virustotal"] == status


def test_the_total_is_capped_at_100_and_floored_at_0():
    big = RiskScorer.explain("sha256", vt={"status": "ok", "malicious": 99, "suspicious": 99}, threatfox={"status": "ok", "matched": True, "match_count": 1},
                             malwarebazaar={"status": "ok", "matched": True, "signature": "S"}, urlscan={"status": "ok", "total_results": 99})
    assert big["total"] == 100 and sum(c["contribution"] for c in big["components"]) > 100


def test_malwarebazaar_only_counts_for_hash_types():
    mb = {"status": "ok", "matched": True, "signature": "S"}
    assert RiskScorer.explain("domain", vt={}, malwarebazaar=mb)["total"] == 0
    assert RiskScorer.explain("sha256", vt={}, malwarebazaar=mb)["total"] == 25


def test_config_comes_from_the_environment_with_the_original_names(monkeypatch):
    monkeypatch.setenv("IOC_VT_MALICIOUS_WEIGHT", "20")
    monkeypatch.setenv("IOC_THREATFOX_MATCH_BONUS", "40")
    cfg = ScoreConfig.from_env()
    assert cfg.vt_malicious_weight == 20 and cfg.threatfox_match_bonus == 40
    assert RiskScorer.explain("domain", vt={"status": "ok", "malicious": 1}, config=cfg)["total"] == 20


def test_unused_provider_branches_are_gone_but_the_payload_keys_remain():
    out = RiskScorer.explain("ip", vt={})
    assert set(out["source_statuses"]) == {"virustotal", "abuseipdb", "alienvault_otx", "urlscan", "threatfox", "malwarebazaar", "rdap"}
    assert {out["source_statuses"][k] for k in ("abuseipdb", "alienvault_otx", "rdap")} == {"unknown"}
    assert not hasattr(RiskScorer, "score") and not hasattr(RiskScorer, "verdict")
