"""The inputs of compute_tier, built from what the pipeline already holds (docs/PHASE_B_PREREGISTRATION.md section 2). PURE: explicit inputs, no I/O, no network, no logging, nothing mutated.

  * findings with their code, produced severity and class;
  * the v1 weighted score and the per-category contributions (read, never recomputed);
  * trusted-receiver authentication failures;
  * hard-evidence CANDIDATES, only for link hosts, link URLs and attachment hashes: a provider answer counts as a candidate only when its key is a host or URL that a LINK of the message names, or the
    SHA-256 of one of its attachments. A Received-hop address, the sender domain and an image host are never candidates (they are never keys of the enrichment data, and a key that is not a link or an
    attachment hash is skipped here as well). Each candidate carries the flags the rules need: is_ip, is_shared_platform (the existing list), path_optin_on and exact_url_match (true only when the
    provider was SENT the full URL, which requires its opt-in), and whether the registrable domain is on the known-sender list or the own-domain list;
  * the blockers (app/blockers_adapter.py), the T4 positive flags (app/scoring/overrides.positive_evidence_flags) and the coverage gate.

The lists and the opt-in arrive as arguments: the caller reads them when it runs, so a configuration change takes effect without a restart of this module.
"""
from __future__ import annotations

from typing import Any

from app.blockers_adapter import derive_message_blockers
from app.enrichment.policy import classify_host, host_of, platform_of
from app.evidence import defang_url
from app.reason_classes import REASON_TABLE
from app.scoring.aggregate import category_coverage
from app.scoring.config import ScoringConfig
from app.scoring.overrides import positive_evidence_flags
from app.shared.matching import domain_matches_any

_FAILURE_METHODS = ("spf", "dkim", "dmarc")


def _is_hash(key: str) -> bool:
    return len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)


def hard_evidence_candidates(parsed: Any, enrichment: Any, listed_domains: frozenset[str] | set[str]) -> list[dict]:
    """One candidate per provider answer that could be hard evidence: a ThreatFox match, a VirusTotal answer with malicious engines, a MalwareBazaar match. compute_tier applies the rules and the thresholds."""
    if enrichment is None or enrichment.status in {"error", "skipped"}:
        return []
    link_keys: set[str] = set()
    for url in parsed.urls:
        host = host_of(url.url)
        link_keys.add(url.url)
        if host:
            link_keys.add(host)
    attachment_hashes = {a.sha256 for a in parsed.attachments}
    listed = sorted(listed_domains)
    out: list[dict] = []
    for key, value in (enrichment.raw_data or {}).items():
        if not isinstance(value, dict) or "uninformative" in value or value.get("internal_host_not_sent"):
            continue  # a shared-platform or internal host was never looked up: there is no answer to turn into a candidate
        if _is_hash(key) and key in attachment_hashes:
            for source, name in (("virustotal", "vt"), ("threatfox", "threatfox"), ("malwarebazaar", "malwarebazaar")):
                answer = value.get(name) or {}
                candidate = _candidate(source, answer)
                if candidate is not None:
                    out.append({**candidate, "indicator": key, "indicator_type": "attachment_hash", "is_ip": False, "is_shared_platform": False, "path_optin_on": False,
                                "exact_url_match": False, "is_known_sender_or_own_domain": False})
            continue
        if key not in link_keys:
            continue  # not a host or URL that a link names: never a candidate
        sent = value.get("sent") or {}
        for source, name in (("virustotal", "vt"), ("threatfox", "threatfox")):
            candidate = _candidate(source, value.get(name) or {})
            if candidate is None:
                continue
            kind = (sent.get(source) or {}).get("type")
            host = host_of(key) if "://" in key else key
            is_url = kind == "url"  # the provider was sent the full URL: only possible with its opt-in, and then a match is on the URL itself
            out.append({**candidate, "indicator": defang_url(key if is_url else (host or key)), "indicator_type": "link_url" if is_url else "link_host",
                        "is_ip": kind == "ip" or (host is not None and classify_host(host) == "ip"), "is_shared_platform": host is not None and platform_of(host) is not None,
                        "path_optin_on": is_url, "exact_url_match": is_url, "is_known_sender_or_own_domain": bool(host) and domain_matches_any(host, listed)})
    return out


def _candidate(source: str, answer: dict) -> dict | None:
    if answer.get("status") != "ok":
        return None
    if source == "virustotal" and (answer.get("malicious") or 0) > 0:
        return {"source": source, "engine_count": answer["malicious"], "confidence": None}
    if source == "threatfox" and answer.get("matched") is True:
        return {"source": source, "engine_count": None, "confidence": answer.get("confidence_level")}
    if source == "malwarebazaar" and answer.get("matched") is True:
        return {"source": source, "engine_count": None, "confidence": None}
    return None


def build_tier_inputs(parsed: Any, module_results: list[Any], analysis_result: Any, coverage_items: list[Any], *, known_sender_domains: frozenset[str], own_domains: frozenset[str],
                      config: ScoringConfig | None = None) -> tuple[dict, list[dict]]:
    """(the inputs of compute_tier, the blocker items). `analysis_result` supplies the findings, the weighted score, the contributions and the confidence."""
    config = config or ScoringConfig()
    by_name = {m.module: m for m in module_results}
    active = [m for m in module_results if m is not None and m.status not in {"error", "skipped"}]
    findings = [{"code": f.code, "severity": f.severity, "class": REASON_TABLE[f.code].cls if f.code in REASON_TABLE else "unknown"} for m in active for f in m.findings]

    auth = by_name.get("auth_check")
    headers = ((auth.raw_data or {}).get("auth_headers") or {}) if auth is not None and auth.status == "ok" else {}
    failures = [{"method": m, "result": headers[m]["result"], "trusted": True} for m in _FAILURE_METHODS if (headers.get(m) or {}).get("evaluated") and headers[m].get("result") == "fail"]

    enrichment = by_name.get("enrichment")
    ran = enrichment is not None and enrichment.status not in {"error", "skipped"}
    aligned_pass, sender_known = positive_evidence_flags(by_name, ScoringConfig(known_sender_domains=known_sender_domains))
    blocker_items = derive_message_blockers(parsed, module_results, coverage_items)
    scoring = analysis_result.scoring
    inputs = {
        "findings": findings,
        "score": scoring.weighted_score,
        "contributions": {c.category: c.contribution for c in scoring.categories},
        "trusted_auth_failures": failures,
        "hard_evidence_candidates": hard_evidence_candidates(parsed, enrichment, frozenset(known_sender_domains) | frozenset(own_domains)),
        "blockers": sorted({item["code"] for item in blocker_items}),
        "t4_positive_flags": {"trusted_aligned_dkim_or_dmarc_pass": aligned_pass, "sender_on_known_list": sender_known},
        "coverage_gate": {"confidence": analysis_result.confidence, "confidence_threshold": config.confidence_threshold,
                          "enrichment_complete": ran and category_coverage("enrichment", enrichment) >= 1.0},
    }
    return inputs, blocker_items
