"""A recording fake HTTP session and fake provider answers, so the REAL provider clients (VirusTotal, ThreatFox, MalwareBazaar, urlscan) run end to end without a network.

`install(monkeypatch, answers)` replaces BaseClient.session with a FakeSession that records every request and answers from `answers`. `clients()` builds the four real clients with dummy keys (a client without
a key reports "disabled"), the scorer and its config, in the shape get_clients() returns. Nothing leaves the process.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any


class FakeResponse:
    def __init__(self, status_code: int, body: Any):
        self.status_code, self._body = status_code, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"{self.status_code}", response=self)


@dataclass
class Answers:
    """What the fake providers say. vt: indicator (domain, IP, hash or full URL) -> malicious engines (default 0); tf: indicator -> confidence (default no match); mb: matched hashes."""

    vt: dict[str, int] = field(default_factory=dict)
    tf: dict[str, int] = field(default_factory=dict)
    mb: set[str] = field(default_factory=set)


class FakeSession:
    def __init__(self, answers: Answers):
        self.answers = answers
        self.requests: list[tuple[str, str, str]] = []  # (provider, method, what was asked about)

    def request(self, method, url, headers=None, params=None, json=None, data=None, timeout=None):
        if "virustotal.com/api/v3/" in url:
            kind, _, tail = url.split("/api/v3/", 1)[1].partition("/")
            what = _decode_url_id(tail) if kind == "urls" else tail
            self.requests.append(("virustotal", method, what))
            malicious = self.answers.vt.get(what, 0)
            return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 50, "undetected": 5}, "reputation": 0}}})
        if "threatfox-api.abuse.ch" in url:
            term = (json or {}).get("search_term", "")
            self.requests.append(("threatfox", method, term))
            if term in self.answers.tf:
                return FakeResponse(200, {"query_status": "ok", "data": [{"confidence_level": self.answers.tf[term], "malware_printable": "fake-family", "threat_type": "payload_delivery", "tags": []}]})
            return FakeResponse(200, {"query_status": "no_result"})
        if "mb-api.abuse.ch" in url:
            term = (data or {}).get("hash", "")
            self.requests.append(("malwarebazaar", method, term))
            if term in self.answers.mb:
                return FakeResponse(200, {"query_status": "ok", "data": [{"file_name": "sample.bin", "file_type": "bin", "signature": "fake", "tags": []}]})
            return FakeResponse(200, {"query_status": "hash_not_found"})
        if "urlscan.io" in url:
            self.requests.append(("urlscan", method, (params or {}).get("q", "")))
            return FakeResponse(200, {"results": [], "total": 0})
        self.requests.append(("unexpected", method, url))
        return FakeResponse(404, {})


def _decode_url_id(identifier: str) -> str:
    return base64.urlsafe_b64decode(identifier + "=" * (-len(identifier) % 4)).decode("utf-8")


def install(monkeypatch, answers: Answers) -> FakeSession:
    from app.enrichment.providers.base import BaseClient

    session = FakeSession(answers)
    monkeypatch.setattr(BaseClient, "session", session)
    return session


def clients() -> dict:
    """The four real clients with dummy keys, the scorer and its config (the shape of providers.get_clients())."""
    from app.enrichment.providers import MalwareBazaarClient, RiskScorer, ScoreConfig, ThreatFoxClient, URLScanClient, VirusTotalClient

    return {"virustotal": VirusTotalClient(api_key="test-key"), "urlscan": URLScanClient(api_key="test-key"), "threatfox": ThreatFoxClient(api_key="test-key"),
            "malwarebazaar": MalwareBazaarClient(api_key="test-key"), "risk_scorer": RiskScorer, "score_config": ScoreConfig.from_env()}
