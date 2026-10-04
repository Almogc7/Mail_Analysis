"""First-party lookup providers (read-only): VirusTotal, urlscan.io, ThreatFox, MalwareBazaar, and the risk scorer.

The code originated in the author's IOC_Enricher project and is maintained here independently; Mail_Analysis has no dependency on that
repository. Nothing in this package can submit a URL or upload a file.
"""
from __future__ import annotations

from typing import Any

from app import config
from app.enrichment.providers.malwarebazaar import MalwareBazaarClient
from app.enrichment.providers.scoring import RiskScorer, ScoreConfig
from app.enrichment.providers.threatfox import ThreatFoxClient
from app.enrichment.providers.urlscan import URLScanClient
from app.enrichment.providers.virustotal import VirusTotalClient

_clients: dict[str, Any] | None = None


def get_clients() -> dict[str, Any]:
    """Instantiates the provider clients with this app's own API keys (a client without a key reports "disabled" for every lookup) and the
    scorer. Cached as a module-level singleton; tests monkeypatch this function to inject stub clients instead of touching the network."""
    global _clients
    if _clients is not None:
        return _clients

    _clients = {
        "virustotal": VirusTotalClient(api_key=config.VT_API_KEY or ""),
        "urlscan": URLScanClient(api_key=config.URLSCAN_API_KEY or ""),
        "threatfox": ThreatFoxClient(api_key=config.THREATFOX_API_KEY or ""),
        "malwarebazaar": MalwareBazaarClient(api_key=config.MALWAREBAZAAR_API_KEY or ""),
        "risk_scorer": RiskScorer,
        "score_config": ScoreConfig.from_env(),
    }
    return _clients


__all__ = [
    "get_clients", "MalwareBazaarClient", "RiskScorer", "ScoreConfig", "ThreatFoxClient", "URLScanClient", "VirusTotalClient",
]
