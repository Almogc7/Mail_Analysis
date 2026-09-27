"""Bridge into the sibling IOC_Enricher repo's provider clients and scorer.

IOC_Enricher has no pyproject.toml — it's a set of flat modules at its repo root that
import each other with bare names (`from ioc_analysis import IOCAnalyzer`, etc.), relying
on being on sys.path. We insert its repo root once here, matching the pattern IOC_Enricher's
own CI already uses (PYTHONPATH=<repo_root>), rather than modifying that repo.

Module 3 (URL/attachment-hash enrichment) is a later milestone — this stub only wires up
the import path so it's ready to build against.
"""

import sys
from typing import Any

from app.config import (
    IOC_ENRICHER_PATH,
    MALWAREBAZAAR_API_KEY,
    THREATFOX_API_KEY,
    URLSCAN_API_KEY,
    VT_API_KEY,
)

_bridged = False
_clients: dict[str, Any] | None = None


def ensure_ioc_enricher_on_path() -> None:
    global _bridged
    if _bridged:
        return
    path_str = str(IOC_ENRICHER_PATH)
    if not IOC_ENRICHER_PATH.exists():
        raise FileNotFoundError(
            f"IOC_ENRICHER_PATH does not exist: {IOC_ENRICHER_PATH}. "
            "Set IOC_ENRICHER_PATH in backend/.env to the IOC_Enricher repo root."
        )
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    _bridged = True


def get_clients() -> dict[str, Any]:
    """Lazily imports and instantiates the IOC_Enricher provider clients relevant to
    URL/attachment-hash enrichment, using Mail_Analysis's own API keys. Cached as a
    module-level singleton -- tests should monkeypatch this function to inject stub
    clients instead of hitting the real network."""
    global _clients
    if _clients is not None:
        return _clients

    ensure_ioc_enricher_on_path()
    from IOC_Enricher import (
        MalwareBazaarClient,
        RiskScorer,
        ScoreConfig,
        ThreatFoxClient,
        URLScanClient,
        VirusTotalClient,
    )

    _clients = {
        "virustotal": VirusTotalClient(api_key=VT_API_KEY or ""),
        "urlscan": URLScanClient(api_key=URLSCAN_API_KEY or ""),
        "threatfox": ThreatFoxClient(api_key=THREATFOX_API_KEY or ""),
        "malwarebazaar": MalwareBazaarClient(api_key=MALWAREBAZAAR_API_KEY or ""),
        "risk_scorer": RiskScorer,
        "score_config": ScoreConfig.from_env(),
    }
    return _clients
