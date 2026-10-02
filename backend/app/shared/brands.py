"""Brand name -> legitimate domain(s).

Shared by auth_check.spoofing (display name vs sender domain) and content_analysis. Matching
logic lives in app/shared/matching.py; this module is data only.

Three layers, merged into KNOWN_BRANDS (later layers win):
  1. GENERIC_BRANDS   -- well-known public brands. Safe to keep in the repo.
  2. SEED_BRANDS      -- single-sample SEEDS: entries added because a real phishing email
                         impersonated them. Labelled so tooling can remove them (the eval's
                         --ablate-seeds does) to measure detection that does NOT depend on a
                         brand this project has already seen.
  3. LOCAL brands     -- an UNTRACKED JSON file (default backend/brands.local.json, override with
                         LOCAL_BRANDS_FILE) for organisation-specific entries such as your own
                         employer. They never belong in the public repo.
                         Format: {"brand name": ["legit-domain.example", ...], ...}

Extend generically; a missing brand just means "not flagged", never "safe".
"""
from __future__ import annotations

import json
import os
from pathlib import Path

GENERIC_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "meta.com"],
    # Regional (Israeli) public brands -- a best-effort, unvetted starter set.
    "bank hapoalim": ["bankhapoalim.co.il"],
    "bank leumi": ["leumi.co.il"],
    "discount bank": ["discountbank.co.il"],
    "israel post": ["israelpost.co.il"],
}

# SEEDS: each exists only because one real phishing email impersonated it.
SEED_BRANDS: dict[str, list[str]] = {
    "kvish6": ["kvish6.co.il"],  # Highway 6 toll road; first real false negative of this project
}
SEED_BRAND_NAMES = frozenset(SEED_BRANDS)

DEFAULT_LOCAL_BRANDS_FILE = Path(__file__).resolve().parents[2] / "brands.local.json"


def load_local_brands(path: Path | str | None = None) -> dict[str, list[str]]:
    """Read the untracked local brands file; {} if it does not exist. Raises ValueError on a
    malformed file rather than silently ignoring configuration."""
    file = Path(path or os.getenv("LOCAL_BRANDS_FILE") or DEFAULT_LOCAL_BRANDS_FILE)
    if not file.exists():
        return {}
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{file.name} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(d, str) for d in v) for k, v in data.items()
    ):
        raise ValueError(f'{file.name} must be {{"brand": ["domain", ...], ...}}')
    return {k.lower(): [d.lower() for d in v] for k, v in data.items()}


def build_known_brands(local_path: Path | str | None = None) -> dict[str, list[str]]:
    return {**GENERIC_BRANDS, **SEED_BRANDS, **load_local_brands(local_path)}


KNOWN_BRANDS: dict[str, list[str]] = build_known_brands()
