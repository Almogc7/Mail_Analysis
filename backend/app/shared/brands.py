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
                         Format: {"brand name": ["legit-domain.example", ...], ...}, or per brand
                         {"domains": [...], "aliases": ["other name", "שם בעברית", ...]}

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


def _domains(value: object) -> list[str] | None:
    return [d.lower() for d in value] if isinstance(value, list) and all(isinstance(d, str) for d in value) else None


def load_local_brands(path: Path | str | None = None) -> dict[str, list[str]]:
    """Read the untracked local brands file; {} if it does not exist. Raises ValueError on a
    malformed file rather than silently ignoring configuration.

    An entry is either a list of domains, or {"domains": [...], "aliases": [...]}. Every alias (a Hebrew name, a
    transliteration, a product name) becomes one more key of the map with the same domains, so the matcher treats an
    alias exactly like the brand name. Aliases belong here, in the untracked file, never in tracked code."""
    file = Path(path or os.getenv("LOCAL_BRANDS_FILE") or DEFAULT_LOCAL_BRANDS_FILE)
    if not file.exists():
        return {}
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{file.name} is not valid JSON: {exc}") from exc
    shape = f'{file.name} must be {{"brand": ["domain", ...] | {{"domains": [...], "aliases": [...]}}, ...}}'
    if not isinstance(data, dict):
        raise ValueError(shape)
    out: dict[str, list[str]] = {}
    for name, value in data.items():
        if not isinstance(name, str):
            raise ValueError(shape)
        if isinstance(value, dict):
            domains, aliases = _domains(value.get("domains")), value.get("aliases", [])
            if domains is None or not isinstance(aliases, list) or not all(isinstance(a, str) and a.strip() for a in aliases):
                raise ValueError(shape)
        else:
            domains, aliases = _domains(value), []
            if domains is None:
                raise ValueError(shape)
        for key in [name, *aliases]:
            out[key.strip().lower()] = domains
    return out


def build_known_brands(local_path: Path | str | None = None) -> dict[str, list[str]]:
    return {**GENERIC_BRANDS, **SEED_BRANDS, **load_local_brands(local_path)}


KNOWN_BRANDS: dict[str, list[str]] = build_known_brands()
