"""What may leave this machine during enrichment, and how provider failures are treated.

Defaults are privacy-first:

* URL indicators are looked up by HOSTNAME (or registrable domain) only. The path and query -- where
  per-recipient tracking tokens live -- are never sent unless that provider is named in
  ENRICHMENT_PATH_QUERY_PROVIDERS (opt-in, default empty).
* Internal-looking hosts (no dot, .local/.corp/.internal..., private or loopback IPs) are never sent.
* Only the lookup call `enrich()` is ever made on a provider, and only for the IOC types listed in
  ALLOWED_TYPES: VirusTotal gets hashes/domains/IPs (URLs only on opt-in) and is never given a file;
  URLScan is queried by search only (no scan is ever submitted, so there is no public/private scan to
  get wrong); ThreatFox gets an IOC string; MalwareBazaar gets hashes. A request outside this policy
  raises PolicyViolation instead of being sent.
* Each provider can be switched off (ENRICHMENT_DISABLED_PROVIDERS). A disabled, not-applicable,
  failing, timed-out or rate-limited provider yields a result whose status is NOT "ok", which the
  enrichment module reports as UNKNOWN with a visible warning -- never as clean.

Config comes from app.config at call time (so tests can monkeypatch it).
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.shared.matching import registrable_domain

PROVIDERS = ("virustotal", "urlscan", "threatfox", "malwarebazaar")

# IOC types each provider may be asked about. "url" additionally requires the explicit path/query opt-in.
ALLOWED_TYPES: dict[str, frozenset[str]] = {
    "virustotal": frozenset({"domain", "ip", "url", "sha256"}),
    "urlscan": frozenset({"domain", "ip", "url"}),
    "threatfox": frozenset({"domain", "ip", "url", "sha256"}),
    "malwarebazaar": frozenset({"sha256"}),
}

_INTERNAL_SUFFIXES = (".local", ".localdomain", ".internal", ".corp", ".lan", ".home", ".intranet", ".private", ".localhost")
_GRANULARITIES = ("hostname", "registrable")


class PolicyViolation(Exception):
    """A lookup that the privacy policy forbids was requested. A bug, never silently sent."""


@dataclass(frozen=True)
class EnrichmentPolicy:
    disabled_providers: frozenset[str] = field(default_factory=frozenset)
    path_query_providers: frozenset[str] = field(default_factory=frozenset)
    granularity: str = "hostname"


def load_policy() -> EnrichmentPolicy:
    """Read the policy from app.config. Unknown provider names or granularity raise ValueError: a typo in
    a disable list must not silently leave that provider enabled."""
    from app import config

    def providers(name: str) -> frozenset[str]:
        values = [v.strip().lower() for v in getattr(config, name)]
        unknown = [v for v in values if v not in PROVIDERS]
        if unknown:
            raise ValueError(f"{name} names unknown provider(s) {unknown}; valid: {list(PROVIDERS)}")
        return frozenset(values)

    granularity = str(config.ENRICHMENT_GRANULARITY).strip().lower()
    if granularity not in _GRANULARITIES:
        raise ValueError(f"ENRICHMENT_GRANULARITY must be one of {list(_GRANULARITIES)}, got {granularity!r}")
    return EnrichmentPolicy(
        disabled_providers=providers("ENRICHMENT_DISABLED_PROVIDERS"),
        path_query_providers=providers("ENRICHMENT_PATH_QUERY_PROVIDERS"),
        granularity=granularity,
    )


# --------------------------------------------------------------------------------------------
# Targets: what exactly would be sent for a URL
# --------------------------------------------------------------------------------------------

def host_of(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip(".").lower()
    try:
        return host.encode("idna").decode("ascii")  # providers expect punycode
    except UnicodeError:
        return host


def classify_host(host: str) -> str:
    """'ip' | 'domain' | 'internal' (never sent externally)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or host.endswith(_INTERNAL_SUFFIXES):
            return "internal"
        return "domain"
    return "ip" if ip.is_global else "internal"


def lookup_key(url: str, policy: EnrichmentPolicy) -> str | None:
    """The IOC identity for a URL under this policy: the full URL if ANY provider has opted in to
    path/query (so each distinct URL is looked up), otherwise just its host (so 20 links on one host
    cost one lookup). None if no host can be extracted."""
    return url if policy.path_query_providers else host_of(url)


def target_for(provider: str, url: str, policy: EnrichmentPolicy) -> tuple[str, str]:
    """(ioc_type, value) to send `provider` for `url`; ioc_type 'internal' means 'do not send'."""
    host = host_of(url)
    if host is None:
        return "internal", url
    kind = classify_host(host)
    if kind == "internal":
        return "internal", host
    if provider in policy.path_query_providers:
        return "url", url
    if kind == "ip":
        return "ip", host
    if policy.granularity == "registrable":
        return "domain", registrable_domain(host) or host
    return "domain", host


# --------------------------------------------------------------------------------------------
# The guard in front of every provider client
# --------------------------------------------------------------------------------------------

def _result(status: str, error: str, enabled: bool = True) -> dict[str, Any]:
    return {"enabled": enabled, "status": status, "error": error}


class GuardedProvider:
    """Wraps one IOC_Enricher provider client. Exposes ONLY lookup(); never forwards any other method,
    so nothing can be uploaded or submitted through it."""

    def __init__(self, name: str, client: Any, policy: EnrichmentPolicy):
        if name not in ALLOWED_TYPES:
            raise ValueError(f"unknown provider {name!r}")
        self.name, self._client, self.policy = name, client, policy

    @property
    def disabled(self) -> bool:
        return self.name in self.policy.disabled_providers

    def lookup(self, ioc_type: str, value: str) -> dict[str, Any]:
        if self.disabled:
            return _result("disabled", "disabled by configuration (ENRICHMENT_DISABLED_PROVIDERS)", enabled=False)
        if ioc_type == "internal":
            return _result("not_applicable", "internal-looking host: never sent to an external service", enabled=False)
        if ioc_type not in ALLOWED_TYPES[self.name]:
            return _result("not_applicable", f"{self.name} is not queried for {ioc_type} indicators by policy", enabled=False)
        if ioc_type == "url" and self.name not in self.policy.path_query_providers:
            raise PolicyViolation(f"{self.name}: sending a URL (path/query) requires ENRICHMENT_PATH_QUERY_PROVIDERS opt-in")
        if ioc_type in ("domain", "ip") and any(c in value for c in "/?#@ \t\r\n"):
            raise PolicyViolation(f"{self.name}: a {ioc_type} lookup must be host-only, got a value with path/query characters")
        try:
            result = self._client.enrich(value, ioc_type)
        except Exception as exc:  # network error, timeout, a bug in the client: unknown, never clean, never a crash
            return _result("failed", f"{type(exc).__name__}: {exc}")
        if not isinstance(result, dict) or "status" not in result:
            return _result("invalid_response", "provider returned something that is not a status dict")
        return result


def guard_clients(clients: dict[str, Any], policy: EnrichmentPolicy) -> dict[str, GuardedProvider]:
    return {name: GuardedProvider(name, clients[name], policy) for name in PROVIDERS if name in clients}


# --------------------------------------------------------------------------------------------
# Shared platforms: hosts where a reputation lookup cannot tell good from bad
# --------------------------------------------------------------------------------------------

DEFAULT_PLATFORMS_FILE = Path(__file__).with_name("shared_platforms.json")


@dataclass(frozen=True)
class Platform:
    name: str
    kind: str  # esp_tracker | link_wrapper | shortener | cloud_content | site_builder
    domains: tuple[str, ...]


def _read_platforms(path: Path) -> list[Platform]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read shared-platforms file {path.name}: {exc}") from exc
    entries = data.get("platforms") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f'{path.name} must be {{"platforms": [{{"name", "kind", "domains": [...]}}]}}')
    platforms = []
    for e in entries:
        ok = isinstance(e, dict) and isinstance(e.get("name"), str) and isinstance(e.get("kind"), str) \
            and isinstance(e.get("domains"), list) and e["domains"] and all(isinstance(d, str) and d.strip() for d in e["domains"])
        if not ok:
            raise ValueError(f"{path.name}: malformed platform entry {e!r}")
        platforms.append(Platform(e["name"], e["kind"], tuple(d.strip().strip(".").lower() for d in e["domains"])))
    return platforms


@lru_cache(maxsize=4)
def _load_platforms(default_path: str, extra_path: str | None) -> tuple[Platform, ...]:
    platforms = _read_platforms(Path(default_path))
    if extra_path:
        platforms += _read_platforms(Path(extra_path))  # organisation-specific additions (untracked)
    return tuple(platforms)


def load_platforms() -> tuple[Platform, ...]:
    """Tracked generic list plus the optional untracked file named by SHARED_PLATFORMS_EXTRA_FILE."""
    return _load_platforms(str(DEFAULT_PLATFORMS_FILE), os.getenv("SHARED_PLATFORMS_EXTRA_FILE") or None)


def platform_of(host: str | None) -> Platform | None:
    """The shared platform a host belongs to (host == domain or a subdomain of it; the longest matching
    domain wins), or None."""
    if not host:
        return None
    host = host.strip(".").lower()
    best: tuple[int, Platform] | None = None
    for platform in load_platforms():
        for domain in platform.domains:
            if (host == domain or host.endswith("." + domain)) and (best is None or len(domain) > best[0]):
                best = (len(domain), platform)
    return best[1] if best else None


# --------------------------------------------------------------------------------------------
# Risk-ordered capping: when there are more lookups than the per-email cap, look up the riskiest
# --------------------------------------------------------------------------------------------

def url_priority(url: str, *, anchor_mismatch: bool, is_cta: bool, sender_domain: str | None) -> tuple[int, list[str]]:
    """How much a URL deserves one of the limited lookups, from LOCAL evidence only (the path is read here
    but never sent anywhere). Higher = look up first. Returns (score, reasons). Not a verdict: it only
    orders the queue, so a cap drops the least interesting indicators instead of the last-listed ones."""
    from app.shared.brands import KNOWN_BRANDS
    from app.shared.matching import domain_matches_any, find_brand_matches

    score, reasons = 0, []
    parts = urlsplit(url)
    host = host_of(url) or ""
    if anchor_mismatch:
        score += 4
        reasons.append("link text shows a different address than the real target")
    if host and classify_host(host) == "ip":
        score += 4
        reasons.append("IP-literal host")
    if any(label.startswith("xn--") for label in host.split(".")):
        score += 3
        reasons.append("punycode (internationalised) host")
    if host.count(".") >= 4:
        score += 2
        reasons.append("many subdomain levels")
    if len(host) > 40:
        score += 1
        reasons.append("very long host name")
    host_reg = registrable_domain(host)
    sender_reg = registrable_domain(sender_domain) if sender_domain else None
    if host_reg and sender_reg and host_reg != sender_reg:
        score += 1
        reasons.append("target is not the sender's domain")
    for match in find_brand_matches(f"{host} {parts.path}", KNOWN_BRANDS):
        if match.kind == "exact" and not domain_matches_any(host, KNOWN_BRANDS[match.brand]):
            score += 3
            reasons.append(f"brand token '{match.brand}' in the URL on an unrelated domain")
            break
    if is_cta:
        score += 1
        reasons.append("clickable link with visible text")
    return score, reasons
