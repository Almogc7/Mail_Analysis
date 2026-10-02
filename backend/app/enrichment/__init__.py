from typing import Any

from app.config import MAX_HASHES_TO_ENRICH, MAX_URLS_TO_ENRICH
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.enrichment import ioc_bridge
from app.enrichment.policy import (
    EnrichmentPolicy,
    GuardedProvider,
    classify_host,
    guard_clients,
    host_of,
    load_policy,
    lookup_key,
    target_for,
)
from app.enrichment.rate_limit import VTRateLimiter

MODULE_NAME = "enrichment"


def _is_incomplete(result: Any) -> bool:
    """Anything but a clean status 'ok' means the provider did not actually evaluate the IOC:
    disabled, not_applicable, rate_limited, failed, timeout, invalid_response, an exception... The
    IOC is then UNKNOWN. 'No detections' from a provider that did not answer is not 'clean'."""
    return not isinstance(result, dict) or result.get("status") != "ok"


def _severity_for_score(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _collect_units(parsed: ParsedEmail, policy: EnrichmentPolicy) -> dict[str, str]:
    """{ioc_key: representative_url}, in first-seen order. The key is the host (default) or the full
    URL (only when some provider opted in to path/query), so many links on one host cost one lookup."""
    units: dict[str, str] = {}
    for u in parsed.urls:
        key = lookup_key(u.url, policy)
        if key is not None and key not in units:
            units[key] = u.url
    return units


def _collect_unique_hashes(parsed: ParsedEmail) -> list[tuple[str, str | None]]:
    """Returns (sha256, filename) pairs, deduped by sha256."""
    seen: dict[str, str | None] = {}
    for a in parsed.attachments:
        if a.sha256 not in seen:
            seen[a.sha256] = a.filename
    return list(seen.items())


def _skip_finding(ioc_kind: str, ioc_value: str) -> Finding:
    return Finding(
        module=MODULE_NAME,
        severity="low",
        title=f"Not enriched: per-email limit reached ({ioc_kind})",
        description=(
            f"{ioc_kind.capitalize()} '{ioc_value}' was not looked up because this email "
            f"exceeded the per-email enrichment limit."
        ),
        evidence={"ioc_kind": ioc_kind, "ioc_value": ioc_value},
        weight=0.0,
    )


def _incomplete_findings(ioc_value: str, provider_results: dict[str, dict[str, Any]]) -> list[Finding]:
    findings = []
    for provider, result in provider_results.items():
        if _is_incomplete(result):
            status = result.get("status") if isinstance(result, dict) else "invalid_response"
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title=f"Enrichment incomplete for {ioc_value}",
                    description=(
                        f"{provider} returned no usable result (status: {status}). This IOC is UNKNOWN on that "
                        "source -- absence of a detection is not evidence that it is clean."
                    ),
                    evidence={"provider": provider, "ioc_value": ioc_value, "result": result},
                    weight=0.0,
                )
            )
    return findings


def _internal_finding(host: str) -> Finding:
    return Finding(
        module=MODULE_NAME,
        severity="info",
        title=f"Enrichment incomplete for {host}",
        description=(
            f"'{host}' looks internal (no public DNS name or a private/loopback address), so it was never "
            "sent to any external service. It is UNKNOWN, not clean."
        ),
        evidence={"provider": "all", "ioc_value": host, "reason": "internal-looking host"},
        weight=0.0,
    )


def _enrich_url_unit(
    key: str, url: str, providers: dict[str, GuardedProvider], policy: EnrichmentPolicy,
    clients: dict[str, Any], vt_limiter: VTRateLimiter,
) -> dict[str, Any]:
    results: dict[str, dict[str, Any]] = {}
    sent: dict[str, dict[str, str]] = {}
    for name in ("virustotal", "urlscan", "threatfox"):
        ioc_type, value = target_for(name, url, policy)
        sent[name] = {"type": ioc_type, "value": value if ioc_type != "internal" else "(not sent)"}
        if name == "virustotal" and not providers[name].disabled and ioc_type != "internal":
            vt_limiter.wait_if_needed()
        results[name] = providers[name].lookup(ioc_type, value)

    # URLScan's hit count says how often a page was SCANNED, not whether it is bad: a popular legitimate
    # host has thousands. At host level it is context only and must not add risk; only an exact-URL
    # lookup (provider opt-in) is a meaningful 'seen before'.
    urlscan_scores = sent["urlscan"]["type"] == "url"
    scoring_type = "url" if any(s["type"] == "url" for s in sent.values()) else ("ip" if sent["virustotal"]["type"] == "ip" else "domain")
    explain = clients["risk_scorer"].explain(
        scoring_type,
        vt=results["virustotal"],
        abuse={},
        otx={},
        config=clients["score_config"],
        threatfox=results["threatfox"],
        urlscan=results["urlscan"] if urlscan_scores else {},
    )
    return {
        "vt": results["virustotal"],
        "urlscan": results["urlscan"],
        "threatfox": results["threatfox"],
        "risk_explain": explain,
        "sent": sent,
        "urlscan_context_only": not urlscan_scores,
    }


def _enrich_hash(sha256: str, providers: dict[str, GuardedProvider], clients: dict[str, Any], vt_limiter: VTRateLimiter) -> dict[str, Any]:
    if not providers["virustotal"].disabled:
        vt_limiter.wait_if_needed()
    vt_result = providers["virustotal"].lookup("sha256", sha256)
    threatfox_result = providers["threatfox"].lookup("sha256", sha256)
    mb_result = providers["malwarebazaar"].lookup("sha256", sha256)

    explain = clients["risk_scorer"].explain(
        "sha256",
        vt=vt_result,
        abuse={},
        otx={},
        config=clients["score_config"],
        threatfox=threatfox_result,
        malwarebazaar=mb_result,
    )
    return {"vt": vt_result, "threatfox": threatfox_result, "malwarebazaar": mb_result, "risk_explain": explain}


def run_enrichment(
    parsed: ParsedEmail,
    clients: dict[str, Any] | None = None,
    vt_limiter: VTRateLimiter | None = None,
    policy: EnrichmentPolicy | None = None,
) -> ModuleResult:
    clients = clients if clients is not None else ioc_bridge.get_clients()
    vt_limiter = vt_limiter if vt_limiter is not None else VTRateLimiter()
    policy = policy if policy is not None else load_policy()
    providers = guard_clients(clients, policy)

    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}
    statuses: dict[str, dict[str, int]] = {}  # provider -> {status: count} for non-ok results

    def tally(provider_results: dict[str, Any]) -> None:
        for provider, result in provider_results.items():
            if _is_incomplete(result):
                status = result.get("status", "invalid_response") if isinstance(result, dict) else "invalid_response"
                statuses.setdefault(provider, {})[status] = statuses.setdefault(provider, {}).get(status, 0) + 1

    units = _collect_units(parsed, policy)
    hashes = _collect_unique_hashes(parsed)

    unit_items = list(units.items())
    to_enrich, skipped = unit_items[:MAX_URLS_TO_ENRICH], unit_items[MAX_URLS_TO_ENRICH:]
    hashes_to_enrich, hashes_skipped = hashes[:MAX_HASHES_TO_ENRICH], hashes[MAX_HASHES_TO_ENRICH:]
    label = "URL" if policy.path_query_providers else "host"

    for key, url in to_enrich:
        host = host_of(url)
        if host is not None and classify_host(host) == "internal":
            raw_data[key] = {"internal_host_not_sent": True}
            findings.append(_internal_finding(key))
            continue
        result = _enrich_url_unit(key, url, providers, policy, clients, vt_limiter)
        raw_data[key] = result

        score = result["risk_explain"]["total"]
        if score > 0:
            components = result["risk_explain"]["components"]
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=_severity_for_score(score),
                    title=f"Suspicious {label}: {key}",
                    description="; ".join(c["label"] for c in components) or "No specific signal breakdown.",
                    evidence={"components": components, "ioc_value": key},
                    weight=float(score),
                )
            )
        provider_results = {"virustotal": result["vt"], "urlscan": result["urlscan"], "threatfox": result["threatfox"]}
        findings.extend(_incomplete_findings(key, provider_results))
        tally(provider_results)

    for sha256, filename in hashes_to_enrich:
        result = _enrich_hash(sha256, providers, clients, vt_limiter)
        raw_data[sha256] = result

        score = result["risk_explain"]["total"]
        if score > 0:
            components = result["risk_explain"]["components"]
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=_severity_for_score(score),
                    title=f"Known-malicious attachment hash: {filename or sha256}",
                    description="; ".join(c["label"] for c in components) or "No specific signal breakdown.",
                    evidence={"components": components, "ioc_value": sha256, "filename": filename},
                    weight=float(score),
                )
            )
        provider_results = {"virustotal": result["vt"], "threatfox": result["threatfox"], "malwarebazaar": result["malwarebazaar"]}
        findings.extend(_incomplete_findings(sha256, provider_results))
        tally(provider_results)

    for key, _url in skipped:
        findings.append(_skip_finding(label.lower(), key))
    for sha256, _ in hashes_skipped:
        findings.append(_skip_finding("hash", sha256))

    if statuses:
        parts = [f"{p}: " + ", ".join(f"{s} x{n}" for s, n in sorted(c.items())) for p, c in sorted(statuses.items())]
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="info",
                title="Some enrichment providers did not give a usable answer",
                description=(
                    "Affected indicators are UNKNOWN, not clean (" + "; ".join(parts) + "). "
                    "Check provider API keys, ENRICHMENT_DISABLED_PROVIDERS, rate limits and connectivity."
                ),
                evidence={"providers": statuses},
                weight=0.0,
            )
        )

    return ModuleResult(module=MODULE_NAME, status="ok", findings=findings, raw_data=raw_data)


__all__ = ["run_enrichment"]
