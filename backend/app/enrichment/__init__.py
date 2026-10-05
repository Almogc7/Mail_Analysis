import logging
from typing import Any

from app.config import MAX_HASHES_TO_ENRICH, MAX_URLS_TO_ENRICH
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.finding_codes import code as finding_code
from app.enrichment import providers as provider_package  # not "providers": functions below have a local of that name
from app.enrichment.policy import (
    EnrichmentPolicy,
    GuardedProvider,
    classify_host,
    guard_clients,
    host_of,
    load_policy,
    lookup_key,
    platform_of,
    target_for,
    url_priority,
)
from app.enrichment.rate_limit import VTRateLimiter
from app.shared.matching import registrable_domain

MODULE_NAME = "enrichment"
logger = logging.getLogger(__name__)


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


def _unit_priority(key: str, representative: str, parsed: ParsedEmail, policy: EnrichmentPolicy) -> tuple[int, list[str]]:
    """Priority of one lookup unit: the best (highest) score among the URLs that map to it."""
    best: tuple[int, list[str]] = (-1, [])
    for u in parsed.urls:
        if lookup_key(u.url, policy) != key:
            continue
        candidate = url_priority(
            u.url,
            anchor_mismatch=u.is_anchor_mismatch,
            is_cta=u.source == "body_html" and bool(u.anchor_text),
            sender_domain=parsed.from_.domain,
        )
        if candidate[0] > best[0]:
            best = candidate
    return best if best[0] >= 0 else url_priority(representative, anchor_mismatch=False, is_cta=False, sender_domain=parsed.from_.domain)


def _collect_unique_hashes(parsed: ParsedEmail) -> list[tuple[str, str | None]]:
    """Returns (sha256, filename) pairs, deduped by sha256."""
    seen: dict[str, str | None] = {}
    for a in parsed.attachments:
        if a.sha256 not in seen:
            seen[a.sha256] = a.filename
    return list(seen.items())


def _skip_finding(ioc_kind: str, ioc_value: str, priority: int | None = None, reasons: list[str] | None = None) -> Finding:
    detail = f" It ranked {priority} for risk ({'; '.join(reasons)})." if priority is not None and reasons else ""
    return Finding(
        module=MODULE_NAME,
        severity="low",
        title=f"Not enriched: per-email limit reached ({ioc_kind})",
        code=finding_code("ENRICH_SKIPPED_PER_EMAIL_LIMIT"),
        description=(
            f"{ioc_kind.capitalize()} '{ioc_value}' was not looked up because this email exceeded the per-email "
            f"enrichment limit; the riskiest indicators are looked up first.{detail} It is UNKNOWN (no answer), which is not the same as 'nothing found'."
        ),
        evidence={"ioc_kind": ioc_kind, "ioc_value": ioc_value, "priority": priority, "reasons": reasons or []},
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
                    code=finding_code("ENRICH_INCOMPLETE_PROVIDER_NO_RESULT"),
                    description=(
                        f"{provider} returned no usable result (status: {status}). This IOC is UNKNOWN on that "
                        "source -- absence of a detection is not evidence that nothing is wrong with it."
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
        code=finding_code("ENRICH_INCOMPLETE_INTERNAL_HOST"),
        description=(
            f"'{host}' looks internal (no public DNS name or a private/loopback address), so it was never "
            "sent to any external service. It is UNKNOWN (no answer), which is not the same as 'nothing found'."
        ),
        evidence={"provider": "all", "ioc_value": host, "reason": "internal-looking host"},
        weight=0.0,
    )


def _uninformative_finding(key: str, platform) -> Finding:
    return Finding(
        module=MODULE_NAME,
        severity="info",
        # Same title prefix as other gaps so scoring coverage counts it: no reputation evidence exists.
        title=f"Enrichment incomplete for {key}",
        code=finding_code("ENRICH_INCOMPLETE_SHARED_PLATFORM"),
        description=(
            f"'{key}' is on {platform.name} ({platform.kind.replace('_', ' ')}), a shared platform: its domains are "
            "reputable but host or relay content anyone can create, so a reputation lookup cannot separate a "
            "good link from a bad one and none was made. UNINFORMATIVE -- unknown on reputation, which is not the same as 'nothing found'."
        ),
        evidence={"provider": "all", "ioc_value": key, "state": "uninformative", "platform": platform.name, "kind": platform.kind},
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
    clients = clients if clients is not None else provider_package.get_clients()
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

    # Hosts that need no external lookup (internal-looking, or on a shared platform) are settled
    # immediately and do NOT consume the per-email cap; only real lookups are capped.
    costly: list[tuple[str, str]] = []
    for key, url in units.items():
        host = host_of(url)
        if host is not None and classify_host(host) == "internal":
            raw_data[key] = {"internal_host_not_sent": True}
            findings.append(_internal_finding(key))
            continue
        platform = platform_of(host)
        if platform is not None:
            raw_data[key] = {"uninformative": {"platform": platform.name, "kind": platform.kind}}
            findings.append(_uninformative_finding(key, platform))
            continue
        costly.append((key, url))
    # Risk-ordered, not first-listed: a link-heavy phish must not push its one suspicious link past the cap.
    # sorted() is stable, so equal priorities keep their first-seen order.
    priorities = {key: _unit_priority(key, url, parsed, policy) for key, url in costly}
    costly.sort(key=lambda item: -priorities[item[0]][0])
    to_enrich, skipped = costly[:MAX_URLS_TO_ENRICH], costly[MAX_URLS_TO_ENRICH:]
    hashes_to_enrich, hashes_skipped = hashes[:MAX_HASHES_TO_ENRICH], hashes[MAX_HASHES_TO_ENRICH:]
    label = "URL" if policy.path_query_providers else "host"

    for key, url in to_enrich:
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
                    code=finding_code("ENRICH_REPUTATION_HOST_SUSPICIOUS"),
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
                    code=finding_code("ENRICH_REPUTATION_HASH_KNOWN_MALICIOUS"),
                    description="; ".join(c["label"] for c in components) or "No specific signal breakdown.",
                    evidence={"components": components, "ioc_value": sha256, "filename": filename},
                    weight=float(score),
                )
            )
        provider_results = {"virustotal": result["vt"], "threatfox": result["threatfox"], "malwarebazaar": result["malwarebazaar"]}
        findings.extend(_incomplete_findings(sha256, provider_results))
        tally(provider_results)

    for key, _url in skipped:
        findings.append(_skip_finding(label.lower(), key, *priorities[key]))
    for sha256, _ in hashes_skipped:
        findings.append(_skip_finding("hash", sha256))

    if statuses:
        parts = [f"{p}: " + ", ".join(f"{s} x{n}" for s, n in sorted(c.items())) for p, c in sorted(statuses.items())]
        findings.append(
            Finding(
                module=MODULE_NAME,
                severity="info",
                title="Some enrichment providers did not give a usable answer",
                code=finding_code("ENRICH_PROVIDERS_NO_USABLE_ANSWER"),
                description=(
                    "Affected indicators are UNKNOWN (no answer), which is not the same as 'nothing found' (" + "; ".join(parts) + "). "
                    "Check provider API keys, ENRICHMENT_DISABLED_PROVIDERS, rate limits and connectivity."
                ),
                evidence={"providers": statuses},
                weight=0.0,
            )
        )

    _log_outcome(statuses, internal=sum(1 for v in raw_data.values() if isinstance(v, dict) and v.get("internal_host_not_sent")),
                 shared=sum(1 for v in raw_data.values() if isinstance(v, dict) and "uninformative" in v),
                 skipped=len(skipped) + len(hashes_skipped), looked_up=len(to_enrich) + len(hashes_to_enrich))
    return ModuleResult(module=MODULE_NAME, status="ok", findings=findings, raw_data=raw_data)


def _log_outcome(statuses: dict[str, dict[str, int]], internal: int, shared: int, skipped: int, looked_up: int) -> None:
    """One console line per analysis about everything that is UNKNOWN rather than answered, mirroring the findings the API returns. Counts
    only: no host, URL, hash or address is ever written to the log here."""
    if not (statuses or internal or shared or skipped):
        logger.info("enrichment: %d indicator(s) looked up, every provider answered", looked_up)
        return
    parts = [f"{p}: " + ", ".join(f"{s} x{n}" for s, n in sorted(c.items())) for p, c in sorted(statuses.items())]
    if internal:
        parts.append(f"{internal} internal-looking host(s) never sent (not looked up)")
    if shared:
        parts.append(f"{shared} shared-platform host(s) not looked up")
    if skipped:
        parts.append(f"{skipped} indicator(s) skipped by the per-email limit")
    logger.warning("enrichment: %d indicator(s) looked up; the rest is UNKNOWN (no answer), which is not the same as 'nothing found' (%s)", looked_up, "; ".join(parts))


__all__ = ["run_enrichment"]
