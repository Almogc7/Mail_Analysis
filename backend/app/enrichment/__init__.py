from typing import Any

from app.config import MAX_HASHES_TO_ENRICH, MAX_URLS_TO_ENRICH
from app.contracts.email import ParsedEmail
from app.contracts.findings import Finding, ModuleResult
from app.enrichment import ioc_bridge
from app.enrichment.rate_limit import VTRateLimiter

MODULE_NAME = "enrichment"

_INCOMPLETE_STATUSES = {"rate_limited", "failed", "invalid_response"}


def _severity_for_score(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _collect_unique_urls(parsed: ParsedEmail) -> list[str]:
    seen: list[str] = []
    for u in parsed.urls:
        if u.url not in seen:
            seen.append(u.url)
    return seen


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
        if result.get("status") in _INCOMPLETE_STATUSES:
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity="info",
                    title=f"Enrichment incomplete for {ioc_value}",
                    description=(
                        f"{provider} did not return a usable result "
                        f"(status: {result.get('status')}). This IOC may not be fully evaluated."
                    ),
                    evidence={"provider": provider, "ioc_value": ioc_value, "result": result},
                    weight=0.0,
                )
            )
    return findings


def _enrich_url(url: str, clients: dict[str, Any], vt_limiter: VTRateLimiter) -> dict[str, Any]:
    vt_limiter.wait_if_needed()
    vt_result = clients["virustotal"].enrich(url, "url")
    urlscan_result = clients["urlscan"].enrich(url, "url")
    threatfox_result = clients["threatfox"].enrich(url, "url")

    explain = clients["risk_scorer"].explain(
        "url",
        vt=vt_result,
        abuse={},
        otx={},
        config=clients["score_config"],
        threatfox=threatfox_result,
        urlscan=urlscan_result,
    )

    return {
        "vt": vt_result,
        "urlscan": urlscan_result,
        "threatfox": threatfox_result,
        "risk_explain": explain,
    }


def _enrich_hash(sha256: str, clients: dict[str, Any], vt_limiter: VTRateLimiter) -> dict[str, Any]:
    vt_limiter.wait_if_needed()
    vt_result = clients["virustotal"].enrich(sha256, "sha256")
    threatfox_result = clients["threatfox"].enrich(sha256, "sha256")
    mb_result = clients["malwarebazaar"].enrich(sha256, "sha256")

    explain = clients["risk_scorer"].explain(
        "sha256",
        vt=vt_result,
        abuse={},
        otx={},
        config=clients["score_config"],
        threatfox=threatfox_result,
        malwarebazaar=mb_result,
    )

    return {
        "vt": vt_result,
        "threatfox": threatfox_result,
        "malwarebazaar": mb_result,
        "risk_explain": explain,
    }


def run_enrichment(
    parsed: ParsedEmail,
    clients: dict[str, Any] | None = None,
    vt_limiter: VTRateLimiter | None = None,
) -> ModuleResult:
    clients = clients if clients is not None else ioc_bridge.get_clients()
    vt_limiter = vt_limiter if vt_limiter is not None else VTRateLimiter()

    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}

    urls = _collect_unique_urls(parsed)
    hashes = _collect_unique_hashes(parsed)

    urls_to_enrich, urls_skipped = urls[:MAX_URLS_TO_ENRICH], urls[MAX_URLS_TO_ENRICH:]
    hashes_to_enrich, hashes_skipped = hashes[:MAX_HASHES_TO_ENRICH], hashes[MAX_HASHES_TO_ENRICH:]

    # _collect_unique_urls/_collect_unique_hashes already dedupe (e.g. the same URL
    # appearing in both body_text and body_html), so each unique IOC is looked up once.

    for url in urls_to_enrich:
        result = _enrich_url(url, clients, vt_limiter)
        raw_data[url] = result

        score = result["risk_explain"]["total"]
        if score > 0:
            components = result["risk_explain"]["components"]
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=_severity_for_score(score),
                    title=f"Suspicious URL: {url}",
                    description="; ".join(c["label"] for c in components) or "No specific signal breakdown.",
                    evidence={"components": components, "ioc_value": url},
                    weight=float(score),
                )
            )
        findings.extend(_incomplete_findings(url, {"virustotal": result["vt"], "urlscan": result["urlscan"], "threatfox": result["threatfox"]}))

    for sha256, filename in hashes_to_enrich:
        result = _enrich_hash(sha256, clients, vt_limiter)
        raw_data[sha256] = result

        score = result["risk_explain"]["total"]
        if score > 0:
            components = result["risk_explain"]["components"]
            label = filename or sha256
            findings.append(
                Finding(
                    module=MODULE_NAME,
                    severity=_severity_for_score(score),
                    title=f"Known-malicious attachment hash: {label}",
                    description="; ".join(c["label"] for c in components) or "No specific signal breakdown.",
                    evidence={"components": components, "ioc_value": sha256, "filename": filename},
                    weight=float(score),
                )
            )
        findings.extend(
            _incomplete_findings(
                sha256, {"virustotal": result["vt"], "threatfox": result["threatfox"], "malwarebazaar": result["malwarebazaar"]}
            )
        )

    for url in urls_skipped:
        findings.append(_skip_finding("url", url))
    for sha256, _ in hashes_skipped:
        findings.append(_skip_finding("hash", sha256))

    return ModuleResult(module=MODULE_NAME, status="ok", findings=findings, raw_data=raw_data)


__all__ = ["run_enrichment"]
