import re
from typing import Any

import authres

# authres is a strict RFC 8601 parser and rejects real-world headers that deviate from the
# grammar in ways multiple mail providers (observed from real Microsoft/Office365-generated
# headers) actually produce: no authserv-id before the first resinfo, and/or a trailing ";"
# after the last resinfo. Both are handled by normalize-and-retry below rather than failing
# outright -- a parse failure here means SPF/DKIM/DMARC results are silently lost, which for
# a triage tool risks hiding a real DMARC fail behind what looks like "no data".
_LOOKS_LIKE_MISSING_AUTHSERV_ID = re.compile(r"^\s*(spf|dkim|dmarc)\s*=", re.IGNORECASE)
_METHOD_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


def _normalize_header_value(raw_header: str) -> str:
    value = raw_header.strip().rstrip(";").strip()
    if _LOOKS_LIKE_MISSING_AUTHSERV_ID.match(value):
        value = f"unknown-authserv; {value}"
    return value


def _regex_fallback_results(raw_header: str) -> dict[str, Any]:
    """Last-resort extraction when authres can't parse the header at all, even after
    normalization -- guarantees a pass/fail/etc. result is never fully lost just because
    of a structural quirk we haven't anticipated. No domain/property detail in this path."""
    results: dict[str, Any] = {}
    for method, value in _METHOD_RESULT_RE.findall(raw_header):
        results[method.lower()] = {"result": value.lower(), "reason": None, "properties": {}}
    return results


def _parse_one(raw_header: str) -> dict[str, Any]:
    """Parse a single Authentication-Results header value with `authres`.

    `authres` expects the header without the leading "Authentication-Results:" name,
    so callers must pass the header *value* only.
    """
    attempts = [raw_header]
    normalized = _normalize_header_value(raw_header)
    if normalized != raw_header:
        attempts.append(normalized)

    last_error: Exception | None = None
    for attempt in attempts:
        try:
            result = authres.AuthenticationResultsHeader.parse(f"Authentication-Results: {attempt}")
        except Exception as exc:
            last_error = exc
            continue

        results: dict[str, Any] = {}
        for r in result.results:
            method = getattr(r, "method", None)
            if method is None:
                continue
            properties = {f"{p.type}.{p.name}": p.value for p in getattr(r, "properties", [])}
            results[method] = {
                "result": getattr(r, "result", "unknown"),
                "reason": getattr(r, "reason", None),
                "properties": properties,
            }
        return {"authserv_id": result.authserv_id, "results": results, "raw": raw_header}

    fallback_results = _regex_fallback_results(raw_header)
    return {
        "parse_error": str(last_error),
        "raw": raw_header,
        "authserv_id": None,
        "results": fallback_results,
    }


def _extract_domain(properties: dict[str, str]) -> str | None:
    value = (
        properties.get("header.d")
        or properties.get("header.from")
        or properties.get("smtp.mailfrom")
        or properties.get("smtp.helo")
    )
    if value and "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value


def check_auth_headers(authentication_results_raw: list[str]) -> dict[str, Any]:
    """Parse every Authentication-Results header found on the message.

    There can legitimately be more than one (e.g. forwarded/relayed mail, each hop
    stamping its own). We surface all parsed instances and pick the first (closest to
    the final receiving MTA, since headers are prepended) as the primary one used for
    SPF/DKIM/DMARC findings — but nothing is hidden from the analyst.
    """
    parsed = [_parse_one(h) for h in authentication_results_raw]

    primary = parsed[0] if parsed else {"authserv_id": None, "results": {}, "raw": None}
    primary_results = primary.get("results", {})

    def _method(name: str) -> dict[str, Any]:
        entry = primary_results.get(name, {})
        return {
            "result": entry.get("result", "none"),
            "domain": _extract_domain(entry.get("properties", {})),
            "raw": primary.get("raw"),
        }

    return {
        "spf": _method("spf"),
        "dkim": _method("dkim"),
        "dmarc": _method("dmarc"),
        "header_present": bool(authentication_results_raw),
        "all_parsed": parsed,
        "primary_authserv_id": primary.get("authserv_id"),
    }


# --------------------------------------------------------------------------------------------
# Trust layer. check_auth_headers() above only PARSES. Anyone on the path -- including the
# sender -- can add an Authentication-Results or Received-SPF header saying "pass", so a result
# only counts when a configured trusted receiver demonstrably added it.
# --------------------------------------------------------------------------------------------

NOT_EVALUATED = "not_evaluated"
UNKNOWN_AUTHSERV = "unknown-authserv"  # placeholder _normalize_header_value inserts when none is present
_METHODS = ("spf", "dkim", "dmarc")


def _norm_host(host: str | None) -> str | None:
    return host.strip().strip("[]()<>.").lower() if host and host.strip() else None


def _hosts_equivalent(a: str, b: str) -> bool:
    # Tolerate a short name vs its FQDN ("mx" / "mx.example.org") and a bare domain vs a host
    # under it ("example.org" / "mx1.example.org"), in either direction. Whole labels only.
    return (
        a == b
        or a.endswith("." + b) or b.endswith("." + a)
        or a.startswith(b + ".") or b.startswith(a + ".")
    )


def _compile_patterns(patterns: list[str], warnings: list[str]) -> list[tuple[str, re.Pattern]]:
    compiled = []
    for pat in patterns:
        try:
            compiled.append((pat, re.compile(pat, re.IGNORECASE)))
        except re.error as exc:
            # Fail safe: an unusable pattern trusts nothing.
            warnings.append(f"invalid trusted-receiver pattern skipped: {exc}")
    return compiled


def _trust_basis(claimed_host: str | None, received_chain, compiled) -> dict[str, Any] | None:
    """The header's claimed host must match a trusted pattern AND be the `by` host of a hop in
    the Received chain (i.e. the message demonstrably passed through it). This cannot stop a
    sender from forging both a header and a matching Received line below the first trusted hop,
    so it assumes your perimeter gateway strips such headers on ingress -- see
    docs in .env.example."""
    host = _norm_host(claimed_host)
    if not host:
        return None
    for pattern, rx in compiled:
        if not rx.search(host):
            continue
        if host == UNKNOWN_AUTHSERV:
            # Some producers (e.g. Microsoft) write Authentication-Results with no authserv-id,
            # so no hop can be tied to the header. Trusted ONLY if the owner explicitly
            # configured a pattern matching the placeholder; the evidence says attribution
            # was impossible.
            return {"host": host, "pattern": pattern, "hop_index": None,
                    "note": "header has no authserv-id; which hop added it could not be verified"}
        for index, hop in enumerate(received_chain):
            hop_host = _norm_host(hop.by_host)
            if hop_host and _hosts_equivalent(host, hop_host) and rx.search(hop_host):
                return {"host": host, "pattern": pattern, "hop_index": index}
    return None


def _domain_of(address_or_domain: str | None) -> str | None:
    if not address_or_domain:
        return None
    return address_or_domain.rsplit("@", 1)[-1].strip().lower() or None


def evaluate_authentication(
    authentication_results_raw: list[str],
    received_spf: list,
    received_chain: list,
    trusted_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """SPF/DKIM/DMARC as established by TRUSTED receivers only.

    Each method is {result, evaluated, domain, source, trust_basis, reason, raw}. `result` is
    the receiver's verdict, or "not_evaluated" with a `reason`. Every claim found in the headers,
    trusted or not, is kept in `claims` so nothing is hidden from the analyst -- untrusted
    claims just never influence a verdict. A pass has no risk-reducing effect anywhere.

    `header_present` feeds scoring coverage and is True only when ALL THREE methods were evaluated
    by a trusted receiver. An SPF-only gateway (x-conformance=spf_only) therefore leaves
    coverage low instead of claiming full confidence on a third of the evidence. (A finer
    per-method coverage value arrives with the verdict-model commit.)
    """
    from app.config import TRUSTED_RECEIVER_PATTERNS

    patterns = TRUSTED_RECEIVER_PATTERNS if trusted_patterns is None else trusted_patterns
    warnings: list[str] = []
    compiled = _compile_patterns(list(patterns), warnings)

    parsed = [_parse_one(h) for h in authentication_results_raw]
    methods: dict[str, dict[str, Any]] = {
        m: {"result": NOT_EVALUATED, "evaluated": False, "domain": None, "source": None, "trust_basis": None,
            "reason": None, "raw": None}
        for m in _METHODS
    }
    claims: list[dict[str, Any]] = []
    spf_only_receiver: str | None = None

    for p in parsed:  # header order = closest to the final receiver first
        authserv = p.get("authserv_id")
        basis = _trust_basis(authserv, received_chain, compiled)
        for method, entry in p.get("results", {}).items():
            if method not in methods:
                continue
            props = entry.get("properties", {})
            claims.append({"source": "authentication-results", "host": authserv, "method": method,
                           "result": entry.get("result"), "trusted": basis is not None})
            if basis is not None and not methods[method]["evaluated"]:
                methods[method].update(
                    result=entry.get("result", "none"), evaluated=True, source="authentication-results",
                    trust_basis=basis, raw=p.get("raw"),
                    domain=_extract_domain(props),
                )

    for spf in received_spf:
        basis = _trust_basis(spf.receiver, received_chain, compiled)
        claims.append({"source": "received-spf", "host": spf.receiver, "method": "spf", "result": spf.result,
                       "trusted": basis is not None, "x_conformance": spf.x_conformance})
        if basis is None:
            continue
        if spf.x_conformance and spf.x_conformance.lower() == "spf_only":
            spf_only_receiver = basis["host"]
        if spf.result != "unknown" and not methods["spf"]["evaluated"]:
            methods["spf"].update(
                result=spf.result, evaluated=True, source="received-spf", trust_basis=basis, raw=spf.raw,
                domain=_domain_of(spf.envelope_from),
            )

    for name, m in methods.items():
        if m["evaluated"]:
            continue
        if name in ("dkim", "dmarc") and spf_only_receiver:
            m["reason"] = "receiver_evaluated_spf_only"
        elif not compiled:
            m["reason"] = "no_trusted_receivers_configured"
        elif any(c["method"] == name for c in claims):
            m["reason"] = "claim_from_untrusted_source"
        else:
            m["reason"] = "no_trusted_result"

    primary = next((p for p in parsed), {})
    return {
        **methods,
        "header_present": all(m["evaluated"] for m in methods.values()),
        "all_parsed": parsed,
        "primary_authserv_id": primary.get("authserv_id"),
        "claims": claims,
        "trusted_receivers_configured": bool(compiled),
        "warnings": warnings,
    }
