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
