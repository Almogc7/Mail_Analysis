from typing import Any

import authres


def _parse_one(raw_header: str) -> dict[str, Any]:
    """Parse a single Authentication-Results header value with `authres`.

    `authres` expects the header without the leading "Authentication-Results:" name,
    so callers must pass the header *value* only.
    """
    try:
        result = authres.AuthenticationResultsHeader.parse(f"Authentication-Results: {raw_header}")
    except Exception as exc:
        return {"parse_error": str(exc), "raw": raw_header, "authserv_id": None, "results": {}}

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
