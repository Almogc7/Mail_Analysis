"""abuse.ch ThreatFox: an exact-match QUERY for confirmed malware-associated indicators (IP, domain, URL, hashes). A POST that only asks a
question: no data is submitted to the database. Needs a free abuse.ch Auth-Key."""
from __future__ import annotations

from typing import Any, Dict, List

from app.enrichment.providers.base import BaseClient


class ThreatFoxClient(BaseClient):
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
    SUPPORTED_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()
        if ioc_type not in self.SUPPORTED_TYPES:
            return self.not_applicable_result(f"ThreatFox does not support IOC type: {ioc_type}")

        headers = {"Auth-Key": self.api_key}
        payload = {"query": "search_ioc", "search_term": ioc_value, "exact_match": True}
        result = self.safe_post(self.BASE_URL, headers=headers, json_body=payload)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        data = result["data"]
        query_status = data.get("query_status")
        if query_status == "no_result":
            return self.ok_result(matched=False, match_count=0)
        if query_status != "ok":
            return self.error_result("failed", f"ThreatFox query_status={query_status}")

        matches = data.get("data") or []
        malware_families: List[str] = []
        threat_types: List[str] = []
        tags: List[str] = []
        for match in matches:
            family = match.get("malware_printable") or match.get("malware")
            if family and family not in malware_families:
                malware_families.append(family)
            threat_type = match.get("threat_type")
            if threat_type and threat_type not in threat_types:
                threat_types.append(threat_type)
            for tag in match.get("tags") or []:
                if tag not in tags:
                    tags.append(tag)

        confidence_level = max((match.get("confidence_level") or 0) for match in matches) if matches else 0

        return self.ok_result(
            matched=True,
            match_count=len(matches),
            malware_families=malware_families[:5],
            threat_types=threat_types[:5],
            tags=tags[:8],
            confidence_level=confidence_level,
            first_seen=matches[0].get("first_seen") if matches else None,
        )
