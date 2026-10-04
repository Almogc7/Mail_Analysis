"""VirusTotal v3: read-only GET lookups of a domain, IP, file hash or URL report. Nothing is ever uploaded or submitted."""
from __future__ import annotations

import base64
from typing import Any, Dict

from app.enrichment.providers.base import BaseClient


class VirusTotalClient(BaseClient):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _encode_vt_url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()

        headers = {"x-apikey": self.api_key}

        if ioc_type == "ip":
            url = f"{self.BASE_URL}/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            url = f"{self.BASE_URL}/domains/{ioc_value}"
        elif ioc_type in {"md5", "sha1", "sha256"}:
            url = f"{self.BASE_URL}/files/{ioc_value}"
        elif ioc_type == "url":
            vt_url_id = self._encode_vt_url_id(ioc_value)
            url = f"{self.BASE_URL}/urls/{vt_url_id}"
        else:
            return self.not_applicable_result(f"VirusTotal does not support IOC type: {ioc_type}")

        result = self.safe_get(url, headers=headers)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        attributes = result["data"].get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return self.ok_result(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attributes.get("reputation"),
            tags=attributes.get("tags", []),
            categories=attributes.get("categories", {}),
        )
