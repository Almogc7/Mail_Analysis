"""urlscan.io: read-only SEARCH of scans that already exist (GET /api/v1/search/). This client never submits a scan, so nothing is ever
scanned on the analyst's behalf and no visibility setting is involved: there is no code path that creates a public (or any) scan."""
from __future__ import annotations

from typing import Any, Dict

from app.enrichment.providers.base import BaseClient


class URLScanClient(BaseClient):
    BASE_URL = "https://urlscan.io/api/v1/search/"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()

        if ioc_type == "domain":
            query = f"domain:{ioc_value}"
        elif ioc_type == "url":
            query = f'page.url:"{ioc_value}"'
        elif ioc_type == "ip":
            query = f"ip:{ioc_value}"
        else:
            return self.not_applicable_result(f"URLScan.io does not support IOC type: {ioc_type}")

        headers = {"API-Key": self.api_key}
        params = {"q": query, "size": 5}

        result = self.safe_get(self.BASE_URL, headers=headers, params=params)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        data = result["data"]
        rows = data.get("results", [])
        return self.ok_result(
            query=query,
            total_results=data.get("total", len(rows)),
            sample_urls=[row.get("page", {}).get("url") for row in rows if row.get("page", {}).get("url")][:5],
            sample_domains=[row.get("page", {}).get("domain") for row in rows if row.get("page", {}).get("domain")][:5],
            sample_countries=[row.get("page", {}).get("country") for row in rows if row.get("page", {}).get("country")][:5],
            screenshots=[row.get("screenshot") for row in rows if row.get("screenshot")][:3],
        )
