"""Shared HTTP behaviour for the lookup providers: one session, bounded retries with back-off, and a uniform result shape.

This code originated in the author's IOC_Enricher project and is maintained here independently. Only read-only lookups exist: there is
no method that submits a URL or uploads a file anywhere. Every provider result is a dict whose "status" is "ok" only when the provider
really answered; anything else (disabled, not_applicable, rate_limited, failed, invalid_response) means the indicator is UNKNOWN,
never clean (see app.enrichment.__init__ and app.enrichment.policy).

Tunables (environment, same names as before): IOC_TIMEOUT_SECONDS (20), IOC_MAX_RETRIES (2), IOC_RETRY_BACKOFF_SECONDS (1.0).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from app import config as _config  # noqa: F401  (loads backend/.env before the tunables below are read, as the old import order did)

TIMEOUT = int(os.getenv("IOC_TIMEOUT_SECONDS", "20"))
MAX_RETRIES = int(os.getenv("IOC_MAX_RETRIES", "2"))
RETRY_BACKOFF_SECONDS = float(os.getenv("IOC_RETRY_BACKOFF_SECONDS", "1.0"))

logger = logging.getLogger(__name__)


class BaseClient:
    session = requests.Session()

    @staticmethod
    def disabled_result() -> Dict[str, Any]:
        return {"enabled": False, "status": "disabled"}

    @staticmethod
    def not_applicable_result(reason: str) -> Dict[str, Any]:
        return {"enabled": False, "status": "not_applicable", "error": reason}

    @staticmethod
    def ok_result(**kwargs: Any) -> Dict[str, Any]:
        return {"enabled": True, "status": "ok", **kwargs}

    @staticmethod
    def error_result(status: str, error: str, http_status: Optional[int] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"enabled": True, "status": status, "error": error}
        if http_status is not None:
            result["http_status"] = http_status
        return result

    def safe_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request("GET", url, headers=headers, params=params)

    def safe_post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request("POST", url, headers=headers, json_body=json_body, data=data)

    def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        provider_name = self.__class__.__name__
        last_error = "Request failed"
        last_status = "failed"
        last_http_status: Optional[int] = None

        for attempt in range(MAX_RETRIES + 1):
            started_at = time.perf_counter()
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    data=data,
                    timeout=TIMEOUT,
                )
                elapsed_ms = int((time.perf_counter() - started_at) * 1000)

                if response.status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                    last_http_status = response.status_code
                    logger.warning("%s rate limited after %sms url=%s", provider_name, elapsed_ms, url)
                elif 500 <= response.status_code < 600:
                    last_error = f"Provider server error ({response.status_code})"
                    last_status = "failed"
                    last_http_status = response.status_code
                    logger.warning(
                        "%s server error status=%s after %sms url=%s",
                        provider_name,
                        response.status_code,
                        elapsed_ms,
                        url,
                    )
                else:
                    response.raise_for_status()
                    try:
                        data = response.json()
                    except ValueError:
                        logger.error("%s returned invalid JSON url=%s", provider_name, url)
                        return {
                            "ok": False,
                            "status": "invalid_response",
                            "error": "Invalid JSON response",
                        }

                    logger.info("%s request succeeded in %sms url=%s", provider_name, elapsed_ms, url)
                    return {"ok": True, "data": data}

            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None
                logger.warning("%s network error attempt=%s url=%s error=%s", provider_name, attempt + 1, url, exc)
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                last_http_status = status_code
                if status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                else:
                    last_error = str(exc)
                    last_status = "failed"
                logger.warning(
                    "%s http error attempt=%s status=%s url=%s error=%s",
                    provider_name,
                    attempt + 1,
                    status_code,
                    url,
                    exc,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None
                logger.warning("%s request exception attempt=%s url=%s error=%s", provider_name, attempt + 1, url, exc)

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))

        return {
            "ok": False,
            "status": last_status,
            "error": last_error,
            "http_status": last_http_status,
        }
