"""A fake HTTP session for provider tests: no network, no sleeping, every request recorded."""
from __future__ import annotations

from typing import Any

import pytest
import requests

from app.enrichment.providers import base


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Client Error", response=self)

    def json(self) -> Any:
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    """Plays queued responses (or raises queued exceptions) in order; the last one repeats."""

    def __init__(self) -> None:
        self.queue: list[Any] = []
        self.calls: list[dict[str, Any]] = []

    def respond(self, *items: Any) -> "FakeSession":
        self.queue = list(items)
        return self

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        item = self.queue[0] if len(self.queue) == 1 else self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_http(monkeypatch) -> FakeSession:
    session = FakeSession()
    monkeypatch.setattr(base.BaseClient, "session", session)
    monkeypatch.setattr(base.time, "sleep", lambda s: None)
    return session
