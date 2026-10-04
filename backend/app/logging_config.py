"""Application logging, configured once at startup (app.main calls configure_logging() when the app is created).

The "app" logger gets its own stderr handler, so the warnings from the enrichment layer and the lookup providers show in the console
whether the app is started by uvicorn, run.ps1, Docker or a test; uvicorn's own loggers and the root logger are left alone, so nothing
is logged twice and no other library's logging changes. Level: LOG_LEVEL in the environment (default INFO).
"""
from __future__ import annotations

import logging
import os
import sys

LOGGER_NAME = "app"
FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


class _StderrHandler(logging.StreamHandler):
    """Writes to whatever sys.stderr is at the moment of each record (so a redirected or captured stderr is honoured)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr


def _resolve_level(level: str | int | None) -> int:
    value = level if level is not None else os.getenv("LOG_LEVEL") or "INFO"
    if isinstance(value, int):
        return value
    resolved = logging.getLevelName(str(value).strip().upper())
    return resolved if isinstance(resolved, int) else logging.INFO


def configure_logging(level: str | int | None = None) -> logging.Logger:
    """Idempotent: calling it again changes the level but never adds a second handler."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(_resolve_level(level))
    if not any(getattr(h, "_mail_analysis", False) for h in logger.handlers):
        handler = _StderrHandler()
        handler.setFormatter(logging.Formatter(FORMAT))
        handler._mail_analysis = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
        logger.propagate = False
    return logger
