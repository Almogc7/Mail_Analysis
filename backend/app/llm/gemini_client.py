"""The optional LLM second opinion's chat backend: a callable (prompt: str) -> str around the google-genai SDK.

Originated in the author's IOC_Enricher project; maintained here independently. The module that builds the prompt (prompting.py) sends
tokenised finding titles only; this file only moves a string to the model and a string back. It is never reached unless LLM_ENABLED
is on (see app.llm).

Environment: GOOGLE_API_KEY (app.config), IOC_CHAT_MODEL (default gemini-flash-latest).
"""
from __future__ import annotations

import os
from typing import Any, Callable, Optional, Tuple

from app import config

CHAT_MODEL = os.getenv("IOC_CHAT_MODEL", "gemini-flash-latest")

ChatCallable = Callable[[str], str]

_client_fn: Optional[ChatCallable] = None


def _load_sdk() -> Tuple[Any, Any]:
    """Imported lazily so the app, and every test that does not use the LLM, never needs the SDK."""
    from google import genai
    from google.genai import errors as genai_errors

    return genai, genai_errors


def get_client() -> ChatCallable:
    """Returns the cached callable. Raises RuntimeError if GOOGLE_API_KEY is not configured; run_llm_opinion() catches that and turns it
    into an LLMOpinion(status="unavailable")."""
    global _client_fn
    if _client_fn is not None:
        return _client_fn

    if not config.GOOGLE_API_KEY:
        raise RuntimeError("GOOGLE_API_KEY is not configured")

    genai, genai_errors = _load_sdk()
    client = genai.Client(api_key=config.GOOGLE_API_KEY)

    def _call(prompt: str) -> str:
        try:
            response = client.models.generate_content(model=CHAT_MODEL, contents=prompt)
        except genai_errors.APIError as exc:
            raise RuntimeError(f"Chat model request failed: {exc.message}") from exc
        return response.text or ""

    _client_fn = _call
    return _client_fn


def get_model_name() -> str:
    """For LLMOpinion.model provenance. Never raises."""
    return CHAT_MODEL
