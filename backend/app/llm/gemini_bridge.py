"""Bridge into the sibling IOC_Enricher repo's Gemini chat client.

Reuses only IOC_Enricher.api.chat.get_chat_client() -- a Callable[[str], str] wrapping
google-genai. Its build_prompt/build_grounding_context/generate_chat_reply are specific to
the IOC-batch chat assistant use case and are intentionally not reused here; Module 6
builds its own prompt/context logic around AnalysisResult instead (see prompting.py).
"""

from typing import Callable

from app.enrichment.ioc_bridge import ensure_ioc_enricher_on_path

CHAT_MODEL_FALLBACK = "gemini-flash-latest"


def get_client() -> Callable[[str], str]:
    """Returns get_chat_client()'s callable. Raises whatever that call raises (e.g.
    RuntimeError if GOOGLE_API_KEY isn't configured) -- run_llm_opinion() is responsible
    for catching that and turning it into an LLMOpinion(status="unavailable")."""
    ensure_ioc_enricher_on_path()
    from api.chat import get_chat_client

    return get_chat_client()


def get_model_name() -> str:
    """For LLMOpinion.model provenance. Best-effort -- falls back to a hardcoded default
    if IOC_Enricher isn't importable for some reason (shouldn't happen if get_client()
    already succeeded, but this must never itself raise)."""
    try:
        ensure_ioc_enricher_on_path()
        from api.chat import CHAT_MODEL

        return CHAT_MODEL
    except Exception:
        return CHAT_MODEL_FALLBACK
