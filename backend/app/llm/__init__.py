from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Callable

from app.config import LLM_ENABLED, LLM_TIMEOUT_SECONDS
from app.contracts.analysis import AnalysisResult
from app.contracts.llm_opinion import LLMOpinion
from app.llm import gemini_bridge
from app.llm.prompting import Tokenizer, build_prompt, parse_response


def run_llm_opinion(
    analysis_result: AnalysisResult,
    chat_client: Callable[[str], str] | None = None,
    timeout_seconds: float | None = None,
) -> LLMOpinion:
    """Never raises -- always returns an LLMOpinion. status="unavailable" means the LLM is disabled
    or the client couldn't even be constructed (e.g. no API key); status="error" means it was invoked
    but the call itself failed or timed out.

    OFF BY DEFAULT: unless LLM_ENABLED is set, nothing is sent to any external model. A caller that
    passes its own `chat_client` has opted in explicitly. When enabled, the prompt contains the verdict,
    numbers and finding TITLES only, with addresses, hostnames, URLs, file names, IPs and internal-looking
    names replaced by placeholders; the reply is mapped back to the real values locally."""
    timeout_seconds = timeout_seconds if timeout_seconds is not None else LLM_TIMEOUT_SECONDS

    if chat_client is None and not LLM_ENABLED:
        return LLMOpinion(
            narrative="", flags=[], model="none", status="unavailable",
            error="LLM is disabled (set LLM_ENABLED=1 to enable it); nothing was sent to an external model",
        )
    model_name = gemini_bridge.get_model_name()

    if chat_client is None:
        try:
            chat_client = gemini_bridge.get_client()
        except Exception as exc:
            return LLMOpinion(narrative="", flags=[], model=model_name, status="unavailable", error=str(exc))

    tokenizer = Tokenizer()
    prompt = build_prompt(analysis_result, tokenizer)

    # Not using ThreadPoolExecutor as a context manager: its __exit__ calls shutdown(wait=True),
    # which would block on the hung call anyway and defeat the timeout below. shutdown(wait=False)
    # lets us return immediately; the orphaned thread finishes (or errors) in the background.
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        raw_text = executor.submit(chat_client, prompt).result(timeout=timeout_seconds)
    except FutureTimeoutError:
        return LLMOpinion(
            narrative="",
            flags=[],
            model=model_name,
            status="error",
            error=f"Gemini request timed out after {timeout_seconds}s",
        )
    except Exception as exc:
        return LLMOpinion(narrative="", flags=[], model=model_name, status="error", error=str(exc))
    finally:
        executor.shutdown(wait=False)

    narrative, flags = parse_response(raw_text)
    # Put the real values back for the analyst (locally); the model only ever saw placeholders.
    return LLMOpinion(narrative=tokenizer.restore(narrative), flags=[tokenizer.restore(f) for f in flags],
                      model=model_name, status="ok")


def attach_llm_opinion(analysis_result: AnalysisResult, **kwargs) -> AnalysisResult:
    opinion = run_llm_opinion(analysis_result, **kwargs)
    return analysis_result.model_copy(update={"llm_opinion": opinion})


__all__ = ["run_llm_opinion", "attach_llm_opinion"]
