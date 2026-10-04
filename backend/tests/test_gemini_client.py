"""First-party Gemini chat client: no key means a clear error, the SDK is only loaded on use, replies and errors are mapped, nothing else."""
import sys
import types

import pytest

from app import config
from app.llm import gemini_client


class _APIError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class _Models:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []

    def generate_content(self, model, contents):
        self.calls.append((model, contents))
        if self.error:
            raise self.error
        return types.SimpleNamespace(text=self.reply)


class _FakeGenai:
    def __init__(self, models):
        self.models = models
        self.keys = []

    def Client(self, api_key):  # noqa: N802 (mirrors the SDK)
        self.keys.append(api_key)
        return types.SimpleNamespace(models=self.models)


@pytest.fixture
def sdk(monkeypatch):
    models = _Models(reply="hello")
    genai = _FakeGenai(models)
    errors = types.SimpleNamespace(APIError=_APIError)
    monkeypatch.setattr(gemini_client, "_load_sdk", lambda: (genai, errors))
    monkeypatch.setattr(gemini_client, "_client_fn", None)
    monkeypatch.setattr(config, "GOOGLE_API_KEY", "test-key")
    return genai, models


def test_without_a_key_it_raises_the_documented_error_and_never_loads_the_sdk(monkeypatch):
    monkeypatch.setattr(gemini_client, "_client_fn", None)
    monkeypatch.setattr(config, "GOOGLE_API_KEY", None)
    monkeypatch.setattr(gemini_client, "_load_sdk", lambda: pytest.fail("SDK loaded without a key"))
    with pytest.raises(RuntimeError, match="GOOGLE_API_KEY is not configured"):
        gemini_client.get_client()


def test_a_prompt_goes_to_the_configured_model_and_the_text_comes_back(sdk):
    genai, models = sdk
    assert gemini_client.get_client()("the prompt") == "hello"
    assert models.calls == [(gemini_client.CHAT_MODEL, "the prompt")] and genai.keys == ["test-key"]


def test_the_callable_is_cached_so_the_sdk_client_is_built_once(sdk):
    genai, _ = sdk
    first = gemini_client.get_client()
    assert gemini_client.get_client() is first and genai.keys == ["test-key"]


def test_an_empty_reply_is_an_empty_string_never_none(sdk):
    _, models = sdk
    models.reply = None
    assert gemini_client.get_client()("p") == ""


def test_an_sdk_api_error_becomes_a_runtime_error_with_the_message(sdk):
    _, models = sdk
    models.error = _APIError("quota exceeded")
    with pytest.raises(RuntimeError, match="Chat model request failed: quota exceeded"):
        gemini_client.get_client()("p")


def test_the_model_name_never_raises_and_comes_from_ioc_chat_model_with_a_default(monkeypatch):
    assert gemini_client.get_model_name() == gemini_client.CHAT_MODEL and gemini_client.CHAT_MODEL
    monkeypatch.delenv("IOC_CHAT_MODEL", raising=False)
    import importlib

    assert importlib.reload(gemini_client).CHAT_MODEL == "gemini-flash-latest"
    monkeypatch.setenv("IOC_CHAT_MODEL", "some-other-model")
    assert importlib.reload(gemini_client).get_model_name() == "some-other-model"
    monkeypatch.delenv("IOC_CHAT_MODEL")
    importlib.reload(gemini_client)


def test_importing_the_module_does_not_import_the_sdk():
    sys.modules.pop("google.genai", None)
    import importlib

    importlib.reload(gemini_client)
    assert "google.genai" not in sys.modules
