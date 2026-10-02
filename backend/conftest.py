import pytest


@pytest.fixture(autouse=True)
def enable_llm_for_tests(monkeypatch):
    """The LLM module is OFF by default in production. Tests that exercise the pipeline inject stub clients
    and expect it to run, so it is switched on here; tests of the default itself override this to False."""
    monkeypatch.setattr("app.llm.LLM_ENABLED", True)
