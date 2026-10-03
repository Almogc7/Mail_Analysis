import pytest


@pytest.fixture(autouse=True)
def enable_llm_for_tests(monkeypatch):
    """The LLM module is OFF by default in production. Tests that exercise the pipeline inject stub clients
    and expect it to run, so it is switched on here; tests of the default itself override this to False."""
    monkeypatch.setattr("app.llm.LLM_ENABLED", True)


@pytest.fixture(autouse=True)
def restore_trust_configuration(monkeypatch):
    """tests.eval.apply_mode() assigns app.config.TRUSTED_RECEIVER_PATTERNS and KNOWN_SENDER_DOMAINS directly. Put both
    back after every test so a mode set by one test can never leak into the next (order-dependent verdicts)."""
    import app.config as app_config

    monkeypatch.setattr(app_config, "TRUSTED_RECEIVER_PATTERNS", list(app_config.TRUSTED_RECEIVER_PATTERNS))
    monkeypatch.setattr(app_config, "KNOWN_SENDER_DOMAINS", app_config.KNOWN_SENDER_DOMAINS)
