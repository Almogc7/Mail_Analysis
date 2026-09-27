import time

from app.contracts.findings import Finding, ModuleResult
from app.llm import run_llm_opinion
from app.llm.prompting import build_context
from app.scoring import build_analysis_result


def _sample_analysis_result():
    auth = ModuleResult(
        module="auth_check",
        status="ok",
        findings=[
            Finding(
                module="auth_check",
                severity="high",
                title="SPF check failed",
                description="SPF authentication result was 'fail'.",
                evidence={"raw": "spf=fail", "domain": "evil.example.com"},
                weight=25.0,
            )
        ],
        raw_data={"auth_headers": {"header_present": True}},
    )
    enrichment = ModuleResult(module="enrichment", status="ok", findings=[], raw_data={})
    content = ModuleResult(module="content_analysis", status="ok", findings=[], raw_data=None)
    return build_analysis_result(_fake_parsed(), [auth, enrichment, content])


def _fake_parsed():
    from app.contracts.email import EmailAddress, ParsedEmail

    return ParsedEmail(
        source_format="eml",
        from_=EmailAddress(address="a@example.com", domain="example.com"),
        raw_size_bytes=10,
    )


def test_happy_path_parses_well_formed_json():
    def stub_client(prompt: str) -> str:
        return '{"narrative": "SPF failed, driving the suspicious verdict.", "flags": ["Check if this is a known forwarder"]}'

    opinion = run_llm_opinion(_sample_analysis_result(), chat_client=stub_client)

    assert opinion.status == "ok"
    assert "SPF failed" in opinion.narrative
    assert opinion.flags == ["Check if this is a known forwarder"]


def test_markdown_fenced_json_is_parsed_via_fallback():
    def stub_client(prompt: str) -> str:
        return '```json\n{"narrative": "Fenced narrative.", "flags": []}\n```'

    opinion = run_llm_opinion(_sample_analysis_result(), chat_client=stub_client)

    assert opinion.status == "ok"
    assert opinion.narrative == "Fenced narrative."
    assert opinion.flags == []


def test_unparseable_response_falls_back_to_raw_text_as_narrative():
    def stub_client(prompt: str) -> str:
        return "This email looks suspicious because the SPF check failed."

    opinion = run_llm_opinion(_sample_analysis_result(), chat_client=stub_client)

    assert opinion.status == "ok"
    assert opinion.narrative == "This email looks suspicious because the SPF check failed."
    assert opinion.flags == []


def test_client_construction_failure_is_unavailable(monkeypatch):
    def raising_get_client():
        raise RuntimeError("GOOGLE_API_KEY is not configured")

    monkeypatch.setattr("app.llm.gemini_bridge.get_client", raising_get_client)

    opinion = run_llm_opinion(_sample_analysis_result())

    assert opinion.status == "unavailable"
    assert "GOOGLE_API_KEY" in opinion.error


def test_client_invocation_failure_is_error():
    def stub_client(prompt: str) -> str:
        raise RuntimeError("Chat model request failed: rate limited")

    opinion = run_llm_opinion(_sample_analysis_result(), chat_client=stub_client)

    assert opinion.status == "error"
    assert "rate limited" in opinion.error


def test_timeout_is_error_and_does_not_hang():
    def slow_client(prompt: str) -> str:
        time.sleep(2)
        return '{"narrative": "too slow", "flags": []}'

    started = time.monotonic()
    opinion = run_llm_opinion(_sample_analysis_result(), chat_client=slow_client, timeout_seconds=0.1)
    elapsed = time.monotonic() - started

    assert opinion.status == "error"
    assert "timed out" in opinion.error
    assert elapsed < 1.0


def test_build_context_contains_verdict_score_and_finding_titles():
    context = build_context(_sample_analysis_result())

    assert "suspicious" in context
    assert "SPF check failed" in context
    assert "auth_check" in context
