"""LLM: off by default; when on, only tokenized finding titles leave the machine."""
import json

import pytest

from app.contracts.findings import Finding, ModuleResult
from app.llm import run_llm_opinion
from app.llm.prompting import SYSTEM_PROMPT, Tokenizer, build_context, build_prompt
from app.scoring import build_analysis_result
from tests.eval import FIXTURES, analyze

OK_REPLY = json.dumps({"narrative": "Looks suspicious.", "flags": []})


def _fake_parsed():
    from app.contracts.email import EmailAddress, ParsedEmail

    return ParsedEmail(source_format="eml", from_=EmailAddress(address="a@example.com", domain="example.com"), raw_size_bytes=10)


def _result_with(*findings: Finding):
    auth = ModuleResult(module="auth_check", status="ok", findings=list(findings), raw_data={"auth_headers": {"header_present": True}})
    quiet = [ModuleResult(module=m, status="ok", findings=[], raw_data={}) for m in ("enrichment", "content_analysis")]
    return build_analysis_result(_fake_parsed(), [auth, *quiet])


# ---- off by default -------------------------------------------------------------------------------

def test_llm_is_disabled_by_default_in_the_shipped_config():
    from app import config

    assert config.LLM_ENABLED is False  # conftest flips app.llm.LLM_ENABLED for pipeline tests, never app.config


def test_when_disabled_nothing_is_constructed_or_sent(monkeypatch):
    monkeypatch.setattr("app.llm.LLM_ENABLED", False)
    touched = []
    monkeypatch.setattr("app.llm.gemini_client.get_client", lambda: touched.append("client") or (lambda p: OK_REPLY))
    monkeypatch.setattr("app.llm.gemini_client.get_model_name", lambda: touched.append("model") or "x")

    opinion = run_llm_opinion(_result_with())

    assert touched == []  # not even the bridge was imported or consulted
    assert opinion.status == "unavailable" and opinion.model == "none" and opinion.narrative == ""
    assert "LLM_ENABLED" in opinion.error and "nothing was sent" in opinion.error


def test_a_caller_that_passes_its_own_client_has_opted_in(monkeypatch):
    monkeypatch.setattr("app.llm.LLM_ENABLED", False)
    seen = []
    opinion = run_llm_opinion(_result_with(), chat_client=lambda prompt: seen.append(prompt) or OK_REPLY)
    assert opinion.status == "ok" and len(seen) == 1


def test_the_pipeline_with_the_llm_off_still_completes(monkeypatch):
    from app.api.pipeline import run_pipeline

    monkeypatch.setattr("app.llm.LLM_ENABLED", False)
    monkeypatch.setattr("app.enrichment.providers.get_clients", __import__("tests.test_analyze_route", fromlist=["x"])._stub_enrichment_clients)
    monkeypatch.setattr("app.enrichment.rate_limit.VTRateLimiter.wait_if_needed", lambda self: None)
    raw = (FIXTURES / "benign" / "synthetic" / "05_spf_only_small_business.eml").read_bytes()
    result = run_pipeline(raw, "x.eml")
    assert result.verdict and result.llm_opinion.status == "unavailable"


# ---- the tokenizer --------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,must_not_contain",
    [
        ("mail from vnz73mailr@vh319.sweb.ru", ["vnz73mailr", "sweb.ru", "vh319"]),
        ("link https://u1.ct.sendgrid.net/ls/click?upn=SECRET end", ["sendgrid", "SECRET", "upn"]),
        ("hop 192.0.2.7 and 2001:db8::1", ["192.0.2.7", "2001:db8"]),
        ("attachment Invoice_JohnSmith.pdf", ["JohnSmith", ".pdf"]),
        ("gateway MAILGW-NODE7 relayed", ["MAILGW"]),
        ("host esa1.gateway.example.net replied", ["esa1", "gateway.example.net"]),
        ("hash " + "ab" * 32, ["abab"]),
    ],
)
def test_identifying_strings_are_replaced(text, must_not_contain):
    out = Tokenizer().scrub(text)
    for fragment in must_not_contain:
        assert fragment not in out, (fragment, out)
    assert "<" in out and ">" in out


def test_placeholders_are_stable_distinct_and_typed():
    t = Tokenizer()
    out = t.scrub("a@x.example.com wrote to b@y.example.com and a@x.example.com again via https://z.example.org/p")
    assert out.count("<EMAIL_1>") == 2 and "<EMAIL_2>" in out and "<URL_1>" in out
    assert t.scrub("a@x.example.com") == "<EMAIL_1>"  # same value, same token across calls


def test_private_addresses_get_a_distinct_internal_kind():
    out = Tokenizer().scrub("from 192.0.2.7")  # documentation range is not routable => treated as internal
    assert "<INTERNAL_IP_1>" in out


def test_clock_times_versions_and_plain_words_are_left_alone():
    text = "Sat, 26 Sep 2026 07:49:29 id 15.2.1748.24 Possible display-name spoofing of 'kvish6'"
    assert Tokenizer().scrub(text) == text


def test_restore_round_trips_and_ignores_unknown_placeholders():
    t = Tokenizer()
    scrubbed = t.scrub("sender vnz73mailr@vh319.sweb.ru linked https://evil.example.net/x")
    assert t.restore(f"The sender {scrubbed.split()[1]} is odd, see <URL_9>.") == "The sender vnz73mailr@vh319.sweb.ru is odd, see <URL_9>."
    assert t.restore(scrubbed) == "sender vnz73mailr@vh319.sweb.ru linked https://evil.example.net/x"


# ---- what the prompt contains -----------------------------------------------------------------------

def test_descriptions_and_evidence_never_enter_the_prompt():
    finding = Finding(module="auth_check", severity="high", title="SPF check failed",
                      description="SECRET-DESCRIPTION for victim@corp.example.com",
                      evidence={"raw": "SECRET-EVIDENCE", "domain": "internal.corp"}, weight=25.0)
    prompt = build_prompt(_result_with(finding))
    assert "SPF check failed" in prompt
    for secret in ("SECRET-DESCRIPTION", "SECRET-EVIDENCE", "victim@", "internal.corp"):
        assert secret not in prompt


def test_the_prompt_tells_the_model_about_placeholders_and_titles_only():
    assert "placeholder" in SYSTEM_PROMPT and "TITLES" in SYSTEM_PROMPT


def test_a_findings_title_with_an_address_is_tokenized():
    finding = Finding(module="enrichment", severity="medium", title="Suspicious host: pay.evil-example.net",
                      description="d", weight=5.0)
    context = build_context(_result_with(finding))
    assert "pay.evil-example.net" not in context and "<HOST_1>" in context


def test_override_reasons_are_tokenized_too():
    finding = Finding(module="auth_check", severity="high", title="Possible display-name spoofing of 'kvish6'", description="d", weight=25.0)
    result = _result_with(finding)
    result.scoring.applied_overrides[0].reason = "see https://leak.example.net/x"  # a reason that names a URL
    assert "leak.example.net" not in build_context(result)


def test_the_real_kvish6_analysis_leaks_no_identifier_into_the_prompt():
    result = analyze(FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "clean")
    prompt = build_prompt(result)
    forbidden = [
        "sweb", "vh319", "77.222", "vnz73mailr", "kvish6.co.il", "service.", "sendgrid", "printernet", "walla",
        "example.com", "esa1", "gateway", "corp", "192.0.2", "198.51.100", "recipient", "nextopic", ".pdf",
    ]
    for fragment in forbidden:
        assert fragment not in prompt, fragment
    assert not any("֐" <= ch <= "׿" for ch in prompt)  # no Hebrew content of any kind
    assert "Verdict:" in prompt and "auth_check" in prompt and "Possible display-name spoofing of" in prompt


def test_the_model_reply_is_restored_for_the_analyst_but_never_the_other_way(monkeypatch):
    finding = Finding(module="enrichment", severity="medium", title="Suspicious host: pay.evil-example.net", description="d", weight=5.0)
    sent = []

    def client(prompt):
        sent.append(prompt)
        return json.dumps({"narrative": "Traffic to <HOST_1> is the concern.", "flags": ["Check <HOST_1> manually"]})

    opinion = run_llm_opinion(_result_with(finding), chat_client=client)
    assert "pay.evil-example.net" not in sent[0]
    assert opinion.narrative == "Traffic to pay.evil-example.net is the concern."
    assert opinion.flags == ["Check pay.evil-example.net manually"]
