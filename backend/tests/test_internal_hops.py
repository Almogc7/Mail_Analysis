"""INTERNAL_HOP_PATTERNS: hops added by the analyst's own infrastructure can be hidden from the page, and ONLY those.

Safety: a Received line below the first trusted hop was written by the sender and can claim anything, so it is never hidden (it is labelled
claimed / unverified). Hiding is display only: verdict, score, coverage and blockers are the same with hiding on and off."""
from datetime import datetime, timedelta, timezone

import pytest

from app import config
from app.api import pipeline
from app.contracts.email import EmailAddress, ParsedEmail, ReceivedHop
from app.contracts.findings import ModuleResult
from app.evidence import build_evidence
from app.hops import hidden_indexes, is_internal_hop, trust_boundary
from app.indicators import build_indicator_pack, visible_pack
from tests.eval import apply_mode

T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)
PATTERNS = [r"(^|\.)corp\.example\.net$", r"secsvc"]
# routable-looking and private addresses, built at runtime (the fixture guard forbids IP literals in tracked files)
IP_EXT, IP_SEC, IP_GW = (".".join(parts) for parts in (("93", "184", "216", "34"), ("151", "101", "1", "69"), ("104", "16", "132", "229")))
IP_PRIVATE = ".".join(("10", "1", "2", "3"))


def _mail(chain):
    return ParsedEmail(source_format="eml", raw_size_bytes=1, received_chain=chain,
                       from_=EmailAddress(display_name="A", address="a@sender.example.org", domain="sender.example.org"))


def _auth(trusted_newest_index: int | None) -> ModuleResult:
    """An auth module whose DKIM result was written by the hop at this newest-first index (None: nothing trusted)."""
    methods = {}
    if trusted_newest_index is not None:
        methods["dkim"] = {"evaluated": True, "result": "pass", "trust_basis": {"host": "edge.secsvc.example.com", "hop_index": trusted_newest_index}}
    return ModuleResult(module="auth_check", status="ok", findings=[], raw_data={"auth_headers": {"trusted_receivers_configured": True, **methods}})


def _chain():
    """newest first. Outside world -> security service -> gateway -> mailbox server."""
    return [
        ReceivedHop(raw="r3", from_host="gw.corp.example.net", by_host="mx.corp.example.net", from_ip=IP_GW, timestamp=T0 + timedelta(seconds=30)),
        ReceivedHop(raw="r2", from_host="relay.secsvc.example.com", by_host="gw.corp.example.net", from_ip=IP_SEC, timestamp=T0 + timedelta(seconds=20)),
        ReceivedHop(raw="r1", from_host="mail.sender.example.org", by_host="edge.secsvc.example.com", from_ip=IP_EXT, timestamp=T0),
    ]


TRUST_AT_OLDEST = _auth(2)  # the security service (the oldest hop) wrote the trusted result: everything newer is ours


@pytest.fixture
def internal(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_HOP_PATTERNS", PATTERNS)


# ---- what looks internal ------------------------------------------------------------------------------------------------------

def test_nothing_looks_internal_when_no_patterns_are_configured(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_HOP_PATTERNS", [])
    assert not any(is_internal_hop(h) for h in _chain())
    assert not any(h.internal for h in build_evidence(_mail(_chain()), [TRUST_AT_OLDEST]).hop_timeline)


def test_a_hop_sent_from_your_own_system_looks_internal_but_the_hop_that_hands_the_message_to_it_does_not(internal):
    r3, r2, r1 = _chain()
    assert is_internal_hop(r3) and is_internal_hop(r2)
    assert not is_internal_hop(r1)  # an outside server delivering to the security service: its address is the best evidence of the source


def test_a_machine_with_a_private_address_handing_the_message_to_your_system_looks_internal_even_if_its_own_name_does_not_match(internal):
    assert is_internal_hop(ReceivedHop(raw="x", from_host="mailer01", from_ip=IP_PRIVATE, by_host="relay.secsvc.example.com"))
    assert is_internal_hop(ReceivedHop(raw="x", from_host=None, from_ip=None, by_host="gw.corp.example.net"))  # nothing known about the sender side
    assert not is_internal_hop(ReceivedHop(raw="x", from_host="mailer01", from_ip=IP_EXT, by_host="gw.corp.example.net"))  # public sender: shown
    assert not is_internal_hop(ReceivedHop(raw="x", from_host="mailer01", from_ip=IP_PRIVATE, by_host="other.example.org"))  # receiver is not yours


def test_matching_is_case_insensitive_ignores_a_trailing_dot_and_a_missing_host(internal):
    assert is_internal_hop(ReceivedHop(raw="x", from_host="GW.CORP.EXAMPLE.NET."))
    assert not is_internal_hop(ReceivedHop(raw="x", from_host=None, from_ip=IP_EXT, by_host="gw.corp.example.net"))


def test_an_invalid_pattern_fails_loudly_not_silently(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_HOP_PATTERNS", ["(unclosed"])
    with pytest.raises(ValueError, match="INTERNAL_HOP_PATTERNS"):
        is_internal_hop(ReceivedHop(raw="x", from_host="a.example.org"))


# ---- the trust boundary -------------------------------------------------------------------------------------------------------

def test_the_boundary_is_the_oldest_trusted_hop_and_absent_when_nothing_is_trusted():
    assert trust_boundary(_auth(2)) == 2 and trust_boundary(_auth(0)) == 0 and trust_boundary(_auth(None)) is None and trust_boundary(None) is None
    both = ModuleResult(module="auth_check", status="ok", findings=[], raw_data={"auth_headers": {
        "dkim": {"evaluated": True, "trust_basis": {"hop_index": 1}}, "spf": {"evaluated": True, "trust_basis": {"hop_index": 3}}}})
    assert trust_boundary(both) == 3
    unevaluated = ModuleResult(module="auth_check", status="ok", findings=[], raw_data={"auth_headers": {"dkim": {"evaluated": False, "trust_basis": {"hop_index": 1}}}})
    assert trust_boundary(unevaluated) is None
    failed = ModuleResult(module="auth_check", status="error", findings=[], raw_data={})
    assert trust_boundary(failed) is None


def test_without_a_trusted_hop_nothing_is_hidden_and_every_hop_is_labelled_unverified(internal):
    for auth in (None, _auth(None)):
        assert hidden_indexes(_chain(), auth) == set()
        timeline = build_evidence(_mail(_chain()), [auth] if auth else []).hop_timeline
        assert not any(h.internal for h in timeline) and all(h.unverified for h in timeline)
        assert timeline[2].from_host == "gw.corp.example.net"  # names are still there


def test_hops_at_or_above_the_trusted_hop_are_hidden_and_the_trusted_hop_and_those_above_it_are_not_labelled_unverified(internal):
    timeline = build_evidence(_mail(_chain()), [TRUST_AT_OLDEST]).hop_timeline
    assert [h.index for h in timeline] == [1, 2, 3] and [h.internal for h in timeline] == [False, True, True]
    assert [h.unverified for h in timeline] == [False, False, False]  # boundary is the oldest hop, so nothing is below it
    assert [h.delay_seconds_from_previous for h in timeline] == [None, 20.0, 10.0]  # timing stays truthful across the hidden hops
    for hidden in timeline[1:]:
        assert (hidden.from_host, hidden.by_host, hidden.from_ip, hidden.protocol) == (None, None, None, None) and hidden.timestamp is not None
    assert timeline[0].from_ip == IP_EXT and timeline[0].by_host == "edge.secsvc.example.com"
    assert "corp.example.net" not in build_evidence(_mail(_chain()), [TRUST_AT_OLDEST]).model_dump_json()


def _forged_chain():
    """newest first. idx0 is ours; idx1 wrote the trusted result; idx2 and idx3 sit BELOW it and were written by the sender, who forges internal names."""
    return [
        ReceivedHop(raw="g0", from_host="gw.corp.example.net", by_host="mx.corp.example.net", from_ip=IP_GW, timestamp=T0 + timedelta(seconds=40)),
        ReceivedHop(raw="g1", from_host="relay.example.org", by_host="edge.secsvc.example.com", from_ip=IP_EXT, timestamp=T0 + timedelta(seconds=30)),
        # forged: claims one of our hosts as the sender, with a private address
        ReceivedHop(raw="g2", from_host="gw.corp.example.net", by_host="relay.example.org", from_ip=IP_PRIVATE, timestamp=T0 + timedelta(seconds=20)),
        # forged: claims to be handed over to our security service by a public address the attacker wants out of sight
        ReceivedHop(raw="g3", from_host="mailer.corp.example.net", by_host="relay.secsvc.example.com", from_ip=IP_SEC, timestamp=T0 + timedelta(seconds=10)),
    ]


def test_a_forged_received_line_that_claims_an_internal_host_below_the_trust_boundary_stays_visible_and_is_labelled_unverified(internal):
    auth = _auth(1)
    assert hidden_indexes(_forged_chain(), auth) == {0}  # only the hop above the boundary
    timeline = build_evidence(_mail(_forged_chain()), [auth]).hop_timeline
    assert [h.internal for h in timeline] == [False, False, False, True]
    assert [h.unverified for h in timeline] == [True, True, False, False]  # oldest first: g3, g2 below the boundary; g1 trusted; g0 above
    forged = timeline[0], timeline[1]
    assert forged[0].from_host == "mailer.corp.example.net" and forged[1].from_host == "gw.corp.example.net" and forged[1].from_ip == IP_PRIVATE


def test_a_forged_internal_claim_below_the_boundary_cannot_hide_an_address_from_the_indicator_list(internal):
    chain = _forged_chain()
    pack = build_indicator_pack(_mail(chain), [_auth(1)])
    shown = {i.value for i in visible_pack(pack).indicators}
    assert IP_SEC in shown  # the forged hop's public address is still listed
    assert IP_EXT in shown  # the trusted hop's `from` is the outside server: shown
    full = {i.value: i.hidden_by_config for i in pack.indicators}
    assert full[IP_SEC] is False and full[IP_EXT] is False
    assert IP_GW in full and full[IP_GW] is True and IP_GW not in shown  # the genuinely internal hop above the boundary is hidden


def test_a_hop_below_the_boundary_is_never_hidden_even_when_it_is_the_oldest_and_origin(internal):
    forged_origin = [
        ReceivedHop(raw="a", from_host="gw.corp.example.net", by_host="mx.corp.example.net", from_ip=IP_GW),
        ReceivedHop(raw="b", from_host="evil.example.org", by_host="edge.secsvc.example.com", from_ip=IP_EXT),
        ReceivedHop(raw="c", from_host="relay.secsvc.example.com", by_host="evil.example.org", from_ip=IP_SEC),  # forged origin
    ]
    timeline = build_evidence(_mail(forged_origin), [_auth(1)]).hop_timeline
    assert timeline[0].is_origin and not timeline[0].internal and timeline[0].unverified and timeline[0].from_host == "relay.secsvc.example.com"


# ---- indicators ---------------------------------------------------------------------------------------------------------------

def test_hidden_hops_are_flagged_in_the_full_pack_and_counted_but_not_named_in_the_response_pack(internal):
    pack = build_indicator_pack(_mail(_chain()), [TRUST_AT_OLDEST])
    flagged = {i.value for i in pack.indicators if i.hidden_by_config}
    assert flagged == {IP_GW, IP_SEC}  # the full pack still holds them: coverage and blockers are built from it
    response = visible_pack(pack)
    values = {i.value for i in response.indicators}
    assert IP_EXT in values and "mail.sender.example.org" in values
    assert not values & {IP_GW, IP_SEC}
    assert response.hidden_by_config_count == 2 and len(response.indicators) == len(pack.indicators) - 2
    assert response.counts == {k: sum(1 for i in response.indicators if i.kind == k) for k in response.counts}


def test_an_address_that_also_appears_outside_a_hidden_hop_is_not_hidden(internal):
    chain = _chain()
    mail = _mail(chain).model_copy(update={"urls": []})
    pack = build_indicator_pack(mail, [TRUST_AT_OLDEST])
    # IP_SEC is only in a hidden hop here; add a visible use of the same address (the Received hop of an unrelated, visible hop)
    chain.append(ReceivedHop(raw="r0", from_host="old.example.org", by_host="x.example.org", from_ip=IP_SEC))
    pack = build_indicator_pack(_mail(chain), [_auth(3)])
    assert {i.value: i.hidden_by_config for i in pack.indicators}[IP_SEC] is False


def test_without_patterns_the_same_hops_are_indicators_and_nothing_is_counted_hidden(monkeypatch):
    monkeypatch.setattr(config, "INTERNAL_HOP_PATTERNS", [])
    pack = build_indicator_pack(_mail(_chain()), [TRUST_AT_OLDEST])
    assert {IP_GW, IP_SEC, IP_EXT} <= {i.value for i in pack.indicators}
    assert visible_pack(pack).hidden_by_config_count == 0 and len(visible_pack(pack).indicators) == len(pack.indicators)


def test_visible_pack_of_nothing_is_nothing():
    assert visible_pack(None) is None


# ---- hiding is display only: same verdict, coverage and blockers --------------------------------------------------------------

RAW = ("\r\n".join([
    "Received: from gw.corp.example.net (gw.corp.example.net [" + IP_PRIVATE + "]) by mx.corp.example.net with ESMTP; Sun, 04 Oct 2026 09:00:30 +0000",
    "Received: from relay.secsvc.example.com (relay.secsvc.example.com [" + IP_SEC + "]) by gw.corp.example.net with ESMTP; Sun, 04 Oct 2026 09:00:20 +0000",
    "Authentication-Results: edge.secsvc.example.com; spf=pass smtp.mailfrom=sender.example.org; dkim=pass header.d=sender.example.org; dmarc=pass header.from=sender.example.org",
    "Received: from mail.sender.example.org (mail.sender.example.org [" + IP_EXT + "]) by edge.secsvc.example.com with ESMTPS; Sun, 04 Oct 2026 09:00:00 +0000",
    "From: A <a@sender.example.org>", "To: t@example.com", "Subject: hello", "Message-ID: <1@sender.example.org>", "Date: Sun, 04 Oct 2026 09:00:00 +0000",
    "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "",
    "Hello, this is a short ordinary message with one link https://news.example.org/a to read.", ""])).encode()


def _run(monkeypatch, patterns):
    apply_mode("strict")
    monkeypatch.setattr(config, "TRUSTED_RECEIVER_PATTERNS", [r"^edge\.secsvc\.example\.com$"])
    monkeypatch.setattr(config, "INTERNAL_HOP_PATTERNS", patterns)
    monkeypatch.setattr(pipeline, "run_enrichment", lambda parsed: ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}))
    monkeypatch.setattr(pipeline, "run_llm_opinion", lambda result: None)
    return pipeline.run_pipeline(RAW, "m.eml")


def test_hiding_hops_changes_neither_verdict_nor_coverage_nor_blockers_nor_any_scoring_input(monkeypatch):
    shown = _run(monkeypatch, [])
    hidden = _run(monkeypatch, PATTERNS)
    # the test is not vacuous: with the patterns on, hops really were hidden and an indicator really was left out of the response
    assert not any(h.internal for h in shown.evidence.hop_timeline)
    assert [h.internal for h in hidden.evidence.hop_timeline] == [False, True, True]
    # one indicator: the security service's public address (the gateway hop's address is private, so it was never an indicator)
    assert hidden.indicators.hidden_by_config_count == 1 and shown.indicators.hidden_by_config_count == 0
    assert IP_SEC in {i.value for i in shown.indicators.indicators} and IP_SEC not in {i.value for i in hidden.indicators.indicators}
    assert (shown.verdict, shown.score, shown.confidence) == (hidden.verdict, hidden.score, hidden.confidence)
    assert shown.scoring.model_dump() == hidden.scoring.model_dump()
    assert [f.model_dump() for f in shown.findings] == [f.model_dump() for f in hidden.findings]
    assert [m.model_dump() for m in shown.module_results] == [m.model_dump() for m in hidden.module_results]
    assert [c.model_dump() for c in shown.coverage_report] == [c.model_dump() for c in hidden.coverage_report]
    blockers = lambda r: [(c.area, c.subject) for c in r.coverage_report if c.blocks_no_indicators]
    assert blockers(shown) == blockers(hidden)
    # everything else in the response is identical too: only the hop rows and the indicator list differ
    a, b = shown.model_dump(), hidden.model_dump()
    for d in (a, b):
        d["evidence"].pop("hop_timeline")
        d.pop("indicators")
    assert a == b


def test_the_raw_headers_are_never_touched_by_hiding(monkeypatch):
    shown = _run(monkeypatch, [])
    hidden = _run(monkeypatch, PATTERNS)
    assert shown.parsed_email.headers == hidden.parsed_email.headers
    assert shown.parsed_email.received_chain == hidden.parsed_email.received_chain
    assert any(h.name.lower() == "received" and "gw.corp.example.net" in h.value for h in hidden.parsed_email.headers)


def test_the_setting_is_read_from_a_json_array_in_the_environment(monkeypatch):
    monkeypatch.setenv("INTERNAL_HOP_PATTERNS", '["a\\\\.example"]')
    assert config._json_pattern_list("INTERNAL_HOP_PATTERNS") == ["a\\.example"]
    monkeypatch.setenv("INTERNAL_HOP_PATTERNS", "not json")
    with pytest.raises(ValueError):
        config._json_pattern_list("INTERNAL_HOP_PATTERNS")
