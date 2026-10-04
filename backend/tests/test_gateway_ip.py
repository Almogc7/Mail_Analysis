"""The address of a trusted receiver itself is "your gateway": labelled as such and left out of the "N need a manual check" count. Display only: the full
indicator pack keeps it as a manual check, and coverage, blockers and the verdict are built from the full set."""
from datetime import datetime, timedelta, timezone

from app import config
from app.api import pipeline
from app.contracts.email import EmailAddress, ParsedEmail, ReceivedHop
from app.contracts.findings import ModuleResult
from app.hops import gateway_hop_indexes
from app.indicators import build_indicator_pack, visible_pack
from tests.eval import apply_mode

T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)
IP_SENDER, IP_GATEWAY, IP_OTHER = (".".join(p) for p in (("93", "184", "216", "34"), ("151", "101", "1", "69"), ("104", "16", "132", "229")))
IP_PRIVATE = ".".join(("10", "1", "2", "3"))
GATEWAY = "esa1.gateway.example.com"


def _mail(chain):
    return ParsedEmail(source_format="eml", raw_size_bytes=1, received_chain=chain,
                       from_=EmailAddress(display_name="A", address="a@sender.example.org", domain="sender.example.org"))


def _auth(trusted_newest_index):
    methods = {}
    if trusted_newest_index is not None:
        methods["spf"] = {"evaluated": True, "result": "pass", "trust_basis": {"host": GATEWAY, "hop_index": trusted_newest_index}}
    return ModuleResult(module="auth_check", status="ok", findings=[], raw_data={"auth_headers": {"trusted_receivers_configured": True, **methods}})


def _chain():
    """newest first: idx0 inside, idx1 SENT BY the gateway, idx2 is the hop that wrote the trusted result (the gateway received from the sender)."""
    return [
        ReceivedHop(raw="r3", from_host="mx.inside.example.net", by_host="mailbox.inside.example.net", from_ip=IP_PRIVATE, timestamp=T0 + timedelta(seconds=20)),
        ReceivedHop(raw="r2", from_host=GATEWAY, by_host="mx.inside.example.net", from_ip=IP_GATEWAY, timestamp=T0 + timedelta(seconds=10)),
        ReceivedHop(raw="r1", from_host="mail.sender.example.org", by_host=GATEWAY, from_ip=IP_SENDER, timestamp=T0),
    ]


def _by_value(pack):
    return {i.value: i for i in pack.indicators}


def test_the_hop_sent_by_the_trusted_receiver_is_the_gateway_hop_and_the_senders_hop_is_not():
    assert gateway_hop_indexes(_chain(), _auth(2)) == {1}


def test_with_no_trusted_hop_there_is_no_gateway():
    assert gateway_hop_indexes(_chain(), _auth(None)) == set() and gateway_hop_indexes(_chain(), None) == set()


def test_a_line_below_the_trusted_hop_that_names_the_gateway_is_never_a_gateway_hop():
    forged = _chain() + [ReceivedHop(raw="r0", from_host=GATEWAY, by_host="x.example.org", from_ip=IP_OTHER, timestamp=T0 - timedelta(seconds=5))]
    assert gateway_hop_indexes(forged, _auth(2)) == {1}  # the forged oldest hop (index 3) sits below the trusted hop
    pack = build_indicator_pack(_mail(forged), [_auth(2)])
    assert _by_value(pack)[IP_OTHER].gateway is False and _by_value(pack)[IP_OTHER].manual_check is True


def test_the_gateway_address_is_flagged_and_the_senders_address_is_not():
    pack = build_indicator_pack(_mail(_chain()), [_auth(2)])
    by = _by_value(pack)
    assert by[IP_GATEWAY].gateway is True
    assert by[IP_SENDER].gateway is False and by[IP_SENDER].manual_check is True  # where the mail came from still needs checking


def test_an_address_that_also_appears_somewhere_else_is_not_called_the_gateway():
    chain = _chain() + [ReceivedHop(raw="r0", from_host="old.example.org", by_host="x.example.org", from_ip=IP_GATEWAY)]
    assert _by_value(build_indicator_pack(_mail(chain), [_auth(2)]))[IP_GATEWAY].gateway is False


def test_the_full_pack_keeps_the_manual_check_and_only_the_response_pack_clears_it():
    full = build_indicator_pack(_mail(_chain()), [_auth(2)])
    assert _by_value(full)[IP_GATEWAY].manual_check is True and full.manual_check_count == sum(i.manual_check for i in full.indicators)
    shown = visible_pack(full)
    assert _by_value(shown)[IP_GATEWAY].manual_check is False and _by_value(shown)[IP_GATEWAY].gateway is True
    assert shown.manual_check_count == full.manual_check_count - 1 and IP_GATEWAY in _by_value(shown)  # still listed, just not counted
    assert _by_value(full)[IP_GATEWAY].manual_check is True  # the visible copy did not alter the full pack


def test_without_a_trusted_hop_the_same_address_is_an_ordinary_manual_check():
    full = build_indicator_pack(_mail(_chain()), [_auth(None)])
    pack = visible_pack(full)
    assert _by_value(pack)[IP_GATEWAY].gateway is False and _by_value(pack)[IP_GATEWAY].manual_check is True
    assert pack.manual_check_count == full.manual_check_count  # nothing was cleared


# ---- through the pipeline: only the display differs ------------------------------------------------------------------------------

RAW = ("\r\n".join([
    "Received: from mx.inside.example.net (mx.inside.example.net [" + IP_PRIVATE + "]) by mailbox.inside.example.net with ESMTP; Sun, 04 Oct 2026 09:00:20 +0000",
    "Received: from " + GATEWAY + " (" + GATEWAY + " [" + IP_GATEWAY + "]) by mx.inside.example.net with ESMTP; Sun, 04 Oct 2026 09:00:10 +0000",
    "Authentication-Results: " + GATEWAY + "; spf=pass smtp.mailfrom=sender.example.org",
    "Received: from mail.sender.example.org (mail.sender.example.org [" + IP_SENDER + "]) by " + GATEWAY + " with ESMTPS; Sun, 04 Oct 2026 09:00:00 +0000",
    "From: A <a@sender.example.org>", "To: t@example.com", "Subject: hello", "Message-ID: <1@sender.example.org>", "Date: Sun, 04 Oct 2026 09:00:00 +0000",
    "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "",
    "Hello, this is a short ordinary message with one link https://news.example.org/a to read.", ""])).encode()


def _run(monkeypatch, detect_gateway: bool):
    apply_mode("strict")
    monkeypatch.setattr(config, "TRUSTED_RECEIVER_PATTERNS", [r"^esa1\.gateway\.example\.com$"])
    if not detect_gateway:
        monkeypatch.setattr("app.indicators.gateway_hop_indexes", lambda chain, auth: set())
    monkeypatch.setattr(pipeline, "run_enrichment", lambda parsed: ModuleResult(module="enrichment", status="ok", findings=[], raw_data={}))
    monkeypatch.setattr(pipeline, "run_llm_opinion", lambda result: None)
    return pipeline.run_pipeline(RAW, "m.eml")


def test_labelling_the_gateway_changes_neither_verdict_nor_coverage_nor_blockers_nor_the_evidence(monkeypatch):
    labelled = _run(monkeypatch, True)
    plain = _run(monkeypatch, False)
    # not vacuous: the gateway address really is flagged and cleared in one run and an ordinary manual check in the other
    on, off = _by_value(labelled.indicators), _by_value(plain.indicators)
    assert on[IP_GATEWAY].gateway and on[IP_GATEWAY].manual_check is False
    assert not off[IP_GATEWAY].gateway and off[IP_GATEWAY].manual_check is True
    assert labelled.indicators.manual_check_count == plain.indicators.manual_check_count - 1
    assert (labelled.verdict, labelled.score, labelled.confidence) == (plain.verdict, plain.score, plain.confidence)
    assert labelled.scoring.model_dump() == plain.scoring.model_dump()
    assert [c.model_dump() for c in labelled.coverage_report] == [c.model_dump() for c in plain.coverage_report]
    assert [(c.area, c.subject) for c in labelled.coverage_report if c.blocks_no_indicators] == [(c.area, c.subject) for c in plain.coverage_report if c.blocks_no_indicators]
    assert labelled.evidence.model_dump() == plain.evidence.model_dump()
    a, b = labelled.model_dump(), plain.model_dump()
    a.pop("indicators"), b.pop("indicators")
    assert a == b
