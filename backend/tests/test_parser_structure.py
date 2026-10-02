"""Structured Received hops and Received-SPF parsing (parser/normalize.py)."""
import pytest

from app.parser import parse_email_file
from app.parser.normalize import _parse_received_hop, _parse_received_spf
from tests.eval import FIXTURES

EXIM_LOCAL = (
    "from vnz73mailr by vh319.sweb.ru with local (Exim 4.99.4)\n\t(envelope-from <vnz73mailr@vh319.sweb.ru>)\n"
    "\tid 1xAKLo-00000001dvx-3Hlm\n\tfor recipient@example.com;\n\tSat, 26 Sep 2026 07:49:28 +0300"
)
EXTERNAL_TLS = (
    "from vh319.sweb.ru ([77.222.61.245])\n  by esa1.gateway.example.net with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; "
    "26 Sep 2026 07:49:29 +0300"
)
GATEWAY_WITH_CIPHER_COMMENT = (
    "from esa1.gateway.example.net (esa1.gateway.example.net [198.51.100.193])\n"
    "\t(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))\n\t(No client certificate requested)\n"
    "\tby Internal Gateway with ESMTPS id 00000000000000000000\n\tfor <recipient@example.com>; Sat, 26 Sep 2026 07:50:39 +0300 (IDT)"
)
EXCHANGE = (
    "from mbx-b.corp.example.com (192.0.2.33) by\n mbx-a2.corp.example.com (192.0.2.32) with Microsoft SMTP Server\n"
    " (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id\n 15.2.1748.24 via Mailbox Transport; Sat, 26 Sep 2026 07:50:22 +0300"
)
SUBMISSION = "from [203.0.113.5] (helo=laptop) by mail.example.com with ESMTPSA id abc123; Mon, 21 Sep 2026 10:00:00 +0000"
POSTFIX_PICKUP = "by host1.example.com (Postfix, from userid 1000)\n\tid ABC123; Mon, 21 Sep 2026 10:00:00 +0000"
IPV6 = "from mx.example.net (mx.example.net [IPv6:2001:db8::1]) by mx.example.org with ESMTPS; Mon, 21 Sep 2026 10:00:00 +0000"


def test_exim_local_submission():
    hop = _parse_received_hop(EXIM_LOCAL)
    assert hop.is_local_submission and hop.protocol == "local"
    assert hop.envelope_from == "vnz73mailr@vh319.sweb.ru"
    assert hop.from_ip is None and not hop.authenticated and not hop.tls
    assert hop.by_host == "vh319.sweb.ru" and hop.timestamp is not None


def test_external_hop_has_sender_ip_and_tls():
    hop = _parse_received_hop(EXTERNAL_TLS)
    assert hop.from_ip == "77.222.61.245" and hop.protocol == "ESMTP" and hop.tls
    assert not hop.is_local_submission


def test_cipher_comment_is_not_mistaken_for_the_protocol():
    hop = _parse_received_hop(GATEWAY_WITH_CIPHER_COMMENT)
    assert hop.protocol == "ESMTPS" and hop.tls and hop.from_ip == "198.51.100.193"


def test_exchange_hop():
    hop = _parse_received_hop(EXCHANGE)
    assert hop.from_ip == "192.0.2.33" and hop.protocol == "Microsoft" and hop.tls


def test_authenticated_submission():
    hop = _parse_received_hop(SUBMISSION)
    assert hop.authenticated and hop.tls and hop.from_ip == "203.0.113.5" and not hop.is_local_submission


def test_postfix_pickup_is_local_submission():
    assert _parse_received_hop(POSTFIX_PICKUP).is_local_submission


def test_ipv6_literal():
    assert _parse_received_hop(IPV6).from_ip == "2001:db8::1"


SPF_PASS = (
    "Pass (esa1.gateway.example.net: domain of\n  vnz73mailr@vh319.sweb.ru designates 77.222.61.245 as  permitted sender)\n"
    " identity=mailfrom; client-ip=77.222.61.245;\n  receiver=esa1.gateway.example.net;\n"
    '  envelope-from="vnz73mailr@vh319.sweb.ru";\n  x-sender="vnz73mailr@vh319.sweb.ru"; x-conformance=spf_only;\n'
    '  x-record-type="v=spf1"; x-record-text="v=spf1 ip4:77.222.61.245 include:_spf.example.net ~all"'
)


def test_received_spf_fields():
    spf = _parse_received_spf(SPF_PASS, 24)
    assert spf.result == "pass" and spf.header_index == 24
    assert spf.receiver == "esa1.gateway.example.net" and spf.client_ip == "77.222.61.245"
    assert spf.envelope_from == "vnz73mailr@vh319.sweb.ru" and spf.identity == "mailfrom"
    assert spf.x_conformance == "spf_only"


@pytest.mark.parametrize(
    "value,result",
    [
        ("SoftFail (mx.example.org: domain of x@example.com does not designate 192.0.2.1 as permitted sender)", "softfail"),
        ("None (mx.example.org: no sender authenticity information available)", "none"),
        ("neutral (mx.example.org: ...) receiver=mx.example.org", "neutral"),
        ("garbled", "unknown"),
    ],
)
def test_received_spf_result_words(value, result):
    assert _parse_received_spf(value, 0).result == result


def test_receiver_falls_back_to_comment_hostname():
    assert _parse_received_spf("Pass (mx.example.org: domain of a@example.com designates 192.0.2.1 as permitted sender)", 0).receiver == "mx.example.org"


def test_kvish6_fixture_chain_and_spf():
    path = FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
    parsed = parse_email_file(path.read_bytes(), path.name)
    first_hop = parsed.received_chain[-1]
    assert first_hop.is_local_submission and not first_hop.authenticated
    sender_hop = next(h for h in parsed.received_chain if h.from_ip == "77.222.61.245")
    assert sender_hop.from_host == "vh319.sweb.ru" and sender_hop.tls
    assert [h.protocol for h in parsed.received_chain].count("Microsoft") == 3
    (spf,) = parsed.received_spf
    assert spf.result == "pass" and spf.x_conformance == "spf_only" and spf.receiver == "esa1.gateway.example.net"
    # receiver names an ESA host that appears in the chain
    assert any(h.by_host == spf.receiver or h.from_host == spf.receiver for h in parsed.received_chain)
