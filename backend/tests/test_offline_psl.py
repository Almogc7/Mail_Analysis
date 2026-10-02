"""tldextract must work fully offline: bundled public-suffix snapshot, no fetch, no cache.

Registrable-domain logic decides whether a sender domain belongs to a brand, so a silent
fallback to a network fetch (or to a wrong, naive 'last two labels' split) would change
verdicts depending on connectivity -- and leak lookups from an analysis box."""
import socket

import pytest
import tldextract

from app.shared import matching

# Multi-label public suffixes where a naive "last two labels" split gives the wrong answer.
CASES = [
    ("service.kvish6.co.il", "kvish6.co.il"),
    ("www.leumi.co.il", "leumi.co.il"),
    ("a.b.example.org.il", "example.org.il"),
    ("mail.example.co.uk", "example.co.uk"),
    ("x.y.example.com.au", "example.com.au"),
    ("vh319.sweb.ru", "sweb.ru"),
    ("u123.ct.sendgrid.net", "sendgrid.net"),
    ("deep.sub.example.com", "example.com"),
]


@pytest.fixture
def no_network(monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("network access attempted during an offline-only test")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


def test_module_extractor_is_configured_offline():
    ex = matching._EXTRACT
    assert ex.suffix_list_urls == ()  # no remote suffix list is ever requested
    assert ex.fallback_to_snapshot is True  # the bundled snapshot is the only source


@pytest.mark.parametrize("host,expected", CASES)
def test_fresh_offline_extractor_resolves_without_network(no_network, host, expected):
    # A FRESH extractor, so no earlier test can have warmed an in-memory suffix list.
    fresh = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    assert fresh(host).top_domain_under_public_suffix == expected


@pytest.mark.parametrize("host,expected", CASES)
def test_registrable_domain_helper_with_network_blocked(no_network, host, expected):
    assert matching.registrable_domain(host) == expected


def test_domain_matching_uses_registrable_domains_for_multilabel_suffixes(no_network):
    assert matching.domain_matches_any("service.kvish6.co.il", ["kvish6.co.il"])
    assert not matching.domain_matches_any("kvish6.co.il.evil.example.net", ["kvish6.co.il"])
    assert not matching.domain_matches_any("evil-kvish6.co.il", ["kvish6.co.il"])
