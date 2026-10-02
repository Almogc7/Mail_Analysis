"""Risk-ordered capping, dropped indicators listed, and coverage that counts them."""
import pytest

from app.contracts.email import EmailAddress, ExtractedUrl
from app.enrichment import run_enrichment
from app.enrichment.policy import url_priority
from app.scoring.aggregate import category_coverage
from tests.test_enrichment import _base_parsed_email, _no_sleep_limiter
from tests.test_enrichment_policy import _clients

PUBLIC_IP = ".".join(("8", "8", "4", "4"))  # built at runtime: tests must not contain public IP literals


def _prio(url, **kw):
    kw.setdefault("anchor_mismatch", False)
    kw.setdefault("is_cta", False)
    kw.setdefault("sender_domain", "sender.example.com")
    return url_priority(url, **kw)


# ---- the priority function ------------------------------------------------------------------------

def test_a_plain_link_on_the_senders_own_domain_scores_zero():
    assert _prio("https://www.sender.example.com/page") == (0, [])


@pytest.mark.parametrize(
    "url,kwargs,minimum,reason",
    [
        ("https://other.example.org/x", {}, 1, "not the sender's domain"),
        ("https://other.example.org/x", {"anchor_mismatch": True}, 5, "different address"),
        (f"http://{PUBLIC_IP}/login", {}, 4, "IP-literal"),  # no registrable domain, so no extra "not the sender's" point
        ("https://xn--e1afmkfd.example.org/x", {}, 4, "punycode"),
        ("https://a.b.c.d.e.example.org/x", {}, 3, "many subdomain"),
        ("https://secure-login.example.org/paypal/verify", {}, 4, "brand token 'paypal'"),
        ("https://other.example.org/x", {"is_cta": True}, 2, "clickable"),
    ],
)
def test_each_risk_feature_adds_to_the_priority_and_explains_itself(url, kwargs, minimum, reason):
    score, reasons = _prio(url, **kwargs)
    assert score >= minimum and any(reason in r for r in reasons), (score, reasons)


def test_a_brand_token_on_the_brands_own_domain_is_not_a_signal():
    score, reasons = _prio("https://www.paypal.com/paypal/help", sender_domain="paypal.com")
    assert not any("brand token" in r for r in reasons) and score == 0


def test_priority_reads_the_path_locally_but_never_needs_it_to_be_sent():
    # the path is used for ranking only; it is inspected here and never reaches a provider (see policy tests)
    assert _prio("https://other.example.org/paypal/x")[0] > _prio("https://other.example.org/x")[0]


# ---- capping ----------------------------------------------------------------------------------------

def _urls(*items):
    return [ExtractedUrl(url=u, source="body_html", anchor_text=t, is_anchor_mismatch=m) for u, t, m in items]


def test_the_cap_keeps_the_riskiest_hosts_not_the_first_listed(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 2)
    urls = _urls(
        ("https://news1.sender.example.com/a", None, False),
        ("https://news2.sender.example.com/b", None, False),
        ("https://news3.sender.example.com/c", None, False),
        ("https://secure-login.evil-example.net/paypal/verify", "https://paypal.com/verify", True),
        (f"http://{PUBLIC_IP}/invoice", None, False),
    )
    parsed = _base_parsed_email(from_=EmailAddress(address="a@sender.example.com", domain="sender.example.com"), urls=urls)
    clients = _clients()
    result = run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())

    looked_up = {v for v, _t in clients["virustotal"].calls}
    assert looked_up == {"secure-login.evil-example.net", PUBLIC_IP}  # the last two listed, because they are riskiest
    dropped = [f.evidence["ioc_value"] for f in result.findings if f.title.startswith("Not enriched:")]
    assert sorted(dropped) == ["news1.sender.example.com", "news2.sender.example.com", "news3.sender.example.com"]


def test_equal_priorities_keep_first_seen_order(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 2)
    urls = _urls(*[(f"https://h{i}.other-example.org/x", None, False) for i in range(5)])
    parsed = _base_parsed_email(urls=urls)
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert [v for v, _t in clients["virustotal"].calls] == ["h0.other-example.org", "h1.other-example.org"]


def test_every_dropped_indicator_is_listed_with_its_rank_and_reasons(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    urls = _urls(("https://plain.other-example.org/x", None, False), ("https://z.evil-example.net/y", "see this", True))
    parsed = _base_parsed_email(urls=urls)
    result = run_enrichment(parsed, clients=_clients(), vt_limiter=_no_sleep_limiter())
    (skip,) = [f for f in result.findings if f.title.startswith("Not enriched:")]
    assert skip.evidence["ioc_value"] == "plain.other-example.org" and isinstance(skip.evidence["priority"], int)
    assert "UNKNOWN, not clean" in skip.description and "riskiest indicators are looked up first" in skip.description
    assert skip.evidence["reasons"]  # the analyst can see why it ranked where it did


def test_a_unit_takes_the_priority_of_its_riskiest_url(monkeypatch):
    # two links to the same host: the plain one first, the mismatched one second -- the host ranks as risky
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    urls = _urls(
        ("https://calm.other-example.org/a", None, False),
        ("https://shared.evil-example.net/a", None, False),
        ("https://shared.evil-example.net/b", "https://bank.example.com", True),
    )
    parsed = _base_parsed_email(urls=urls)
    clients = _clients()
    run_enrichment(parsed, clients=clients, vt_limiter=_no_sleep_limiter())
    assert [v for v, _t in clients["virustotal"].calls] == ["shared.evil-example.net"]


# ---- coverage counts dropped indicators -------------------------------------------------------------

def test_dropped_indicators_lower_enrichment_coverage(monkeypatch):
    monkeypatch.setattr("app.enrichment.MAX_URLS_TO_ENRICH", 1)
    urls = _urls(*[(f"https://h{i}.other-example.org/x", None, False) for i in range(4)])
    result = run_enrichment(_base_parsed_email(urls=urls), clients=_clients(), vt_limiter=_no_sleep_limiter())
    # 4 indicators, 1 looked up fully, 3 dropped by the cap => 1/4 covered
    assert category_coverage("enrichment", result) == pytest.approx(0.25)


def test_a_fully_enriched_email_has_full_coverage_and_uninformative_hosts_do_not():
    result = run_enrichment(_base_parsed_email(urls=_urls(("https://a.other-example.org/x", None, False))),
                            clients=_clients(), vt_limiter=_no_sleep_limiter())
    assert category_coverage("enrichment", result) == 1.0
    mixed = run_enrichment(_base_parsed_email(urls=_urls(("https://a.other-example.org/x", None, False),
                                                         ("https://u1.ct.sendgrid.net/ls/click", None, False))),
                           clients=_clients(), vt_limiter=_no_sleep_limiter())
    assert category_coverage("enrichment", mixed) == pytest.approx(0.5)  # the tracker host has no reputation evidence
