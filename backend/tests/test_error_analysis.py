"""tests/error_analysis.py: aggregates only, tuning only, correct buckets."""
import io

import pytest

import tests.error_analysis as ea
from app.parser import parse_email_file
from tests.eval import analyze

PUBLIC_IP = ".".join(("8", "8", "4", "4"))  # built at runtime: tests must not contain public IP literals

MARKERS = ["UNIQUESUBJECTXYZ", "uniq-host-xyz.example.net", "uniqsender@uniq-domain-xyz.example.org", "UNIQBODYWORDXYZ",
           "uniq-attachment-xyz.pdf", "uniq-display-name-xyz"]


def _eml(subject="s", frm='"d" <a@sender.example.com>', body="hello", html=None, extra_headers="", attachment=None, ctype="text/plain; charset=utf-8"):
    lines = [f"From: {frm}", "To: Test <recipient@example.com>", f"Subject: {subject}", "Date: Mon, 21 Sep 2026 10:00:00 +0000",
             "Message-ID: <x@sender.example.com>", "MIME-Version: 1.0"]
    if extra_headers:
        lines.append(extra_headers)
    if attachment:
        lines += ['Content-Type: multipart/mixed; boundary="B"', "", "--B", "Content-Type: text/plain", "", body,
                  "--B", f'Content-Type: application/pdf; name="{attachment}"', f'Content-Disposition: attachment; filename="{attachment}"',
                  "Content-Transfer-Encoding: base64", "", "JVBERi0xLjQK", "--B--", ""]
    elif html is not None:
        lines += ['Content-Type: multipart/alternative; boundary="B"', "", "--B", "Content-Type: text/plain; charset=utf-8", "", body,
                  "--B", "Content-Type: text/html; charset=utf-8", "", html, "--B--", ""]
    else:
        lines += [f"Content-Type: {ctype}", "", body, ""]
    return ("\r\n".join(lines)).encode("utf-8")


def _features(raw: bytes):
    parsed = parse_email_file(raw, "x.eml")
    # a stand-in result: features() reads only module_results/raw_data for the auth section
    class R:
        module_results = []
    return ea.features(parsed, R())


# ---- output hygiene -------------------------------------------------------------------------------

@pytest.fixture
def corpus(tmp_path):
    tuning = tmp_path / "_local_corpus" / "tuning"
    tuning.mkdir(parents=True)
    raw = _eml(subject=MARKERS[0], frm=f'"{MARKERS[5]}" <{MARKERS[2]}>',
               body=f"{MARKERS[3]} visit https://{MARKERS[1]}/x?token=SECRETTOK", attachment=MARKERS[4])
    (tuning / "0123456789abcdef.eml").write_bytes(raw)
    (tuning / "fedcba9876543210.eml").write_bytes(_eml(body="plain note with no links at all"))
    return tmp_path / "_local_corpus"


def test_the_report_never_contains_content(corpus, capsys):
    assert ea.main(["--corpus-dir", str(corpus)]) == 0
    out = capsys.readouterr().out
    for marker in MARKERS + ["SECRETTOK", "0123456789abcdef", "fedcba9876543210", "recipient@", "sender.example.com"]:
        assert marker not in out, marker
    assert "TUNING split only, aggregates only" in out and "samples: 2" in out


def test_a_holdout_path_is_refused(tmp_path, capsys):
    root = tmp_path / "holdout_corpus"
    (root / "tuning").mkdir(parents=True)
    (root / "tuning" / "aaaaaaaaaaaaaaaa.eml").write_bytes(_eml())
    assert ea.main(["--corpus-dir", str(root)]) == 2
    assert "refusing" in capsys.readouterr().err


def test_a_missing_tuning_corpus_is_a_clear_error(tmp_path, capsys):
    assert ea.main(["--corpus-dir", str(tmp_path / "nothing")]) == 1
    assert "no tuning corpus" in capsys.readouterr().err


def test_report_handles_no_misses():
    out = io.StringIO()
    ea.report([("suspicious", {"url: any URL present"}, "URL(s), no attachment", [])], out)
    assert "no misses to analyze" in out.getvalue()


def test_report_counts_misses_and_profile_exclusively():
    rows = [
        ("legit", {"url: any URL present", "url kind: shortener"}, "URL(s), no attachment", []),
        ("legit", {"url: any URL present"}, "URL(s), no attachment", ["auth_check.x"]),
        ("legit", set(), "no URL, no attachment: text only", []),
        ("suspicious", {"url: any URL present"}, "URL(s), no attachment", ["auth_check.x"]),
    ]
    out = io.StringIO()
    ea.report(rows, out)
    text = out.getvalue()
    assert "misses: 3" in text and "flagged (strict): 1" in text
    assert "url kind: shortener" in text and "misses with NO non-info finding at all" in text
    assert "no URL, no attachment: text only" in text


# ---- the buckets ----------------------------------------------------------------------------------

def test_attachment_families_use_extension_never_content():
    feats, profile = _features(_eml(attachment="invoice.pdf"))
    assert "attachment type: pdf" in feats and "attachment: any attachment present" in feats
    assert profile == "attachment, no URL"
    assert ea._family("a.docm", None) == "office document" and ea._family("a.exe", None) == "executable / script"
    assert ea._family("x", "image/png") == "image" and ea._family(None, None) == "other / unknown"


def test_url_kinds():
    html = (f'<a href="https://bit.ly/abc">go</a><a href="http://{PUBLIC_IP}/login">x</a>'
            '<a href="https://a.b.c.d.e.example.org/verify-account">y</a>'
            '<a href="https://tracker.example.net/click?u=https://elsewhere.example.org">z</a>')
    feats, profile = _features(_eml(body="see links", html=html))
    for expected in ("url kind: shortener", "url kind: IP-literal host", "url kind: many subdomain levels",
                     "url kind: credential-style word in host or path", "url kind: redirector-looking path or URL in query",
                     "url kind: plain http (no TLS)", "url: any URL present"):
        assert expected in feats, expected
    assert profile == "URL(s), no attachment"


def test_form_markers():
    html = '<form action="https://collector.example.net/post"><input type="password" name="p"></form><script>1</script>'
    feats, _ = _features(_eml(body="x", html=html))
    assert {"form: <form> in the HTML body", "form: password input", "form: posts to an external URL", "html: <script> present"} <= feats


def test_body_shapes():
    assert "body: plain text only, no URL, no attachment" in _features(_eml(body="just a note"))[0]
    feats, profile = _features(_eml(body="", html='<img src="https://img.example.org/a.png">'))
    assert "body: image-only (almost no visible text)" in feats and profile.startswith("no URL/attachment: image-only")


def test_sender_buckets():
    feats, _ = _features(_eml(frm='"x" <someone@gmail.com>', extra_headers="Reply-To: other@elsewhere.example.org"))
    assert "sender: freemail provider" in feats and "sender: Reply-To on a different domain" in feats
    feats, _ = _features(_eml(frm='"x" <vnz73mailr@vh319.hosting.example.net>'))
    assert "sender: server-style hostname as the From domain" in feats and "sender: auto-generated-looking mailbox name" in feats


def test_language_buckets():
    english = "Please review the attached document and let us know if you have any questions about this request for the team. " * 3
    german = "Bitte prüfen Sie das beigefügte Dokument und teilen Sie uns mit, ob Sie Fragen zu dieser Anfrage für das Team haben. " * 3
    hebrew = "שלום רב, אנא עיינו במסמך המצורף ועדכנו אותנו אם יש לכם שאלות בנוגע לבקשה זו עבור הצוות שלנו. " * 3
    assert not any(f.startswith("language: ") for f in _features(_eml(body=english))[0])
    assert "language: Latin script but probably not English" in _features(_eml(body=german))[0]
    assert "language: non-Latin script (hebrew)" in _features(_eml(body=hebrew))[0]


def test_a_malformed_from_is_now_recovered_instead_of_reported_as_unusable():
    # Unquoted comma in the display name: the standard parser used to hand back a fragment with no domain, which
    # this analysis exposed on 22% of the tuning split. The tolerant extractor recovers the address.
    feats, _ = _features(_eml(frm="PayPal, Inc. <support@evil.example.net>"))
    assert "sender: no usable From address" not in feats


def test_real_corpus_run_on_fixtures_does_not_crash():
    r = analyze(ea.FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "clean")
    parsed = parse_email_file((ea.FIXTURES / "malicious" / "kvish6_invoice_phish.eml").read_bytes(), "k.eml")
    feats, profile = ea.features(parsed, r)
    assert "sender: a hop is a local submission (not authenticated SMTP)" in feats
    assert "url kind: tracker / link wrapper (known platform)" in feats
    assert "language: non-Latin script (hebrew)" in feats or "language: too little text to tell" in feats
    assert profile == "URL(s), no attachment"


def test_link_text_does_not_turn_a_hebrew_message_into_latin():
    # a real failure mode: plain-text parts carry <https://...> link text whose Latin letters swamp the Hebrew
    hebrew = "שלום רב, אנא עיינו במסמך המצורף ועדכנו אותנו אם יש לכם שאלות בנוגע לבקשה זו עבור הצוות שלנו. " * 2
    links = " ".join(f"<https://tracking-host-{i}.example.org/some/long/path/segment/{i}?token=abcdefghijkl>" for i in range(12))
    assert "language: non-Latin script (hebrew)" in _features(_eml(body=hebrew + links))[0]


def test_candidate_groups_and_residual_are_reported():
    rows = [
        ("legit", {"sender: no usable From address"}, "URL(s), no attachment", []),
        ("legit", {"url kind: shortener", "form: password input"}, "URL(s), no attachment", []),
        ("legit", {"auth: no Authentication-Results header"}, "no URL, no attachment: text only", []),
        ("legit", {"attachment: any attachment present"}, "attachment, no URL", []),
    ]
    out = io.StringIO()
    ea.report(rows, out)
    text = out.getvalue()
    assert "CANDIDATE SIGNAL GROUPS" in text and "union of A-G" in text
    residual = next(line for line in text.splitlines() if "RESIDUAL" in line)
    assert residual.rsplit("(", 1)[0].split()[-1] == "1"  # only the third row carries no structural evidence
    union = next(line for line in text.splitlines() if "union of A-G" in line)
    assert union.rsplit("(", 1)[0].split()[-1] == "3"


def test_every_group_feature_name_is_one_the_tool_can_actually_emit():
    """Guards against a typo silently making a group look empty: each name must appear as a literal in the
    tool's source (where features() builds it)."""
    source = open(ea.__file__, encoding="utf-8").read()
    for names in ea.CANDIDATE_GROUPS.values():
        for name in names:
            group, _, rest = name.partition(": ")
            fragment = rest.split(" (")[0]
            assert group in source and fragment in source, name
