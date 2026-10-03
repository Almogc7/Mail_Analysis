"""Local analyst feedback log (app/feedback.py): privacy, upsert, summary."""
import io
import sqlite3

import pytest

from app import feedback
from app.contracts.findings import Finding
from tests.eval import FIXTURES, analyze


def _f(module, title, severity="medium"):
    return Finding(module=module, severity=severity, title=title, description="d", weight=1.0)


@pytest.fixture
def db(tmp_path):
    return tmp_path / "feedback.sqlite"


@pytest.fixture(scope="module")
def kvish():
    return analyze(FIXTURES / "malicious" / "kvish6_invoice_phish.eml", "clean")


@pytest.fixture(scope="module")
def benign():
    return analyze(FIXTURES / "benign" / "synthetic" / "01_newsletter_esp_click_tracking.eml", "clean")


@pytest.fixture(scope="module")
def spoof(tmp_path_factory):
    # a corroborated claim (claim + machine-provisioned sender) so it is FLAGGED; a bare claim is only inconclusive now
    raw = (b"From: PayPal Support <vnz73mailr@vh319.hosting.example.net>\r\nTo: t@example.com\r\nSubject: Notice\r\n"
           b"Date: Mon, 21 Sep 2026 10:00:00 +0000\r\nMessage-ID: <fb1@x.example.com>\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: text/plain\r\n\r\nhello\r\n")
    path = tmp_path_factory.mktemp("fb") / "spoof.eml"
    path.write_bytes(raw)
    return analyze(path, "clean")


# ---- signal names carry no email content --------------------------------------------------------

@pytest.mark.parametrize(
    "module,title,expected",
    [
        ("auth_check", "Possible display-name spoofing of 'kvish6'", "auth_check.possible_display_name_spoofing_of"),
        ("auth_check", "SPF check failed", "auth_check.spf_check_failed"),
        ("auth_check", "SPF/DKIM/DMARC all passed", "auth_check.spf_dkim_dmarc_all_passed"),
        ("auth_check", "Machine-provisioned sender claiming a brand", "auth_check.machine_provisioned_sender_claiming_a_brand"),
        ("enrichment", "Suspicious URL: https://evil.example.net/a?x=1", "enrichment.suspicious_url"),
        ("enrichment", "Enrichment incomplete for https://evil.example.net/a", "enrichment.enrichment_incomplete_for"),
        ("enrichment", "Not enriched: per-email limit reached (url)", "enrichment.not_enriched"),
        ("enrichment", "Known-malicious attachment hash: invoice.exe", "enrichment.known_malicious_attachment_hash"),
        ("content_analysis", "Body content claims to be 'paypal' but a linked URL doesn't match", "content_analysis.body_content_claims_to_be"),
        ("auth_check", "", "auth_check.unnamed"),
    ],
)
def test_signal_names_strip_every_variable_part(module, title, expected):
    assert feedback.signal_name(_f(module, title)) == expected


def test_signal_names_skip_info_findings(kvish):
    names = feedback.signal_names(kvish)
    assert names == sorted(set(names)) and names
    assert not any("not_evaluated" in n or "claims_from_untrusted" in n for n in names)


# ---- what is stored ------------------------------------------------------------------------------

def test_a_record_holds_only_hash_verdict_signals_and_flags(kvish, db):
    feedback.record_feedback(kvish, agree=False, db_path=db)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        (row,) = conn.execute("SELECT * FROM feedback").fetchall()
    assert list(row.keys()) == feedback.FIELDS
    assert row["raw_sha256"] == kvish.parsed_email.raw_sha256 and len(row["raw_sha256"]) == 64
    assert row["verdict"] == "suspicious" and row["agree"] == 0 and row["note"] is None
    assert row["source_format"] == "eml" and row["schema_version"] == feedback.SCHEMA_VERSION
    assert "auth_check.possible_display_name_spoofing_of" in row["signals"]


def test_no_email_content_reaches_the_database_file(kvish, db):
    feedback.record_feedback(kvish, agree=True, db_path=db)
    raw = db.read_bytes()
    content_markers = [b"sweb", b"kvish6", b"sendgrid", b"printernet", b"walla", b"vnz73mailr", b"recipient@",
                       b"example.com", "החשבונית".encode("utf-8"), b"Caution"]
    for marker in content_markers:
        assert marker not in raw, marker


def test_note_is_optional_trimmed_and_capped(kvish, db):
    feedback.record_feedback(kvish, agree=False, note="  " + "x" * 900 + "  ", db_path=db)
    with sqlite3.connect(db) as conn:
        (note,) = conn.execute("SELECT note FROM feedback").fetchone()
    assert note == "x" * feedback.NOTE_MAX_CHARS
    feedback.record_feedback(kvish, agree=False, note="   ", db_path=db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT note FROM feedback").fetchone() == (None,)


def test_feedback_is_upserted_per_file_hash(kvish, db):
    feedback.record_feedback(kvish, agree=False, note="first", db_path=db)
    feedback.record_feedback(kvish, agree=True, note="changed my mind", db_path=db)
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT agree, note, first_ts <= updated_ts FROM feedback").fetchall()
    assert rows == [(1, "changed my mind", 1)]


def test_refuses_an_analysis_without_a_file_hash(kvish, db):
    no_hash = kvish.model_copy(update={"parsed_email": kvish.parsed_email.model_copy(update={"raw_sha256": None})})
    with pytest.raises(ValueError):
        feedback.record_feedback(no_hash, agree=True, db_path=db)
    assert not db.exists() or sqlite3.connect(db).execute("SELECT COUNT(*) FROM feedback").fetchone() == (0,)


# ---- summary -------------------------------------------------------------------------------------

def test_empty_summary_is_well_formed(db):
    s = feedback.summary(db)
    assert s["total"] == 0 and s["fp_rate_among_reviewed_flagged"] is None and "self-selected" in s["caveat"]


def test_summary_counts_suspected_false_positives_and_negatives(kvish, spoof, benign, db):
    feedback.record_feedback(kvish, agree=True, db_path=db)  # flagged, analyst agrees
    feedback.record_feedback(spoof, agree=False, note="newsletter I subscribed to", db_path=db)  # flagged, disagrees => FP
    feedback.record_feedback(benign, agree=False, db_path=db)  # inconclusive (needs_review), disagrees
    s = feedback.summary(db)
    assert (s["total"], s["agree"], s["disagree"]) == (3, 1, 2)
    assert s["reviewed_flagged"] == 2 and s["suspected_false_positives"] == 1 and s["fp_rate_among_reviewed_flagged"] == 0.5
    # disagreeing with an INCONCLUSIVE verdict is not a false negative on a benign call: it is counted on its own
    assert s["suspected_false_negatives"] == 0 and s["disagreed_inconclusive"] == 1
    assert s["by_verdict"]["suspicious"] == {"agree": 1, "disagree": 1} and s["by_verdict"]["needs_review"] == {"agree": 0, "disagree": 1}
    assert "auth_check.possible_display_name_spoofing_of" in s["signals_in_disagreed_flagged"]
    assert "auth_check.possible_display_name_spoofing_of" in s["signals_in_agreed_flagged"]


def test_export_csv_has_the_documented_columns_only(kvish, db):
    feedback.record_feedback(kvish, agree=False, db_path=db)
    out = io.StringIO()
    feedback.export_csv(out, db)
    header, row = out.getvalue().splitlines()[:2]
    assert header.split(",") == feedback.FIELDS and kvish.parsed_email.raw_sha256 in row
    assert "sweb" not in out.getvalue() and "kvish6" not in out.getvalue()


def test_cli_summary_prints_the_caveat(db, monkeypatch, capsys):
    monkeypatch.setattr(feedback, "FEEDBACK_DB", db)
    assert feedback.main(["summary"]) == 0
    out = capsys.readouterr().out
    assert "feedback log: 0 reviewed" in out and "self-selected" in out
    assert feedback.main(["bogus"]) == 2


def test_default_database_is_the_gitignored_local_file():
    assert feedback.FEEDBACK_DB.name == "feedback.local.sqlite"
