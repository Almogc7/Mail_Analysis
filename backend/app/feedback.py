"""Local analyst feedback log: measure real-world false positives over time.

Each analysis can be marked agree / disagree (with an optional short note). Records go to a LOCAL
SQLite file (default backend/feedback.local.sqlite, gitignored; override with FEEDBACK_DB) and
contain ONLY:

    sha256 of the file as received, verdict, score, confidence, signal names, agree/disagree,
    source format, whether trusted receivers were configured, timestamps, and the optional note.

They never contain email content: no subject, addresses, URLs, body text or finding descriptions.
"Signal names" are derived from finding titles with every variable part removed (see signal_name),
so 'Possible display-name spoofing of <brand>' is logged as 'auth_check.possible_display_name_spoofing_of'.
The note is free text typed by the analyst: keep it free of email content. It is capped at 500
characters and is the only field that can hold anything beyond hashes/names/verdicts.

Why this exists: the offline eval has only synthetic benign mail, so real-world precision is NOT
established. Disagreements on flagged verdicts are the data that would establish it. Caveat: reviewed
analyses are self-selected by the analyst, so the summary is a signal, not an unbiased rate.

CLI:  python -m app.feedback summary        counts, suspected FP/FN, signals behind disagreements
      python -m app.feedback export         CSV on stdout (same fields as the table)
"""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

from app.config import FEEDBACK_DB
from app.contracts.analysis import AnalysisResult
from app.contracts.findings import Finding

SCHEMA_VERSION = 1
NOTE_MAX_CHARS = 500
FLAGGED = {"malicious", "suspicious"}
_STOP_CHARS = set(".@'\"([<")

_DDL = """
CREATE TABLE IF NOT EXISTS feedback (
    raw_sha256 TEXT PRIMARY KEY,
    first_ts TEXT NOT NULL,
    updated_ts TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score INTEGER,
    confidence REAL,
    signals TEXT NOT NULL,
    agree INTEGER NOT NULL CHECK (agree IN (0, 1)),
    note TEXT,
    source_format TEXT,
    trusted_receivers_configured INTEGER,
    schema_version INTEGER NOT NULL
)
"""
FIELDS = ["raw_sha256", "first_ts", "updated_ts", "verdict", "score", "confidence", "signals", "agree", "note",
          "source_format", "trusted_receivers_configured", "schema_version"]


def signal_name(finding: Finding) -> str:
    """A stable, content-free name for a finding: module + the leading words of its title, stopping
    at the first word that looks like data (contains . @ quote bracket, or a colon that is not the
    trailing one). 'Suspicious URL: http://x' -> 'enrichment.suspicious_url'."""
    words: list[str] = []
    for raw in finding.title.split():
        trailing_colon = raw.endswith(":")
        token = raw[:-1] if trailing_colon else raw
        if not token or any(c in _STOP_CHARS or c == ":" for c in token):
            break
        clean = "".join(c.lower() if c.isalnum() else "_" for c in token).strip("_")
        if clean:
            words.append(clean)
        if trailing_colon:
            break
    slug = "_".join(words)[:60].strip("_") or "unnamed"
    return f"{finding.module}.{slug}"


def signal_names(result: AnalysisResult) -> list[str]:
    return sorted({signal_name(f) for f in result.findings if f.severity != "info"})


def _connect(db_path: Path | str | None) -> sqlite3.Connection:
    path = Path(db_path or FEEDBACK_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_DDL)
    return conn


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def record_feedback(result: AnalysisResult, agree: bool, note: str | None = None, db_path: Path | str | None = None) -> dict:
    """Insert or update (one row per file hash; the analyst may change their mind)."""
    sha = result.parsed_email.raw_sha256
    if not sha:
        raise ValueError("analysis has no raw_sha256; cannot key feedback without the file hash")
    if result.verdict is None:
        raise ValueError("analysis has no verdict yet")
    note = (note or "").strip()[:NOTE_MAX_CHARS] or None
    auth = next((m for m in result.module_results if m.module == "auth_check"), None)
    trusted = ((auth.raw_data or {}).get("auth_headers", {}) if auth else {}).get("trusted_receivers_configured")
    now = _now()
    with closing(_connect(db_path)) as conn, conn:
        conn.execute(
            """INSERT INTO feedback (raw_sha256, first_ts, updated_ts, verdict, score, confidence, signals, agree, note,
                                     source_format, trusted_receivers_configured, schema_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(raw_sha256) DO UPDATE SET updated_ts=excluded.updated_ts, verdict=excluded.verdict,
                   score=excluded.score, confidence=excluded.confidence, signals=excluded.signals,
                   agree=excluded.agree, note=excluded.note, source_format=excluded.source_format,
                   trusted_receivers_configured=excluded.trusted_receivers_configured""",
            (sha, now, now, result.verdict, result.score, result.confidence, json.dumps(signal_names(result)),
             int(agree), note, result.parsed_email.source_format, None if trusted is None else int(bool(trusted)),
             SCHEMA_VERSION),
        )
    return {"raw_sha256": sha, "verdict": result.verdict, "agree": agree, "signals": signal_names(result)}


def _rows(db_path: Path | str | None) -> list[sqlite3.Row]:
    with closing(_connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM feedback ORDER BY first_ts").fetchall()


def summary(db_path: Path | str | None = None) -> dict:
    rows = _rows(db_path)
    by_verdict: dict[str, dict[str, int]] = {}
    fp_signals: dict[str, int] = {}
    ok_signals: dict[str, int] = {}
    for r in rows:
        slot = by_verdict.setdefault(r["verdict"], {"agree": 0, "disagree": 0})
        slot["agree" if r["agree"] else "disagree"] += 1
        if r["verdict"] in FLAGGED:
            bucket = ok_signals if r["agree"] else fp_signals
            for s in json.loads(r["signals"]):
                bucket[s] = bucket.get(s, 0) + 1
    flagged = [r for r in rows if r["verdict"] in FLAGGED]
    fp = sum(1 for r in flagged if not r["agree"])
    fn = sum(1 for r in rows if r["verdict"] == "legit" and not r["agree"])
    inconclusive_disagreed = sum(1 for r in rows if r["verdict"] == "needs_review" and not r["agree"])
    return {
        "total": len(rows),
        "agree": sum(1 for r in rows if r["agree"]),
        "disagree": sum(1 for r in rows if not r["agree"]),
        "by_verdict": by_verdict,
        "reviewed_flagged": len(flagged),
        "suspected_false_positives": fp,
        "suspected_false_negatives": fn,
        "disagreed_inconclusive": inconclusive_disagreed,
        "fp_rate_among_reviewed_flagged": (fp / len(flagged)) if flagged else None,
        "signals_in_disagreed_flagged": dict(sorted(fp_signals.items(), key=lambda kv: -kv[1])),
        "signals_in_agreed_flagged": dict(sorted(ok_signals.items(), key=lambda kv: -kv[1])),
        "caveat": "reviewed analyses are self-selected by the analyst: a signal, not an unbiased rate",
    }


def export_csv(out, db_path: Path | str | None = None) -> None:
    writer = csv.writer(out)
    writer.writerow(FIELDS)
    for r in _rows(db_path):
        writer.writerow([r[f] for f in FIELDS])


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "summary"
    if cmd == "export":
        export_csv(sys.stdout)
        return 0
    if cmd != "summary":
        print("usage: python -m app.feedback [summary|export]", file=sys.stderr)
        return 2
    s = summary()
    print(f"feedback log: {s['total']} reviewed ({s['agree']} agree, {s['disagree']} disagree)")
    for verdict, c in sorted(s["by_verdict"].items()):
        print(f"  {verdict:12} agree {c['agree']}  disagree {c['disagree']}")
    rate = s["fp_rate_among_reviewed_flagged"]
    print(f"suspected false positives: {s['suspected_false_positives']} of {s['reviewed_flagged']} reviewed flagged"
          + (f" ({rate:.0%})" if rate is not None else ""))
    print(f"suspected false negatives: {s['suspected_false_negatives']} (disagreed 'legit' verdicts)")
    print(f"disagreed with an inconclusive verdict: {s['disagreed_inconclusive']} (direction unknown)")
    if s["signals_in_disagreed_flagged"]:
        print("signals present when a flagged verdict was disagreed with:")
        for sig, n in list(s["signals_in_disagreed_flagged"].items())[:10]:
            print(f"  {n:3} {sig}")
    print(f"note: {s['caveat']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
