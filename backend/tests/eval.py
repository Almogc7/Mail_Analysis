"""Offline eval over tests/fixtures/{malicious,benign}/ plus the local tuning corpus.

    cd backend && python -m tests.eval [--ablate-seeds] [--enrichment clean|disabled]
                                       [--trusted-receivers fixtures|none] [--json OUT]
    cd backend && python -m tests.eval --final-holdout      # ONCE, after tuning is finished

Runs parse -> auth_check -> enrichment (stub providers, NO network) -> content_analysis ->
scoring. The LLM module is never called. Prints the per-fixture verdict, score and per-category
coverage, then recall per malicious set and flagged-count per benign source.

Reading the numbers:
  * "flagged" = verdict in {malicious, suspicious}. `needs_review` is an abstention: strict counts
    it as missed/not flagged, lenient as flagged.
  * NO combined precision/recall is printed. The malicious sets are all-malicious corpora (the
    phishing corpus contains no benign mail at all) and the benign sets are small, so pooling them
    yields a meaningless number. Recall is reported per malicious set; false positives per benign
    source, with synthetic (hand-written regression guards, NOT an accuracy claim) kept apart from
    real mail supplied by the owner (benign/_from_user/).
  * malicious/synthetic/ are hand-written display-name-spoof positives (matcher tests), not real phish.
  * --enrichment clean assumes every provider answers "no detections" (what a fresh
    attacker-controlled URL looks like). It measures the structural signals alone.
  * --ablate-seeds removes the single-sample seeds (the "kvish6" brand and the Hebrew urgency
    phrase taken from that sample). This is the honest "before".

Local corpus (gitignored, made by scripts/select_corpus.py): _local_corpus/tuning/*.eml is evaluated
when present and skipped otherwise. _local_corpus/holdout/ is NEVER read by a normal run. The only
way to evaluate it is --final-holdout, which appends a timestamped line to the tracked
tests/HOLDOUT_LOG.md first, then prints AGGREGATE counts only (no file names, no per-sample
verdicts). Do not run it before the verdict-model work is finished.
Attachments are only parsed/hashed, never opened or extracted.

Exit status is 1 if any benign fixture reaches `malicious` (the pre-commit gate).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FLAGGED = {"malicious", "suspicious"}

# The two single-sample seeds, removed by --ablate-seeds.
SEED_BRANDS = ["kvish6"]
SEED_URGENCY = ["תקף לחודש בלבד"]

# Placeholder gateway hosts used inside the fixtures. --trusted-receivers fixtures (the default)
# trusts exactly these, mirroring a deployment that has configured its own gateway; "none" shows
# the out-of-the-box behaviour where SPF/DKIM/DMARC are not_evaluated.
FIXTURE_TRUSTED_RECEIVERS = [chr(94) + r"mx" + chr(92) + ".example" + chr(92) + ".org" + chr(36),
                             chr(94) + r"esa1" + chr(92) + ".gateway" + chr(92) + ".example" + chr(92) + ".net" + chr(36)]


@dataclass
class Row:
    label: str  # malicious | benign
    source: str  # kvish / synthetic / _from_user / local_corpus
    name: str
    verdict: str = ""
    score: int = 0
    confidence: float = 0.0
    coverage: dict[str, float] = field(default_factory=dict)
    overrides: list[str] = field(default_factory=list)
    top_findings: list[str] = field(default_factory=list)
    error: str | None = None


def _ablate_seeds() -> None:
    from app.content_analysis import brand_impersonation, urgency
    from app.shared import brands

    for b in SEED_BRANDS:
        brands.KNOWN_BRANDS.pop(b, None)
        brand_impersonation._BRAND_PATTERNS.pop(b, None)
    for phrase in SEED_URGENCY:
        if phrase in urgency.URGENCY_PHRASES:
            urgency.URGENCY_PHRASES.remove(phrase)


class _Stub:
    def __init__(self, result):
        self._result = result

    def enrich(self, ioc_value, ioc_type):
        return self._result


def _stub_clients(mode: str) -> dict:
    from app.enrichment.ioc_bridge import get_clients
    from tests.fixtures.provider_responses import (
        CLEAN_URLSCAN_RESULT,
        CLEAN_VT_URL_RESULT,
        DISABLED_RESULT,
        NO_MATCH_MALWAREBAZAAR_RESULT,
        NO_MATCH_THREATFOX_RESULT,
    )

    real = get_clients()  # constructs clients only; no network call happens here
    if mode == "disabled":
        vt = urlscan = tf = mb = DISABLED_RESULT
    else:
        vt, urlscan, tf, mb = (
            CLEAN_VT_URL_RESULT,
            CLEAN_URLSCAN_RESULT,
            NO_MATCH_THREATFOX_RESULT,
            NO_MATCH_MALWAREBAZAAR_RESULT,
        )
    return {
        "virustotal": _Stub(vt),
        "urlscan": _Stub(urlscan),
        "threatfox": _Stub(tf),
        "malwarebazaar": _Stub(mb),
        "risk_scorer": real["risk_scorer"],
        "score_config": real["score_config"],
    }


def analyze(path: Path, enrichment_mode: str):
    from app.auth_check import run_auth_check
    from app.content_analysis import run_content_analysis
    from app.contracts.findings import ModuleResult
    from app.enrichment import run_enrichment
    from app.enrichment.rate_limit import VTRateLimiter
    from app.parser import parse_email_file
    from app.scoring import build_analysis_result

    parsed = parse_email_file(path.read_bytes(), path.name)
    auth = run_auth_check(parsed)
    enr = run_enrichment(parsed, _stub_clients(enrichment_mode), VTRateLimiter(sleep_fn=lambda s: None))
    content = run_content_analysis(parsed)
    results: list[ModuleResult] = [auth, enr, content]
    return build_analysis_result(parsed, results)


def _row_for(path: Path, label: str, source: str, enrichment_mode: str) -> Row:
    row = Row(label=label, source=source, name=path.name)
    try:
        res = analyze(path, enrichment_mode)
    except Exception as exc:  # a parse crash must show up in the table, not abort the run
        row.verdict, row.error = "ERROR", f"{type(exc).__name__}: {exc}"
        return row
    row.verdict, row.score, row.confidence = res.verdict, res.score, res.confidence
    row.coverage = {c.category: round(c.coverage, 2) for c in res.scoring.categories}
    row.overrides = [o.rule for o in res.scoring.applied_overrides]
    row.top_findings = [f"{f.severity}:{f.title[:60]}" for f in res.findings if f.severity != "info"][:3]
    return row


HOLDOUT_LOG = Path(__file__).resolve().parent / "HOLDOUT_LOG.md"
_HOLDOUT_LOG_HEADER = (
    "# Hold-out evaluation log\n\n"
    "Every `python -m tests.eval --final-holdout` run appends a timestamped line BEFORE it evaluates "
    "anything (so even a crashed run is on record) and an aggregate-only result line after. No file "
    "names, per-sample verdicts or content are ever written here. The hold-out set exists to be "
    "evaluated once, after tuning is finished.\n\n"
)


def collect(corpus_dir: Path | None = None) -> list[tuple[Path, str, str]]:
    """Fixtures + the local TUNING corpus. The hold-out directory is never collected here."""
    corpus = corpus_dir or FIXTURES / "_local_corpus"
    items: list[tuple[Path, str, str]] = []

    def add(directory: Path, label: str, source_of):
        if directory.exists():
            for p in sorted(directory.rglob("*")):
                if p.suffix.lower() in {".eml", ".msg"}:
                    items.append((p, label, source_of(p)))

    add(FIXTURES / "malicious", "malicious", lambda p: "kvish" if p.parent.name == "malicious" else p.parent.name)
    add(FIXTURES / "benign", "benign", lambda p: p.parent.name)
    add(corpus / "tuning", "malicious", lambda p: "tuning_corpus")
    return items


def _git_state() -> tuple[str, bool]:
    import subprocess

    root = Path(__file__).resolve().parents[2]
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True).stdout.strip())
    except Exception:
        return "unknown", True
    return head, dirty


def _log_holdout(log: Path, line: str) -> None:
    if not log.exists():
        log.write_text(_HOLDOUT_LOG_HEADER, encoding="utf-8")
    with log.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _stamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def final_holdout(args) -> int:
    """The ONE sanctioned way to evaluate the hold-out set. Aggregate output only: no file names,
    no per-sample verdicts, no findings."""
    corpus = args.corpus_dir or FIXTURES / "_local_corpus"
    log = args.holdout_log or HOLDOUT_LOG
    files = sorted((corpus / "holdout").glob("*.eml"))
    if not files:
        print("eval: no hold-out set found (nothing evaluated, nothing logged)", file=sys.stderr)
        return 1
    head, dirty = _git_state()
    config = f"enrichment={args.enrichment} trusted_receivers={args.trusted_receivers} ablate_seeds={args.ablate_seeds}"
    _log_holdout(log, f"- {_stamp()} UTC | HEAD {head}{' +uncommitted changes' if dirty else ''} | FINAL HOLD-OUT run started | n={len(files)} | {config}")

    verdicts: dict[str, int] = {}
    for path in files:
        verdict = _row_for(path, "malicious", "holdout", args.enrichment).verdict
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
    flagged = sum(verdicts.get(v, 0) for v in FLAGGED)
    lenient = flagged + verdicts.get("needs_review", 0)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items()))
    _log_holdout(log, f"- {_stamp()} UTC | result | n={len(files)} | flagged(strict)={flagged} flagged(lenient)={lenient} | {summary}")

    print(f"eval FINAL HOLD-OUT (logged to {log.name}): n={len(files)}")
    print(f"  recall strict  (malicious+suspicious): {flagged}/{len(files)}")
    print(f"  recall lenient (+needs_review):        {lenient}/{len(files)}")
    print(f"  verdict counts: {summary}")
    print("  (aggregate only: no file names or per-sample verdicts are printed)")
    return 0


def _flagged(verdict: str, lenient: bool) -> bool:
    return verdict in FLAGGED or (lenient and verdict == "needs_review")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ablate-seeds", action="store_true", help="remove the single-sample brand/Hebrew seeds")
    ap.add_argument("--enrichment", choices=("clean", "disabled"), default="clean")
    ap.add_argument("--trusted-receivers", choices=("fixtures", "none"), default="fixtures")
    ap.add_argument("--json", metavar="OUT", help="also write rows + metrics as JSON")
    ap.add_argument("--no-gate", action="store_true", help="exit 0 even if a benign fixture is malicious")
    ap.add_argument("--final-holdout", action="store_true",
                    help="evaluate the hold-out set ONCE (aggregate only) and append to tests/HOLDOUT_LOG.md; "
                         "never run this before the tuning work is finished")
    ap.add_argument("--corpus-dir", type=Path, help=argparse.SUPPRESS)  # tests only
    ap.add_argument("--holdout-log", type=Path, help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    if args.final_holdout and args.json:
        print("eval: --json is not allowed with --final-holdout (it would write per-sample verdicts)", file=sys.stderr)
        return 2

    import app.config as app_config

    app_config.TRUSTED_RECEIVER_PATTERNS = list(FIXTURE_TRUSTED_RECEIVERS) if args.trusted_receivers == "fixtures" else []
    if args.ablate_seeds:
        _ablate_seeds()

    if args.final_holdout:
        return final_holdout(args)

    corpus = args.corpus_dir or FIXTURES / "_local_corpus"
    items = collect(args.corpus_dir)
    rows = [_row_for(p, label, src, args.enrichment) for p, label, src in items]

    print(f"eval: enrichment={args.enrichment} trusted_receivers={args.trusted_receivers} ablate_seeds={args.ablate_seeds} fixtures={len(rows)}")
    if not (corpus / "tuning").exists():
        print("eval: no local corpus (tests/fixtures/_local_corpus/tuning) -- skipped")
    holdout = corpus / "holdout"
    if holdout.exists():
        print(f"eval: hold-out present ({sum(1 for _ in holdout.glob('*.eml'))} files) -- not read; only --final-holdout evaluates it")
    print("note: benign evidence is SYNTHETIC ONLY (regression guards, not an accuracy claim); real-world precision is not established\n")

    header = f"{'label':9} {'source':13} {'verdict':12} {'score':>5} {'conf':>5}  {'cov auth/enr/content':21} fixture"
    print(header)
    print("-" * len(header))
    for r in rows:
        cov = "/".join(f"{r.coverage.get(c, 0):.2f}" for c in ("auth_check", "enrichment", "content_analysis"))
        print(f"{r.label:9} {r.source:13} {r.verdict:12} {r.score:>5} {r.confidence:>5}  {cov:21} {r.name}")
        if r.error:
            print(f"{'':9} !! {r.error}")
        elif r.label == "malicious" or r.verdict in FLAGGED | {"needs_review"}:
            extra = ", ".join(r.overrides) or "-"
            print(f"{'':9} overrides: {extra} | {'; '.join(r.top_findings) or 'no non-info findings'}")

    by_src: dict[tuple[str, str], list[str]] = {}
    for r in rows:
        by_src.setdefault((r.label, r.source), []).append(r.verdict)
    benign_sources = ("synthetic", "_from_user")
    for src in benign_sources:  # always list both, so an empty real-user slot is visible
        by_src.setdefault(("benign", src), [])

    metrics: dict[str, dict] = {"recall": {}, "benign_flagged": {}}
    print("\nRecall -- each malicious set reported on its own (strict = needs_review counts as missed; lenient = counts as flagged):")
    for (label, src), verdicts in sorted(by_src.items()):
        if label != "malicious":
            continue
        s = sum(_flagged(v, False) for v in verdicts)
        l = sum(_flagged(v, True) for v in verdicts)
        metrics["recall"][src] = {"strict": s, "lenient": l, "n": len(verdicts)}
        kind = {"kvish": "real, 1 sample", "synthetic": "hand-written spoof positives", "tuning_corpus": "real, tuning split"}.get(src, "")
        print(f"  {src:14} strict {s}/{len(verdicts)}  lenient {l}/{len(verdicts)}   ({kind})")

    print("\nBenign fixtures flagged -- SYNTHETIC ONLY; each source on its own, real-world precision NOT established:")
    for src in benign_sources:
        verdicts = by_src[("benign", src)]
        flagged_n = sum(_flagged(v, False) for v in verdicts)
        review_n = sum(v == "needs_review" for v in verdicts)
        metrics["benign_flagged"][src] = {"flagged": flagged_n, "needs_review": review_n, "n": len(verdicts)}
        kind = "hand-written regression guards, NOT an accuracy claim" if src == "synthetic" else "real mail; the owner is not supplying any"
        shown = f"{flagged_n}/{len(verdicts)} flagged, {review_n} needs_review" if verdicts else "0/0 (none -- no real benign mail)"
        print(f"  {src:14} {shown}   ({kind})")

    benign_mal = [r.name for r in rows if r.label == "benign" and r.verdict == "malicious"]
    print(f"\nbenign fixtures reaching MALICIOUS: {len(benign_mal)}" + (f" -> {benign_mal}" if benign_mal else ""))
    print("No combined precision/recall is printed: the malicious sets are all-malicious corpora and the benign sets are\n"
          "small, so pooling them would produce a number that means nothing. Read the per-source lines above.\n"
          "REAL-WORLD PRECISION IS NOT ESTABLISHED: the only benign evidence is synthetic (hand-written).")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"args": {k: str(v) for k, v in vars(args).items()}, "rows": [asdict(r) for r in rows], "metrics": metrics},
                       ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
    return 0 if args.no_gate or not benign_mal else 1


if __name__ == "__main__":
    sys.exit(main())
