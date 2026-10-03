"""Offline eval over tests/fixtures/{malicious,benign}/ plus the local tuning corpus.

    cd backend && python -m tests.eval [--ablate-seeds] [--enrichment clean|disabled]
                                       [--mode both|strict|configured] [--json OUT]
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

# ---------------------------------------------------------------------------------------------------------------
# Trust modes. Every report shows BOTH, side by side:
#   STRICT      nothing is trusted: SPF/DKIM/DMARC are not_evaluated. What a default deployment sees.
#   CONFIGURED  the headers the corpus collector's gateway wrote are trusted (they name hops in the chain).
#               Patterns come from the UNTRACKED env var EVAL_CONFIGURED_TRUSTED_RECEIVERS (JSON array, in
#               backend/.env); unset, the default trusts every header that names a hop in the chain.
# The corpus is public phishing collected by someone else's mail server, so many samples carry that server's
# SPF/DKIM/DMARC FAILURES. That frequency is NOT representative of mail that has passed a gateway: real inbound
# mail that reaches an analyst mostly passed it, so do not read CONFIGURED recall as a deployment estimate.
# ---------------------------------------------------------------------------------------------------------------
MODES = ("strict", "configured")
MODE_LABELS = {
    "strict": "nothing trusted (what a default deployment sees)",
    "configured": "the corpus collector's gateway headers trusted (a deployment with its gateway configured)",
}
DEFAULT_CONFIGURED_PATTERNS = [".*", "^unknown-authserv$"]
HEADER_NOTE = ("corpus failure-header frequency is NOT representative of mail that passed a gateway; CONFIGURED shows what "
               "trusting a gateway's results adds, not an estimate of real-world recall")


def configured_patterns() -> list[str]:
    raw = os.getenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", "").strip()
    if not raw:
        return list(DEFAULT_CONFIGURED_PATTERNS)
    value = json.loads(raw)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError("EVAL_CONFIGURED_TRUSTED_RECEIVERS must be a JSON array of regex strings")
    return value


def configured_source() -> str:
    if os.getenv("EVAL_CONFIGURED_TRUSTED_RECEIVERS", "").strip():
        return "patterns from EVAL_CONFIGURED_TRUSTED_RECEIVERS (untracked config)"
    return "default: trusts every header that names a hop in the chain"


def apply_mode(mode: str) -> None:
    import app.config as app_config

    app_config.TRUSTED_RECEIVER_PATTERNS = [] if mode == "strict" else configured_patterns()


# Kept for tests that build a trust configuration around the fixtures' placeholder gateways.
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
    "PRE-REGISTRATION: the final hold-out run reports BOTH modes -- STRICT (nothing trusted) and CONFIGURED (the corpus "
    "collector's gateway headers trusted) -- each with flagged and inconclusive counts. It is never reported in only the "
    "more flattering mode. Corpus failure-header frequency is not representative of mail that passed a gateway.\n\n"
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
    """The ONE sanctioned way to evaluate the hold-out set. Reports BOTH modes (pre-registered in HOLDOUT_LOG.md),
    aggregate output only: no file names, no per-sample verdicts, no findings."""
    corpus = args.corpus_dir or FIXTURES / "_local_corpus"
    log = args.holdout_log or HOLDOUT_LOG
    files = sorted((corpus / "holdout").glob("*.eml"))
    if not files:
        print("eval: no hold-out set found (nothing evaluated, nothing logged)", file=sys.stderr)
        return 1
    head, dirty = _git_state()
    config = f"enrichment={args.enrichment} ablate_seeds={args.ablate_seeds} modes={','.join(MODES)}"
    _log_holdout(log, f"- {_stamp()} UTC | HEAD {head}{' +uncommitted changes' if dirty else ''} | FINAL HOLD-OUT run started | n={len(files)} | {config}")

    print(f"eval FINAL HOLD-OUT (logged to {log.name}): n={len(files)}  [both modes, as pre-registered]")
    print(f"  note: {HEADER_NOTE}")
    for mode in MODES:
        apply_mode(mode)
        verdicts: dict[str, int] = {}
        for path in files:
            verdict = _row_for(path, "malicious", "holdout", args.enrichment).verdict
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        flagged = sum(verdicts.get(v, 0) for v in FLAGGED)
        inconclusive = verdicts.get("needs_review", 0)
        summary = ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items()))
        _log_holdout(log, f"- {_stamp()} UTC | result | mode={mode} | n={len(files)} | flagged={flagged} inconclusive={inconclusive} | {summary}")
        print(f"  {mode.upper():10} flagged {flagged}/{len(files)}   inconclusive {inconclusive}   verdict counts: {summary}")
    print("  (aggregate only: no file names or per-sample verdicts are printed)")
    return 0


def _counts(verdicts: list[str]) -> dict[str, int]:
    """Four verdicts, using the current literals: legit = benign, needs_review = inconclusive."""
    c = {
        "n": len(verdicts),
        "malicious": sum(v == "malicious" for v in verdicts),
        "suspicious": sum(v == "suspicious" for v in verdicts),
        "inconclusive": sum(v == "needs_review" for v in verdicts),
        "benign": sum(v == "legit" for v in verdicts),
    }
    c["flagged"] = c["malicious"] + c["suspicious"]
    return c


def _fmt_malicious(c: dict[str, int]) -> str:
    """For an all-malicious set: 'missed' is a confident benign verdict on malicious mail; 'inconclusive' is a miss that
    at least reaches a human."""
    if not c["n"]:
        return "0/0"
    return (f"flagged {c['flagged']:>3}/{c['n']:<3} (malicious {c['malicious']}, suspicious {c['suspicious']})   "
            f"inconclusive {c['inconclusive']:>3}   missed {c['benign']:>3}")


def _fmt_benign(c: dict[str, int]) -> str:
    return (f"benign {c['benign']:>3}   inconclusive {c['inconclusive']:>3}   suspicious {c['suspicious']:>3}   "
            f"malicious {c['malicious']:>3}   (flagged {c['flagged']}/{c['n']})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ablate-seeds", action="store_true", help="remove the single-sample brand/Hebrew seeds")
    ap.add_argument("--enrichment", choices=("clean", "disabled"), default="clean")
    ap.add_argument("--mode", choices=("both", "strict", "configured"), default="both",
                    help="which trust mode(s) to report (default both, side by side)")
    ap.add_argument("--json", metavar="OUT", help="also write rows + metrics as JSON")
    ap.add_argument("--no-gate", action="store_true", help="exit 0 even if a benign fixture is malicious")
    ap.add_argument("--final-holdout", action="store_true",
                    help="evaluate the hold-out set ONCE (aggregate only, both modes) and append to tests/HOLDOUT_LOG.md; "
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
    if args.final_holdout and args.mode != "both":
        print("eval: --final-holdout always reports both modes (pre-registered); --mode is not accepted with it", file=sys.stderr)
        return 2

    if args.ablate_seeds:
        _ablate_seeds()
    if args.final_holdout:
        return final_holdout(args)

    modes = MODES if args.mode == "both" else (args.mode,)
    corpus = args.corpus_dir or FIXTURES / "_local_corpus"
    items = collect(args.corpus_dir)
    rows_by_mode: dict[str, list[Row]] = {}
    for mode in modes:
        apply_mode(mode)
        rows_by_mode[mode] = [_row_for(p, label, src, args.enrichment) for p, label, src in items]

    print(f"eval: enrichment={args.enrichment} ablate_seeds={args.ablate_seeds} fixtures={len(items)} modes={','.join(modes)}")
    for mode in modes:
        print(f"  {mode.upper():10} = {MODE_LABELS[mode]}" + (f"  [{configured_source()}]" if mode == "configured" else ""))
    print(f"note: {HEADER_NOTE}")
    if not (corpus / "tuning").exists():
        print("eval: no local corpus (tests/fixtures/_local_corpus/tuning) -- skipped")
    holdout = corpus / "holdout"
    if holdout.exists():
        print(f"eval: hold-out present ({sum(1 for _ in holdout.glob('*.eml'))} files) -- not read; only --final-holdout evaluates it")
    print("note: benign evidence is SYNTHETIC ONLY (regression guards, not an accuracy claim); real-world precision is not established\n")

    # ---- per fixture, modes side by side -------------------------------------------------------------
    def cell(mode: str, i: int) -> str:
        r = rows_by_mode[mode][i]
        return f"{r.verdict:12}{r.score:>3}"

    mode_header = " ".join(f"{m.upper():^15}" for m in modes)
    header = f"{'label':9} {'source':13} {mode_header}  {'cov(auth/enr/content)':21} fixture"
    print(header)
    print("-" * len(header))
    first_mode = modes[0]
    for i, base in enumerate(rows_by_mode[first_mode]):
        cov = "/".join(f"{base.coverage.get(c, 0):.2f}" for c in ("auth_check", "enrichment", "content_analysis"))
        cells = " ".join(f"{cell(m, i):15}" for m in modes)
        print(f"{base.label:9} {base.source:13} {cells}  {cov:21} {base.name}")
        shown = rows_by_mode[modes[-1]][i]
        if shown.error:
            print(f"{'':9} !! {shown.error}")
        elif shown.label == "malicious" or shown.verdict in FLAGGED | {"needs_review"}:
            print(f"{'':9} overrides: {', '.join(shown.overrides) or '-'} | {'; '.join(shown.top_findings) or 'no non-info findings'}")

    # ---- summaries -----------------------------------------------------------------------------------------
    def by_source(mode: str) -> dict[tuple[str, str], list[str]]:
        out: dict[tuple[str, str], list[str]] = {}
        for r in rows_by_mode[mode]:
            out.setdefault((r.label, r.source), []).append(r.verdict)
        for src in ("synthetic", "_from_user"):  # always list both, so an empty real-user slot is visible
            out.setdefault(("benign", src), [])
        return out

    tables = {mode: by_source(mode) for mode in modes}
    metrics: dict[str, dict] = {m: {"malicious": {}, "benign": {}} for m in modes}
    kinds = {"kvish": "real, 1 sample", "synthetic": "hand-written spoof positives", "tuning_corpus": "real, tuning split"}

    print("\nMALICIOUS SETS -- each reported alone (flagged = malicious|suspicious; inconclusive = needs_review; missed = a confident benign verdict)")
    for key in sorted({k for t in tables.values() for k in t if k[0] == "malicious"}):
        print(f"  {key[1]:14} ({kinds.get(key[1], '')})")
        for mode in modes:
            counts = _counts(tables[mode].get(key, []))
            metrics[mode]["malicious"][key[1]] = counts
            print(f"      {mode.upper():10} {_fmt_malicious(counts)}")

    print("\nBENIGN FIXTURES -- SYNTHETIC ONLY; each source alone; real-world precision NOT established")
    print("  (inconclusive = the triage-queue cost: benign mail a human would have to look at. In STRICT mode no receiver is\n"
          "   trusted, so 'benign' -- which requires a verified, aligned DKIM/DMARC pass -- is mostly UNREACHABLE by design.)")
    for src in ("synthetic", "_from_user"):
        note = "hand-written regression guards, NOT an accuracy claim" if src == "synthetic" else "real mail; the owner is not supplying any"
        print(f"  {src:14} ({note})")
        for mode in modes:
            counts = _counts(tables[mode][("benign", src)])
            metrics[mode]["benign"][src] = counts
            rate = f"   inconclusive rate {counts['inconclusive']}/{counts['n']}" if counts["n"] else ""
            print(f"      {mode.upper():10} " + (_fmt_benign(counts) + rate if counts["n"] else "0/0 (none -- no real benign mail)"))

    benign_mal = sorted({r.name for m in modes for r in rows_by_mode[m] if r.label == "benign" and r.verdict == "malicious"})
    print(f"\nbenign fixtures reaching MALICIOUS: {len(benign_mal)}" + (f" -> {benign_mal}" if benign_mal else ""))
    print("No combined precision/recall is printed: the malicious sets are all-malicious corpora and the benign sets are\n"
          "small, so pooling them would produce a number that means nothing. Read the per-set lines above.\n"
          "REAL-WORLD PRECISION IS NOT ESTABLISHED: the only benign evidence is synthetic (hand-written).")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"args": {k: str(v) for k, v in vars(args).items()},
                        "rows": {m: [asdict(r) for r in rows_by_mode[m]] for m in modes}, "metrics": metrics},
                       ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
    return 0 if args.no_gate or not benign_mal else 1


if __name__ == "__main__":
    sys.exit(main())
