"""Offline eval over tests/fixtures/{malicious,benign}/ plus the local tuning corpus.

    cd backend && python -m tests.eval [--ablate-seeds] [--enrichment clean|disabled]
                                       [--mode both|strict|configured] [--json OUT]
    cd backend && python -m tests.eval --final-holdout      # ONCE, after tuning is finished

Runs parse -> auth_check -> enrichment (stub providers, NO network) -> content_analysis ->
scoring. The LLM module is never called. Prints the per-fixture verdict, score and per-category
coverage, then recall per malicious set and flagged-count per benign source.

Reading the numbers:
  * "flagged" = verdict in {malicious, suspicious}. `inconclusive` is an abstention: strict counts
    it as missed/not flagged, lenient as flagged.
  * NO combined precision/recall is printed. The malicious sets are all-malicious corpora (the
    phishing corpus contains no benign mail at all) and the benign sets are small, so pooling them
    yields a meaningless number. Recall is reported per malicious set; false positives per benign
    source, with synthetic (hand-written regression guards, NOT an accuracy claim) kept apart from
    real mail supplied by the owner (benign/_from_user/). The synthetic corpus is TWO groups, printed
    under their own names: "benign fixtures" (benign/synthetic) and "synthetic spoofs" (malicious/synthetic).
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
import logging
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
ENRICHMENT_TAGS = {"clean": "[enrichment: offline clean stub]", "disabled": "[enrichment: UNKNOWN (providers unavailable)]"}
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


# Registrable domains the CONFIGURED deployment lists as known senders. The synthetic benign fixtures all send from
# reserved example domains (plus docusign.net for the brand-domain fixture); no real corpus sender is on the list, so it
# changes nothing for the phishing sets. STRICT lists nobody. Override with EVAL_CONFIGURED_KNOWN_SENDERS (JSON array).
DEFAULT_CONFIGURED_KNOWN_SENDERS = ["example.com", "example.org", "example.net", "docusign.net"]


def configured_known_senders() -> frozenset[str]:
    raw = os.getenv("EVAL_CONFIGURED_KNOWN_SENDERS", "").strip()
    value = json.loads(raw) if raw else DEFAULT_CONFIGURED_KNOWN_SENDERS
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError("EVAL_CONFIGURED_KNOWN_SENDERS must be a JSON array of domains")
    return frozenset(value)


def apply_mode(mode: str) -> None:
    import app.config as app_config

    app_config.TRUSTED_RECEIVER_PATTERNS = [] if mode == "strict" else configured_patterns()
    app_config.KNOWN_SENDER_DOMAINS = frozenset() if mode == "strict" else configured_known_senders()


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
    priority: float = 0.0
    reason: str | None = None  # inconclusive sub-reason
    signals: list[str] = field(default_factory=list)  # structural signal ids that fired, e.g. S2, L1
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
    from app.enrichment.providers import get_clients
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


def analyze_parsed(parsed, enrichment_mode: str):
    """The pipeline on an already-parsed message (used by the mutation tests, which edit the ParsedEmail)."""
    from app.auth_check import run_auth_check
    from app.content_analysis import run_content_analysis
    from app.contracts.findings import ModuleResult
    from app.enrichment import run_enrichment
    from app.enrichment.rate_limit import VTRateLimiter
    from app.scoring import build_analysis_result

    auth = run_auth_check(parsed)
    enr = run_enrichment(parsed, _stub_clients(enrichment_mode), VTRateLimiter(sleep_fn=lambda s: None))
    content = run_content_analysis(parsed)
    results: list[ModuleResult] = [auth, enr, content]
    return build_analysis_result(parsed, results)


def analyze(path: Path, enrichment_mode: str):
    from app.parser import parse_email_file

    return analyze_parsed(parse_email_file(path.read_bytes(), path.name), enrichment_mode)


def _row_for(path: Path, label: str, source: str, enrichment_mode: str) -> Row:
    row = Row(label=label, source=source, name=path.name)
    try:
        res = analyze(path, enrichment_mode)
    except Exception as exc:  # a parse crash must show up in the table, not abort the run
        row.verdict, row.error = "ERROR", f"{type(exc).__name__}: {exc}"
        return row
    row.verdict, row.score, row.confidence = res.verdict, res.score, res.confidence
    row.priority, row.reason = res.scoring.priority, res.scoring.inconclusive_reason
    row.signals = sorted({f.evidence["signal"] for f in res.findings if f.evidence.get("structural") and f.evidence.get("signal")})
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
        rows = [_row_for(path, "malicious", "holdout", args.enrichment) for path in files]
        verdicts: dict[str, int] = {}
        for r in rows:
            verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1
        n = len(rows)
        flagged = sum(verdicts.get(v, 0) for v in FLAGGED)
        inconclusive = verdicts.get("inconclusive", 0)
        missed = verdicts.get("benign", 0)
        errors = verdicts.get("ERROR", 0)
        with_signals = sum(r.reason == "signals_present" for r in rows if r.verdict == "inconclusive")
        summary = ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items()))
        _log_holdout(log, f"- {_stamp()} UTC | result | mode={mode} | n={n} | flagged={flagged} inconclusive={inconclusive} missed={missed} | {summary}")
        print(f"  {mode.upper()}")
        print(f"      flagged      {fmt_rate(flagged, n)}   (malicious {verdicts.get('malicious', 0)}, suspicious {verdicts.get('suspicious', 0)})")
        print(f"      inconclusive {fmt_rate(inconclusive, n)}   (signals present {with_signals}, no signals {inconclusive - with_signals})")
        print(f"      missed       {fmt_rate(missed, n)}   (a confident 'no indicators found' on a phishing sample)")
        if errors:
            print(f"      errors       {errors}/{n}   (samples the pipeline crashed on; counted in none of the rows above)")
        print("      " + _signal_counts(rows).replace("signals(samples)", "structural signals (samples)"))
    print("  (aggregate only: no file names or per-sample verdicts are printed)")
    return 0


def _counts(verdicts: list[str]) -> dict[str, int]:
    """Four verdicts, using the current literals: legit = benign, inconclusive = inconclusive."""
    c = {
        "n": len(verdicts),
        "malicious": sum(v == "malicious" for v in verdicts),
        "suspicious": sum(v == "suspicious" for v in verdicts),
        "inconclusive": sum(v == "inconclusive" for v in verdicts),
        "benign": sum(v == "benign" for v in verdicts),
    }
    c["flagged"] = c["malicious"] + c["suspicious"]
    return c


def _reason_split(rows: list["Row"]) -> str:
    """Inconclusive sub-reasons: 'signals' = something fired but was not enough; 'none' = nothing fired and nothing
    positive was established."""
    signals = sum(r.reason == "signals_present" for r in rows if r.verdict == "inconclusive")
    none = sum(r.reason == "no_signals_insufficient_evidence" for r in rows if r.verdict == "inconclusive")
    return f"[inconclusive: signals present {signals} / no signals {none}]" if signals + none else ""


SIGNAL_FAMILY = {"S1": "sender", "S2": "sender", "S3": "sender", "L1": "link", "L2": "link", "L3": "link",
                 "C1": "claim", "C1b": "claim", "C2": "claim", "C3": "claim"}


def _signal_counts(rows: list["Row"]) -> str:
    """Samples in which each structural signal fired, plus samples carrying >= 1 / >= 2 different families."""
    per_signal = {sig: sum(sig in r.signals for r in rows) for sig in SIGNAL_FAMILY}
    fired = "  ".join(f"{sig} {n}" for sig, n in per_signal.items() if n) or "none"
    fams = [len({SIGNAL_FAMILY[s] for s in r.signals}) for r in rows]
    return f"signals(samples): {fired}   | families: >=1 {sum(f >= 1 for f in fams)}, >=2 {sum(f >= 2 for f in fams)}"


def auc(positives: list[float], negatives: list[float]) -> float | None:
    """P(a random positive outranks a random negative), ties counting half. None when either side is empty."""
    if not positives or not negatives:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def frac_above_median(positives: list[float], negatives: list[float]) -> float | None:
    if not positives or not negatives:
        return None
    ordered = sorted(negatives)
    mid = len(ordered) // 2
    median = ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    return sum(p > median for p in positives) / len(positives)


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float] | None:
    """Wilson score interval for a proportion k/n (95% by default). None for n == 0."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return max(0.0, round(centre - half, 12)), min(1.0, round(centre + half, 12))


def fmt_rate(k: int, n: int) -> str:
    ci = wilson(k, n)
    return "n/a" if ci is None else f"{k}/{n} = {100 * k / n:.1f}% [95% CI {100 * ci[0]:.1f}-{100 * ci[1]:.1f}%]"


def _intervals(c: dict[str, int], names: tuple[str, ...]) -> str:
    return "   | " + "; ".join(f"{name} {fmt_rate(c[name], c['n'])}" for name in names) if c["n"] else ""


def _fmt_malicious(c: dict[str, int]) -> str:
    """For an all-malicious set: 'missed' is a confident benign verdict on malicious mail; 'inconclusive' is a miss that
    at least reaches a human."""
    if not c["n"]:
        return "0/0"
    return (f"flagged {c['flagged']:>3}/{c['n']:<3} (malicious {c['malicious']}, suspicious {c['suspicious']})   "
            f"inconclusive {c['inconclusive']:>3}   missed {c['benign']:>3}"
            + _intervals({**c, "missed": c["benign"]}, ("flagged", "inconclusive", "missed")))


def _fmt_benign(c: dict[str, int]) -> str:
    return (f"benign {c['benign']:>3}   inconclusive {c['inconclusive']:>3}   suspicious {c['suspicious']:>3}   "
            f"malicious {c['malicious']:>3}   (flagged {c['flagged']}/{c['n']})"
            + _intervals(c, ("benign", "inconclusive", "flagged")))


def main(argv: list[str] | None = None) -> int:
    """The eval is a batch tool: the app's per-message console warnings (enrichment UNKNOWN summaries) would print once per sample and bury
    the tables, so only errors are logged while it runs. The level is restored afterwards."""
    app_logger = logging.getLogger("app")
    previous = app_logger.level
    app_logger.setLevel(logging.ERROR)
    try:
        return _main(argv)
    finally:
        app_logger.setLevel(previous)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ablate-seeds", action="store_true", help="remove the single-sample brand/Hebrew seeds")
    ap.add_argument("--enrichment", choices=("clean", "unknown", "disabled"), default="clean",
                    help="clean = offline stub answering no-detections for everything; unknown (alias: disabled) = every provider "
                         "answers UNKNOWN, so no indicator is ever covered")
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

    if args.enrichment == "unknown":
        args.enrichment = "disabled"  # the stub that answers UNKNOWN is called "disabled" internally
    if args.ablate_seeds:
        _ablate_seeds()
    if args.final_holdout:
        return final_holdout(args)

    modes = MODES if args.mode == "both" else (args.mode,)
    tag = ENRICHMENT_TAGS[args.enrichment]
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
        elif shown.label == "malicious" or shown.verdict in FLAGGED | {"inconclusive"}:
            print(f"{'':9} overrides: {', '.join(shown.overrides) or '-'} | {'; '.join(shown.top_findings) or 'no non-info findings'}")

    # ---- summaries -----------------------------------------------------------------------------------------
    def by_source(mode: str) -> dict[tuple[str, str], list[Row]]:
        out: dict[tuple[str, str], list[Row]] = {}
        for r in rows_by_mode[mode]:
            out.setdefault((r.label, r.source), []).append(r)
        for src in ("synthetic", "_from_user"):  # always list both, so an empty real-user slot is visible
            out.setdefault(("benign", src), [])
        return out

    tables = {mode: by_source(mode) for mode in modes}

    def group_name(label: str, source: str) -> str:
        """The two hand-written sets share the internal source 'synthetic' but are different things and are never pooled."""
        if source == "synthetic":
            return "benign fixtures" if label == "benign" else "synthetic spoofs"
        return source

    n_benign_fixtures = len(tables[modes[0]].get(("benign", "synthetic"), []))
    n_spoofs = len(tables[modes[0]].get(("malicious", "synthetic"), []))
    print()
    print(f"{tag} SYNTHETIC CORPUS -- TWO GROUPS, reported separately and never pooled: {n_benign_fixtures} benign fixtures and {n_spoofs} synthetic spoofs "
          f"(hand-written, {n_benign_fixtures + n_spoofs} files in all). Neither is an accuracy claim.")
    metrics: dict[str, dict] = {m: {"malicious": {}, "benign": {}} for m in modes}
    kinds = {"kvish": "real, 1 sample", "synthetic": "hand-written display-name-spoof positives", "tuning_corpus": "real, tuning split"}

    print(f"\n{tag} MALICIOUS SETS -- each reported alone (flagged = malicious|suspicious; inconclusive = inconclusive; missed = a confident benign verdict)")
    for key in sorted({k for t in tables.values() for k in t if k[0] == "malicious"}):
        print(f"  {group_name(*key):16} ({kinds.get(key[1], '')}; n={len(tables[modes[0]].get(key, []))})")
        for mode in modes:
            rows = tables[mode].get(key, [])
            counts = _counts([r.verdict for r in rows])
            metrics[mode]["malicious"][key[1]] = counts
            print(f"      {mode.upper():10} {_fmt_malicious(counts)}   {_reason_split(rows)}")

    print(f"\n{tag} BENIGN FIXTURES -- SYNTHETIC ONLY; each source alone; real-world precision NOT established")
    print("  (inconclusive = the triage-queue cost: benign mail a human would have to look at. In STRICT mode no receiver is\n"
          "   trusted, so 'benign' -- which requires a verified, aligned DKIM/DMARC pass -- is mostly UNREACHABLE by design.)")
    for src in ("synthetic", "_from_user"):
        note = "hand-written regression guards, NOT an accuracy claim" if src == "synthetic" else "real mail; the owner is not supplying any"
        print(f"  {group_name('benign', src):16} ({note}; n={len(tables[modes[0]][('benign', src)])})")
        for mode in modes:
            rows = tables[mode][("benign", src)]
            counts = _counts([r.verdict for r in rows])
            metrics[mode]["benign"][src] = counts
            rate = f"   inconclusive rate {counts['inconclusive']}/{counts['n']}   {_reason_split(rows)}" if counts["n"] else ""
            print(f"      {mode.upper():10} " + (_fmt_benign(counts) + rate if counts["n"] else "0/0 (none -- no real benign mail)"))

    print()
    print(f"{tag} STRUCTURAL SIGNALS -- how many samples each fired in (per-family counts; a sample counts once per signal)")
    for key in sorted({k for t in tables.values() for k in t}):
        if not tables[modes[0]].get(key):
            continue
        print(f"  {key[0]}/{group_name(*key)}")
        for mode in modes:
            print(f"      {mode.upper():10} {_signal_counts(tables[mode][key])}")

    print()
    print(f"{tag} RANKING SANITY CHECK -- queue priority of the tuning phish vs the 26 hand-written benign fixtures (not the spoofs). A sanity check only:")
    print("  the benign side is hand-written, so this says the ordering is not backwards, not how well it ranks real mail.")
    for mode in modes:
        phish = [r.priority for r in tables[mode].get(("malicious", "tuning_corpus"), [])]
        benign = [r.priority for r in tables[mode].get(("benign", "synthetic"), [])]
        a, f = auc(phish, benign), frac_above_median(phish, benign)
        metrics[mode]["ranking"] = {"auc": a, "frac_phish_above_benign_median": f, "n_phish": len(phish), "n_benign": len(benign)}
        text = "n/a (empty side)" if a is None else f"AUC {a:.3f}   fraction of tuning phish above the benign-fixture median priority {f:.2f}"
        print(f"      {mode.upper():10} {text}   (phish n={len(phish)}, benign n={len(benign)})")

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
