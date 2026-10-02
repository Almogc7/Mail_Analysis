"""Offline eval over tests/fixtures/{malicious,benign}/.

    cd backend && python -m tests.eval [--ablate-seeds] [--enrichment clean|disabled] [--json OUT]

Runs parse -> auth_check -> enrichment (stub providers, NO network) -> content_analysis ->
scoring. The LLM module is never called. Prints the per-fixture verdict, score and
per-category coverage first (a corpus this small makes P/R alone misleading), then P/R.

Reading the numbers:
  * "flagged" = verdict in {malicious, suspicious}. Two variants are printed because
    `needs_review` is an abstention: strict counts it as NOT flagged, lenient as flagged.
  * malicious/synthetic/ are hand-written display-name-spoof positives (matcher tests);
    they are not real phish and not an accuracy claim either.
  * Synthetic benign fixtures (benign/synthetic/) are hand-written regression guards against
    over-flagging. They are NOT an accuracy claim. Only benign/_from_user/ and the local
    corpus are real data.
  * --enrichment clean assumes every provider answers "no detections" (what a fresh
    attacker-controlled URL looks like). It measures the structural signals alone.
  * --ablate-seeds removes the two single-sample seeds (the "kvish6" brand token and the
    Hebrew urgency phrase taken from that sample). This is the honest "before".

Local corpus (gitignored): tests/fixtures/_local_corpus/tuning/*.eml are evaluated if the
directory exists and skipped silently otherwise. _local_corpus/holdout/ is NEVER evaluated
unless EVAL_UNBLIND_HOLDOUT=1 -- it exists to be looked at once, after tuning is finished.
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


def collect() -> list[tuple[Path, str, str]]:
    items: list[tuple[Path, str, str]] = []

    def add(directory: Path, label: str, source_of):
        if directory.exists():
            for p in sorted(directory.rglob("*")):
                if p.suffix.lower() in {".eml", ".msg"}:
                    items.append((p, label, source_of(p)))

    add(FIXTURES / "malicious", "malicious", lambda p: "kvish" if p.parent.name == "malicious" else p.parent.name)
    add(FIXTURES / "benign", "benign", lambda p: p.parent.name)
    add(FIXTURES / "_local_corpus" / "tuning", "malicious", lambda p: "local_corpus")
    if os.environ.get("EVAL_UNBLIND_HOLDOUT") == "1":
        add(FIXTURES / "_local_corpus" / "holdout", "malicious", lambda p: "HOLDOUT")
    return items


def _prf(rows: list[Row], lenient: bool) -> tuple[int, int, int, int, float | None, float | None]:
    flagged = FLAGGED | ({"needs_review"} if lenient else set())
    tp = sum(1 for r in rows if r.label == "malicious" and r.verdict in flagged)
    fn = sum(1 for r in rows if r.label == "malicious" and r.verdict not in flagged)
    fp = sum(1 for r in rows if r.label == "benign" and r.verdict in flagged)
    tn = sum(1 for r in rows if r.label == "benign" and r.verdict not in flagged)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return tp, fp, fn, tn, precision, recall


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ablate-seeds", action="store_true", help="remove the single-sample brand/Hebrew seeds")
    ap.add_argument("--enrichment", choices=("clean", "disabled"), default="clean")
    ap.add_argument("--json", metavar="OUT", help="also write rows + metrics as JSON")
    ap.add_argument("--no-gate", action="store_true", help="exit 0 even if a benign fixture is malicious")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    if args.ablate_seeds:
        _ablate_seeds()

    items = collect()
    rows = [_row_for(p, label, src, args.enrichment) for p, label, src in items]

    print(f"eval: enrichment={args.enrichment} ablate_seeds={args.ablate_seeds} fixtures={len(rows)}")
    corpus = FIXTURES / "_local_corpus"
    if not (corpus / "tuning").exists():
        print("eval: no local corpus (tests/fixtures/_local_corpus/tuning) -- skipped")
    holdout = corpus / "holdout"
    if holdout.exists() and os.environ.get("EVAL_UNBLIND_HOLDOUT") != "1":
        n = sum(1 for _ in holdout.rglob("*.eml"))
        print(f"eval: hold-out present ({n} files) -- NOT evaluated (set EVAL_UNBLIND_HOLDOUT=1 after tuning is done)")
    print("note: synthetic benign fixtures are regression guards, not an accuracy claim\n")

    header = f"{'label':9} {'source':10} {'verdict':12} {'score':>5} {'conf':>5}  {'cov auth/enr/content':21} fixture"
    print(header)
    print("-" * len(header))
    for r in rows:
        cov = "/".join(f"{r.coverage.get(c, 0):.2f}" for c in ("auth_check", "enrichment", "content_analysis"))
        print(f"{r.label:9} {r.source:10} {r.verdict:12} {r.score:>5} {r.confidence:>5}  {cov:21} {r.name}")
        if r.error:
            print(f"{'':9} !! {r.error}")
        elif r.label == "malicious" or r.verdict in FLAGGED | {"needs_review"}:
            extra = ", ".join(r.overrides) or "-"
            print(f"{'':9} overrides: {extra} | {'; '.join(r.top_findings) or 'no non-info findings'}")

    print()
    metrics = {}
    for name, lenient in (("strict (needs_review = not flagged)", False), ("lenient (needs_review = flagged)", True)):
        tp, fp, fn, tn, p, rc = _prf(rows, lenient)
        metrics[name] = dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=p, recall=rc)
        print(f"{name:38} TP={tp} FP={fp} FN={fn} TN={tn}  precision={_fmt(p)} recall={_fmt(rc)}")
    benign_mal = [r.name for r in rows if r.label == "benign" and r.verdict == "malicious"]
    print(f"benign fixtures reaching MALICIOUS: {len(benign_mal)}" + (f" -> {benign_mal}" if benign_mal else ""))
    by_src = {}
    for r in rows:
        by_src.setdefault((r.label, r.source), []).append(r.verdict)
    print("flagged by source (flagged/total):")
    for (lab, src), verdicts in sorted(by_src.items()):
        print(f"  {lab}/{src}: {sum(v in FLAGGED for v in verdicts)}/{len(verdicts)}")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"args": vars(args), "rows": [asdict(r) for r in rows], "metrics": metrics}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
    return 0 if args.no_gate or not benign_mal else 1


if __name__ == "__main__":
    sys.exit(main())
