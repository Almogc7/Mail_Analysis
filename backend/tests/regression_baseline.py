"""Per-sample regression baseline: the verdict, score, priority and signals of every fixture and every TUNING sample, in STRICT and CONFIGURED
mode, with clean and unknown enrichment, with the single-sample seeds on and ablated (4 variants x 2 modes x 107 samples = 856 rows).

It exists so that "this change must not move any verdict" (phases A and D of docs/DESIGN_V2.md) is a test, not a manual comparison.

    cd backend && python -m tests.regression_baseline --check     # all four variants; exit 1 and a count of differences if anything moved
    cd backend && python -m tests.regression_baseline --write     # re-record (only after a change that is SUPPOSED to move verdicts)
    cd backend && python -m tests.regression_baseline --write-tiers   # add the verdict v2 tier columns beside the v1 columns, leaving every v1 value as recorded

The v1 columns (verdict, score, priority, reason, signals) and their check are what they always were. Beside them sit the verdict v2 columns (V6): tier, route, reason_codes and blocker_codes, from the REAL
pipeline; `--check` also compares them with the recorded ones and with tests/fixtures/predicted_tiers.json (the pre-registered prediction).

The hold-out is never read (tests.eval.collect never collects it). Rows are keyed by sample file name; the tuning names are the public corpus
hash names already listed in CORPUS_MANIFEST.md. No subject, address, URL or content is stored.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import eval as ev  # noqa: E402

BASELINE = Path(__file__).resolve().parent / "fixtures" / "regression_baseline.json"
# seeds-ablated variants last: ablation edits module state and cannot be undone inside one process
ALL_VARIANTS = (("clean", False), ("unknown", False), ("clean", True), ("unknown", True))
FAST_VARIANTS = (("clean", False),)  # what the unit test recomputes by default (the ablated variants are not undoable in-process)
KEPT = ("verdict", "score", "priority", "reason", "signals")  # the v1 columns: unchanged
TIER_COLUMNS = ("tier", "route", "reason_codes", "blocker_codes")  # the verdict v2 columns, beside them
PREDICTED = Path(__file__).resolve().parent / "fixtures" / "predicted_tiers.json"


def variant_name(enrichment: str, ablated: bool) -> str:
    return f"{enrichment}/{'ablated' if ablated else 'asis'}"


def compute(variants=ALL_VARIANTS, corpus_dir: Path | None = None) -> dict[str, dict]:
    items = ev.collect(corpus_dir)
    rows: dict[str, dict] = {}
    ablated_done = False
    for enrichment, ablated in variants:
        if ablated and not ablated_done:
            ev._ablate_seeds()
            ablated_done = True
        for mode in ev.MODES:
            ev.apply_mode(mode)
            for path, label, source in items:
                row = ev._row_for(path, label, source, "disabled" if enrichment == "unknown" else "clean")
                rows[f"{variant_name(enrichment, ablated)}/{mode}/{source}/{path.name}"] = {k: getattr(row, k) for k in KEPT}
    return rows


def compute_tiers(variants=ALL_VARIANTS, corpus_dir: Path | None = None) -> dict[str, dict]:
    """The verdict v2 columns of every row, from the real pipeline (providers stubbed, no network): {row key: {tier, route, reason_codes, blocker_codes}}."""
    from tests import pipeline_identity as pi

    items = ev.collect(corpus_dir)
    rows: dict[str, dict] = {}
    ablated_done = False
    for enrichment, ablated in variants:
        if ablated and not ablated_done:
            ev._ablate_seeds()
            ablated_done = True
        for mode in ev.MODES:
            for path, _label, source in items:
                v2 = pi.run(path, mode, "disabled" if enrichment == "unknown" else "clean").verdict_v2
                rows[f"{variant_name(enrichment, ablated)}/{mode}/{source}/{path.name}"] = {
                    "tier": v2.tier, "route": v2.route, "reason_codes": sorted({r.code for r in v2.reasons}), "blocker_codes": sorted({b.code for b in v2.blockers})}
    return rows


def load() -> dict[str, dict]:
    return json.loads(BASELINE.read_text(encoding="utf-8"))["rows"]


def differences(current: dict[str, dict], recorded: dict[str, dict]) -> list[str]:
    """Keys whose recorded v1 columns differ, restricted to the keys present in `current` (a partial recompute is compared to its own part). Only the v1 columns are compared here: the verdict v2
    columns have their own checks below, so this check means what it always meant."""
    return sorted(k for k in current if {c: (recorded.get(k) or {}).get(c) for c in KEPT} != current[k])


def tier_differences(current: dict[str, dict], recorded: dict[str, dict]) -> list[str]:
    """Keys whose recorded verdict v2 columns differ from a recompute (restricted to the keys present in `current`)."""
    return sorted(k for k in current if {c: (recorded.get(k) or {}).get(c) for c in TIER_COLUMNS} != current[k])


def predicted_differences(recorded: dict[str, dict]) -> list[str]:
    """Keys whose recorded tier or route differs from tests/fixtures/predicted_tiers.json, the pre-registered prediction (or whose tier columns are missing)."""
    from app.verdict_v2_text import TIER_KEYS

    predicted = json.loads(PREDICTED.read_text(encoding="utf-8"))["rows"]
    out = [k for k in predicted if k not in recorded]
    for key, want in predicted.items():
        row = recorded.get(key)
        if row is not None and (row.get("tier"), row.get("route")) != (TIER_KEYS[want["tier"]], want["route"]):
            out.append(key)
    return sorted(set(out) | {k for k in recorded if k not in predicted})


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    import logging

    logging.getLogger("app").setLevel(logging.ERROR)
    if "--write" in argv:
        rows = compute()
        tiers = compute_tiers()
        for key, columns in tiers.items():
            rows[key].update(columns)
        BASELINE.write_text(json.dumps({"note": "see tests/regression_baseline.py", "rows": rows}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        print(f"recorded {len(rows)} rows")
        return 0
    if "--write-tiers" in argv:
        recorded = load()
        v1_before = {k: {c: row.get(c) for c in KEPT} for k, row in recorded.items()}
        for key, columns in compute_tiers().items():
            recorded[key].update(columns)
        assert {k: {c: row.get(c) for c in KEPT} for k, row in recorded.items()} == v1_before, "a v1 value changed"
        BASELINE.write_text(json.dumps({"note": "see tests/regression_baseline.py", "rows": recorded}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        print(f"added the verdict v2 columns to {len(recorded)} rows; every v1 value is as it was")
        return 0
    recorded = load()
    if "--check-tiers" in argv:  # the verdict v2 columns, in a process of their own (see below)
        tiers = compute_tiers()
        tier_moved = tier_differences(tiers, recorded)
        off_prediction = predicted_differences(recorded)
        print(f"verdict v2 columns: compared {len(tiers)} rows; differ from the recorded: {len(tier_moved)}; recorded rows that differ from predicted_tiers.json: {len(off_prediction)}")
        return 1 if tier_moved or off_prediction else 0
    current = compute()
    moved = differences(current, recorded)
    missing = sorted(set(recorded) - set(current))
    print(f"compared {len(current)} rows against {len(recorded)} recorded; moved: {len(moved)}; recorded but not recomputed: {len(missing)}")
    # The seeds-ablated variants cannot be undone inside one process, and the v1 recompute above has already ablated them, so the verdict v2 columns are recomputed in a fresh process.
    import subprocess

    tiers_run = subprocess.run([sys.executable, "-m", "tests.regression_baseline", "--check-tiers"], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
    print(tiers_run.stdout.strip() or tiers_run.stderr.strip()[-500:])
    return 1 if moved or tiers_run.returncode != 0 else 0


if __name__ == "__main__":
    sys.exit(main())
