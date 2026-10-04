"""Per-sample regression baseline: the verdict, score, priority and signals of every fixture and every TUNING sample, in STRICT and CONFIGURED
mode, with clean and unknown enrichment, with the single-sample seeds on and ablated (4 variants x 2 modes x 107 samples = 856 rows).

It exists so that "this change must not move any verdict" (phases A and D of docs/DESIGN_V2.md) is a test, not a manual comparison.

    cd backend && python -m tests.regression_baseline --check     # all four variants; exit 1 and a count of differences if anything moved
    cd backend && python -m tests.regression_baseline --write     # re-record (only after a change that is SUPPOSED to move verdicts)

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
KEPT = ("verdict", "score", "priority", "reason", "signals")


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


def load() -> dict[str, dict]:
    return json.loads(BASELINE.read_text(encoding="utf-8"))["rows"]


def differences(current: dict[str, dict], recorded: dict[str, dict]) -> list[str]:
    """Keys whose recorded row differs, restricted to the keys present in `current` (a partial recompute is compared to its own part)."""
    return sorted(k for k in current if recorded.get(k) != current[k])


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    import logging

    logging.getLogger("app").setLevel(logging.ERROR)
    if "--write" in argv:
        rows = compute()
        BASELINE.write_text(json.dumps({"note": "see tests/regression_baseline.py", "rows": rows}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        print(f"recorded {len(rows)} rows")
        return 0
    current = compute()
    recorded = load()
    moved = differences(current, recorded)
    missing = sorted(set(recorded) - set(current))
    print(f"compared {len(current)} rows against {len(recorded)} recorded; moved: {len(moved)}; recorded but not recomputed: {len(missing)}")
    return 1 if moved else 0


if __name__ == "__main__":
    sys.exit(main())
