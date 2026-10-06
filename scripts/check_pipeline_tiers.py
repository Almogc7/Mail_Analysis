"""The 856-row comparison THROUGH THE REAL PIPELINE (Phase B step 11): verdict_v2.tier and verdict_v2.route of run_pipeline equal backend/tests/fixtures/predicted_tiers.json on every baseline row.

    python scripts/check_pipeline_tiers.py              # all 856 rows (4 variants x 2 modes x 107 samples); exit 1 on any difference
    python scripts/check_pipeline_tiers.py --variants fast   # the 214 as-is clean rows

The rows are the regression baseline's (same variants, modes, samples and keys), run through api.pipeline.run_pipeline with stubbed providers and a stubbed language model (no network, no real sleeping).
A difference is NOT fixed by changing compute_tier, the predictor or the prediction: it is listed and reported (iteration 1 of 3). The seeds-ablated variants cannot be undone inside one process, which
is why the unit test runs this script in a subprocess for the full set. Read-only; the hold-out is never read. Prints the tier counts per mode as aggregates.
"""
from __future__ import annotations

import collections
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.verdict_v2_text import TIER_KEYS  # noqa: E402
from tests import eval as ev  # noqa: E402
from tests import pipeline_identity as pi  # noqa: E402
from tests import regression_baseline as rb  # noqa: E402

PREDICTED = ROOT / "backend" / "tests" / "fixtures" / "predicted_tiers.json"


def check(variants=rb.ALL_VARIANTS) -> dict:
    predicted = json.loads(PREDICTED.read_text(encoding="utf-8"))["rows"]
    items = ev.collect(None)
    differing: list[str] = []
    missing = 0
    counts: dict[str, collections.Counter] = {}
    total = 0
    ablated_done = False
    for enrichment, ablated in variants:
        if ablated and not ablated_done:
            ev._ablate_seeds()
            ablated_done = True
        for mode in ev.MODES:
            for path, _label, source in items:
                key = f"{rb.variant_name(enrichment, ablated)}/{mode}/{source}/{path.name}"
                result = pi.run(path, mode, "disabled" if enrichment == "unknown" else "clean")
                total += 1
                v2 = result.verdict_v2
                if v2 is None:
                    missing += 1
                    differing.append(f"{key} | no verdict_v2")
                    continue
                want = predicted[key]
                if (v2.tier, v2.route) != (TIER_KEYS[want["tier"]], want["route"]):
                    differing.append(f"{key} | pipeline {v2.tier} {v2.route} | predicted {TIER_KEYS[want['tier']]} {want['route']}")
                if enrichment == "clean" and not ablated:
                    counts.setdefault(mode, collections.Counter())[v2.tier] += 1
    return {"rows": total, "differing": differing, "missing": missing, "tier_counts_as_is_clean": {m: dict(sorted(c.items())) for m, c in counts.items()}}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    logging.getLogger("app").setLevel(logging.ERROR)
    outcome = check(rb.FAST_VARIANTS if "fast" in argv else rb.ALL_VARIANTS)
    print(f"checked {outcome['rows']} rows through the real pipeline; verdict_v2 missing: {outcome['missing']}; tier or route differs from predicted_tiers.json: {len(outcome['differing'])}")
    print("tier counts, as-is clean variant:", json.dumps(outcome["tier_counts_as_is_clean"], sort_keys=True))
    for line in outcome["differing"]:
        print("DIFFERS:", line)
    return 1 if outcome["differing"] else 0


if __name__ == "__main__":
    sys.exit(main())
