"""Aggregate profile of the tuning phish that the PRE-iteration-1 rule called benign in CONFIGURED mode.

    cd backend && python -m tests.former_misses

Diagnostic for docs/DETECTION_DESIGN.md iteration 1. It runs the CONFIGURED trust mode over the TUNING split twice:
once with the old rule (authentication alone could be benign: require_known_sender_for_benign=False) to find the
"former misses", and once with the current rule, and reports what those messages look like.

AGGREGATES ONLY: counts and coverage values. No subject, address, host, URL, file name or content; finding titles
are reduced to a generic signal name. The hold-out is never read (a path containing 'holdout' is refused).
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import eval as ev  # noqa: E402


def _signal_name(title: str) -> str:
    """'Suspicious host: x.example' -> 'Suspicious host'; 'Possible display-name spoofing of 'b'' -> '... spoofing'."""
    return re.split(r" of '| for |: ", title, maxsplit=1)[0]


def profile(rows: list[dict]) -> list[str]:
    n = len(rows)
    out = [f"former misses (CONFIGURED, old rule called them benign): {n}"]
    if not n:
        return out
    cov = Counter()
    for r in rows:
        cov[(r["coverage"]["auth_check"], r["coverage"]["enrichment"], r["coverage"]["content_analysis"])] += 1
    out.append("coverage (auth, enrichment, content) -> samples:")
    for key, count in sorted(cov.items()):
        out.append(f"    {key[0]:.2f} / {key[1]:.2f} / {key[2]:.2f}  ->  {count}")
    out.append("enrichment states (samples with at least one indicator in the state): "
               + ", ".join(f"{k} {v}" for k, v in sorted(Counter(s for r in rows for s in set(r["enrichment_states"])).items())))
    out.append("enrichment: samples with NO indicator at all: " + str(sum(1 for r in rows if not r["enrichment_states"])))
    out.append("auth evidence the old rule relied on (samples): " + ", ".join(
        f"{k} {v}" for k, v in sorted(Counter(k for r in rows for k in set(r["auth_basis"])).items())))
    out.append("signals fired (non-info, samples): " + (", ".join(
        f"{k} {v}" for k, v in sorted(Counter(s for r in rows for s in set(r["signals"])).items())) or "none"))
    out.append(f"samples with no non-info finding at all: {sum(1 for r in rows if not r['signals'])}")
    out.append("verdict under the current rule: " + ", ".join(f"{k} {v}" for k, v in sorted(Counter(r["new_verdict"] for r in rows).items())))
    out.append("override that decided it under the current rule: " + ", ".join(
        f"{k} {v}" for k, v in sorted(Counter(o for r in rows for o in set(r["new_overrides"])).items())))
    return out


def _describe(res) -> dict:
    auth = next(m for m in res.module_results if m.module == "auth_check")
    enr = next(m for m in res.module_results if m.module == "enrichment")
    headers = (auth.raw_data or {}).get("auth_headers", {})
    basis: list[str] = []
    for method in ("dkim", "dmarc", "spf"):
        m = headers.get(method, {})
        if m.get("evaluated"):
            tb = m.get("trust_basis") or {}
            how = "authserv-less header (opt-in placeholder)" if tb.get("hop_index") is None else "header attributed to a hop"
            basis.append(f"{method} {m.get('result')} via {m.get('source')} / {how}")
    states: list[str] = []
    for value in (enr.raw_data or {}).values():
        if not isinstance(value, dict):
            continue
        if "uninformative" in value:
            states.append("uninformative (shared platform)")
        elif value.get("internal_host_not_sent"):
            states.append("internal (not sent)")
        elif any(isinstance(v, dict) and v.get("status") not in (None, "ok") for v in value.get("providers", value).values() if isinstance(v, dict)):
            states.append("unknown (a provider did not answer)")
        else:
            states.append("looked up, nothing found")
    return {
        "coverage": {c.category: round(c.coverage, 2) for c in res.scoring.categories},
        "enrichment_states": states,
        "auth_basis": basis or ["no evaluated method"],
        "signals": [_signal_name(f.title) for f in res.findings if f.severity != "info"],
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    tuning = ev.FIXTURES / "_local_corpus" / "tuning"
    if "holdout" in str(tuning).lower().replace("tuning", ""):
        print("former_misses: refusing a hold-out path", file=sys.stderr)
        return 2
    files = sorted(tuning.glob("*.eml"))
    if not files:
        print("former_misses: no local tuning corpus")
        return 0
    from app.scoring import config as scoring_config

    ev.apply_mode("configured")
    import app.scoring as scoring

    real_run = scoring.run_scoring
    rows: list[dict] = []
    for path in files:
        scoring.run_scoring = lambda results, config=None: real_run(results, scoring_config.ScoringConfig(require_known_sender_for_benign=False))
        try:
            old = ev.analyze(path, "clean")
        finally:
            scoring.run_scoring = real_run
        if old.verdict != "legit":
            continue
        new = ev.analyze(path, "clean")
        row = _describe(old)
        row.update(new_verdict=new.verdict, new_overrides=[o.rule for o in new.scoring.applied_overrides])
        rows.append(row)
    print(f"tuning samples: {len(files)}")
    print("\n".join(profile(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
