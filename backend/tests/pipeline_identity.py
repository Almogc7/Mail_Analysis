"""Identity snapshot of the REAL pipeline's output (Phase B step 11): a SHA-256 of every section of AnalysisResult that existed before verdict_v2, for every fixture, sample and TUNING message (never the
hold-out), in both modes, with stubbed providers. Recorded BEFORE the pipeline computed verdict_v2, so a test can prove that adding it changed no existing field. Only hashes are stored.

    cd backend && python -m tests.pipeline_identity --write   # only after a change that is SUPPOSED to alter these sections
    cd backend && python -m tests.pipeline_identity --check
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import eval as ev  # noqa: E402

SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "pipeline_identity_snapshot.json"
SAMPLES = ev.FIXTURES / "samples"
SECTIONS = ("parsed_email", "module_results", "findings", "score", "verdict", "confidence", "scoring", "llm_opinion", "indicators", "evidence", "coverage_report", "schema_version")


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, ensure_ascii=True).encode("ascii")).hexdigest()


def run_raw(raw: bytes, name: str, mode: str = "configured", stub: str = "clean", clients: dict | None = None, known_senders: set | None = None, own_domains: set | None = None, llm_enabled: bool = False):
    """The real pipeline on raw message bytes, with the language model stubbed and no real sleeping. The provider clients are the eval stubs (`stub` clean or disabled) unless `clients` is given.
    `known_senders` and `own_domains`, when given, replace the lists AFTER the mode is applied (the mode sets the known-sender list). The language model is OFF unless `llm_enabled`, which is how the
    identity snapshot was recorded (the unit-test configuration switches it on, so it is pinned here)."""
    import app.config as app_config
    import app.llm as llm_package

    import app.enrichment as enrichment_package
    import app.enrichment.providers as providers
    import app.llm.gemini_client as gemini
    from app.api.pipeline import run_pipeline
    from app.enrichment.rate_limit import VTRateLimiter

    ev.apply_mode(mode)
    previous_own, previous_llm = app_config.OWN_DOMAINS, llm_package.LLM_ENABLED
    llm_package.LLM_ENABLED = llm_enabled
    if known_senders is not None:
        app_config.KNOWN_SENDER_DOMAINS = frozenset(known_senders)
    if own_domains is not None:
        app_config.OWN_DOMAINS = frozenset(own_domains)
    chosen = clients if clients is not None else ev._stub_clients(stub)
    real_get_clients, real_get_client, real_limiter = providers.get_clients, gemini.get_client, enrichment_package.VTRateLimiter
    providers.get_clients = lambda: chosen
    gemini.get_client = lambda: (lambda prompt: '{"narrative": "stub narrative", "flags": []}')
    enrichment_package.VTRateLimiter = lambda: VTRateLimiter(sleep_fn=lambda seconds: None)  # the real limiter really sleeps between VirusTotal calls: timing only, never output
    try:
        return run_pipeline(raw, name)
    finally:
        providers.get_clients, gemini.get_client, enrichment_package.VTRateLimiter = real_get_clients, real_get_client, real_limiter
        app_config.OWN_DOMAINS, llm_package.LLM_ENABLED = previous_own, previous_llm
        ev.apply_mode("configured")


def run(path: Path, mode: str, stub: str = "clean"):
    """The real pipeline on a file, with the providers and the language model stubbed (no network)."""
    return run_raw(path.read_bytes(), path.name, mode, stub)


def digests(path: Path, mode: str) -> dict[str, str]:
    dump = run(path, mode).model_dump(mode="json")
    return {section: _digest(dump.get(section)) for section in SECTIONS}


def samples() -> list[tuple[str, Path]]:
    items = [(f"{source}/{p.name}", p) for p, _label, source in ev.collect(None)]
    items += [(f"samples/{p.name}", p) for p in sorted(SAMPLES.glob("*")) if p.suffix.lower() in {".eml", ".msg"}]
    return items


def compute() -> dict[str, dict[str, str]]:
    return {f"{mode}/{key}": digests(path, mode) for mode in ev.MODES for key, path in samples()}


def main(argv: list[str]) -> int:
    logging.getLogger("app").setLevel(logging.ERROR)
    current = compute()
    if "--write" in argv:
        SNAPSHOT.write_text(json.dumps({"note": "see tests/pipeline_identity.py", "messages": current}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        print(f"recorded {len(current)} (mode, message) entries")
        return 0
    recorded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["messages"]
    moved = sorted(k for k in current if recorded.get(k) != current[k])
    print(f"compared {len(current)} entries against {len(recorded)} recorded; changed: {len(moved)}")
    return 1 if moved else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
