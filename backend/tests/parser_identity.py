"""Identity snapshot of what the parser's additive metadata fields must NOT change (Phase B step 10).

For every fixture, every message in tests/fixtures/samples and every TUNING-corpus message (never the hold-out), this records a SHA-256 of each existing output section: the `attachments` list, the
`urls` list, the `images` list, the evidence block and the indicator pack (the Attachments panel and the indicator list are built from these). The snapshot was recorded BEFORE the parser additions of step
10, so a test can prove that they left those sections byte-identical. Only hashes are stored: no name, address, URL or content.

    cd backend && python -m tests.parser_identity --write   # re-record, only after a change that is SUPPOSED to alter these sections
    cd backend && python -m tests.parser_identity --check    # exit 1 and a count of differing messages if anything changed
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import eval as ev  # noqa: E402

SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "parser_identity_snapshot.json"
SAMPLES = ev.FIXTURES / "samples"
SECTIONS = ("attachments", "urls", "images", "evidence", "indicators")


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, ensure_ascii=True).encode("ascii")).hexdigest()


def digests(path: Path) -> dict[str, str]:
    from app.evidence import build_evidence
    from app.indicators import build_indicator_pack, visible_pack

    result = ev.analyze(path, "clean")
    parsed, modules = result.parsed_email, result.module_results
    indicators = build_indicator_pack(parsed, modules)
    evidence = build_evidence(parsed, modules, indicators)
    return {
        "attachments": _digest([a.model_dump() for a in parsed.attachments]),
        "urls": _digest([u.model_dump() for u in parsed.urls]),
        "images": _digest([i.model_dump() for i in parsed.images]),
        "evidence": _digest(evidence.model_dump(mode="json")),
        "indicators": _digest(visible_pack(indicators).model_dump(mode="json")),
    }


def samples() -> list[tuple[str, Path]]:
    items = [(f"{source}/{p.name}", p) for p, _label, source in ev.collect(None)]
    items += [(f"samples/{p.name}", p) for p in sorted(SAMPLES.glob("*")) if p.suffix.lower() in {".eml", ".msg"}]
    return items


def compute() -> dict[str, dict[str, str]]:
    ev.apply_mode("configured")
    return {key: digests(path) for key, path in samples()}


def main(argv: list[str]) -> int:
    logging.getLogger("app").setLevel(logging.ERROR)
    current = compute()
    if "--write" in argv:
        SNAPSHOT.write_text(json.dumps({"note": "see tests/parser_identity.py", "messages": current}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        print(f"recorded {len(current)} messages")
        return 0
    recorded = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["messages"]
    moved = sorted(k for k in current if recorded.get(k) != current[k])
    print(f"compared {len(current)} messages against {len(recorded)} recorded; changed: {len(moved)}")
    return 1 if moved else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
