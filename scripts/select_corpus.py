#!/usr/bin/env python3
"""Seeded tuning / hold-out split of a local phishing corpus (e.g. a phishing_pot clone).

    python scripts/select_corpus.py --source PATH --seed 20261003 [--n 60]

* Eligible files: every *.eml under --source (recursive), sorted by relative path so the same
  source tree and seed always give the same selection. Files over 5 MB are skipped.
* Selection is a seeded random sample, never hand-picked. The first half becomes the TUNING set
  (the only set whose verdicts may be looked at while building detections) and the second half the
  HOLD-OUT set (not evaluated until the tuning work is finished; tests/eval.py refuses to read it
  without EVAL_UNBLIND_HOLDOUT=1).
* Files are COPIED as raw bytes into backend/tests/fixtures/_local_corpus/{tuning,holdout}/ under
  their SHA256 prefix. That directory is gitignored: raw malicious mail never enters the repo.
  A local-only SOURCE_MAP.json (hash -> original relative path) stays beside them.
* Nothing is parsed, rendered or executed here and attachments are never opened or extracted.
* Only backend/tests/fixtures/CORPUS_MANIFEST.md is tracked: seed, counts and SHA256 hashes of the
  files as received (both sets), no names, no content.
* It refuses to run if the destination already holds a split (use --force only if you accept that
  the old hold-out is thereby discarded -- re-splitting after looking at results defeats its
  purpose).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = ROOT / "backend" / "tests" / "fixtures" / "_local_corpus"
DEFAULT_MANIFEST = ROOT / "backend" / "tests" / "fixtures" / "CORPUS_MANIFEST.md"
MAX_BYTES = 5 * 1024 * 1024


def eligible(source: Path) -> list[Path]:
    files = [p for p in source.rglob("*.eml") if p.is_file() and p.stat().st_size <= MAX_BYTES]
    return sorted(files, key=lambda p: p.relative_to(source).as_posix())


def split(files: list[Path], seed: int, n: int) -> tuple[list[Path], list[Path]]:
    if n < 2 or n % 2:
        raise ValueError("--n must be an even number >= 2 so the split is exactly 50/50")
    if len(files) < n:
        raise ValueError(f"only {len(files)} eligible files, fewer than --n {n}")
    picked = random.Random(seed).sample(files, n)  # seeded, order-independent of the filesystem
    half = n // 2
    return picked[:half], picked[half:]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_manifest(source_label: str, seed: int, n: int, total: int, tuning: list[str], holdout: list[str]) -> str:
    lines = [
        "# Local corpus manifest",
        "",
        "Raw samples are NOT in the repo: `backend/tests/fixtures/_local_corpus/` is gitignored. This file",
        "records only how the split was made and SHA256 hashes of the files **as received**.",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Source | {source_label} |",
        f"| Eligible files at selection time | {total} |",
        f"| Selection | seeded random sample (`random.Random(seed).sample`) of the path-sorted list, never by hand |",
        f"| Seed | `{seed}` |",
        f"| Sample size | {n} ({n // 2} tuning / {n // 2} hold-out, 50/50) |",
        f"| Created (UTC) | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} |",
        "",
        "Rules: only TUNING verdicts may be looked at while building detections. HOLD-OUT is evaluated once,",
        "after the verdict-model work, with `EVAL_UNBLIND_HOLDOUT=1`. Attachments are never opened.",
        "Re-running the split after looking at results invalidates the hold-out.",
        "",
        f"## Tuning ({len(tuning)})",
        "",
        *[f"- `{h}`" for h in sorted(tuning)],
        "",
        f"## Hold-out ({len(holdout)})",
        "",
        *[f"- `{h}`" for h in sorted(holdout)],
        "",
    ]
    return "\n".join(lines)


def run(source: Path, seed: int, n: int, dest: Path, manifest: Path, force: bool = False) -> dict:
    if not source.is_dir():
        raise FileNotFoundError(f"--source is not a directory: {source}")
    if dest.exists() and any(dest.rglob("*.eml")) and not force:
        raise FileExistsError(f"{dest} already holds a split; refusing to re-split (see --force)")
    files = eligible(source)
    tuning_src, holdout_src = split(files, seed, n)

    if dest.exists() and force:
        shutil.rmtree(dest)
    mapping: dict[str, str] = {}
    hashes: dict[str, list[str]] = {"tuning": [], "holdout": []}
    for set_name, chosen in (("tuning", tuning_src), ("holdout", holdout_src)):
        target = dest / set_name
        target.mkdir(parents=True, exist_ok=True)
        for src in chosen:
            digest = sha256_of(src)
            shutil.copyfile(src, target / f"{digest[:16]}.eml")  # raw bytes; never parsed here
            mapping[digest] = src.relative_to(source).as_posix()
            hashes[set_name].append(digest)
    (dest / "SOURCE_MAP.json").write_text(json.dumps(mapping, indent=1), encoding="utf-8")
    manifest.write_text(
        render_manifest("phishing_pot (local clone, path supplied by the repo owner)", seed, n, len(files),
                        hashes["tuning"], hashes["holdout"]),
        encoding="utf-8",
    )
    return {"eligible": len(files), "tuning": len(hashes["tuning"]), "holdout": len(hashes["holdout"])}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True, type=Path, help="directory containing the .eml corpus")
    ap.add_argument("--seed", required=True, type=int)
    ap.add_argument("--n", type=int, default=60, help="total sample size, even (default 60 -> 30/30)")
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    try:
        result = run(args.source, args.seed, args.n, args.dest, args.manifest, args.force)
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"select_corpus: {exc}", file=sys.stderr)
        return 1
    print(f"select_corpus: eligible={result['eligible']} tuning={result['tuning']} holdout={result['holdout']} "
          f"seed={args.seed}\nmanifest: {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
