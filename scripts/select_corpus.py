#!/usr/bin/env python3
"""Seeded tuning / hold-out split of a local phishing corpus (e.g. a phishing_pot clone).

    python scripts/select_corpus.py --source PATH --seed INT [--n N]
    python scripts/select_corpus.py --verify            # re-check an existing corpus against the manifest

* Eligible files: every *.eml under --source (recursive), sorted by relative path so the same
  source tree and seed always give the same selection. Files over 5 MB are skipped.
* Size: --n defaults to 100 (50/50), or 150 (75/75) when the source has at least 150 usable samples;
  the chosen size is printed. An explicit --n always wins.
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
* After copying, EVERY file is re-read and its SHA256 compared with the manifest; a missing, empty,
  altered or unexpected file (e.g. removed by antivirus quarantine) fails loudly with a non-zero exit.
  Hold-out problems are reported as COUNTS only, never names.
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


class CorpusVerificationError(Exception):
    pass


def read_manifest_hashes(manifest_text: str) -> dict[str, list[str]]:
    """{'tuning': [sha256...], 'holdout': [sha256...]} from the '- `hash`' bullets under each heading."""
    sets: dict[str, list[str]] = {"tuning": [], "holdout": []}
    current = None
    for line in manifest_text.splitlines():
        if line.startswith("## Tuning"):
            current = "tuning"
        elif line.startswith("## Hold-out"):
            current = "holdout"
        elif line.startswith("## "):
            current = None
        elif current and line.startswith("- `") and line.rstrip().endswith("`"):
            sets[current].append(line.strip()[3:-1])
    return sets


def verify(dest: Path, manifest: Path) -> dict[str, int]:
    """Re-read every file and compare with the manifest. Raises CorpusVerificationError listing
    every problem (tuning by name, hold-out as counts only)."""
    if not manifest.exists():
        raise CorpusVerificationError(f"manifest not found: {manifest}")
    expected = read_manifest_hashes(manifest.read_text(encoding="utf-8"))
    if not expected["tuning"] or not expected["holdout"] or len(expected["tuning"]) != len(expected["holdout"]):
        raise CorpusVerificationError("manifest does not describe an even, non-empty tuning/hold-out split")
    if set(expected["tuning"]) & set(expected["holdout"]):
        raise CorpusVerificationError("manifest lists the same file in both tuning and hold-out")

    problems: list[str] = []
    for set_name in ("tuning", "holdout"):
        folder = dest / set_name
        bad = 0
        want = {h[:16]: h for h in expected[set_name]}
        for prefix, digest in sorted(want.items()):
            path = folder / f"{prefix}.eml"
            if not path.is_file():
                bad += 1
                if set_name == "tuning":
                    problems.append(f"tuning/{prefix}.eml is MISSING (quarantined by antivirus, or deleted?)")
            elif path.stat().st_size == 0 or sha256_of(path) != digest:
                bad += 1
                if set_name == "tuning":
                    problems.append(f"tuning/{prefix}.eml is empty or does not match its manifest SHA256")
        extra = [p for p in folder.glob("*.eml") if p.stem not in want] if folder.exists() else []
        for p in extra:
            bad += 1
            if set_name == "tuning":
                problems.append(f"tuning/{p.name} is not in the manifest")
        if set_name == "holdout" and bad:
            problems.append(f"{bad} hold-out file(s) missing, altered or unexpected (names not shown)")
    if problems:
        raise CorpusVerificationError("; ".join(problems))
    return {"tuning": len(expected["tuning"]), "holdout": len(expected["holdout"])}


def run(source: Path, seed: int, n: int | None, dest: Path, manifest: Path, force: bool = False) -> dict:
    if not source.is_dir():
        raise FileNotFoundError(f"--source is not a directory: {source}")
    if dest.exists() and any(dest.rglob("*.eml")) and not force:
        raise FileExistsError(f"{dest} already holds a split; refusing to re-split (see --force)")
    files = eligible(source)
    if n is None:
        n = 150 if len(files) >= 150 else 100
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
    verified = verify(dest, manifest)  # fail loudly if anything is missing, quarantined or altered
    return {"eligible": len(files), "n": n, "tuning": verified["tuning"], "holdout": verified["holdout"]}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", type=Path, help="directory containing the .eml corpus")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--n", type=int, default=None, help="total sample size, even (default: 100, or 150 if >= 150 usable samples)")
    ap.add_argument("--verify", action="store_true", help="only verify an existing corpus against the manifest")
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    if args.verify:
        try:
            counts = verify(args.dest, args.manifest)
        except CorpusVerificationError as exc:
            print(f"select_corpus: VERIFICATION FAILED: {exc}", file=sys.stderr)
            return 3
        print(f"select_corpus: verified tuning={counts['tuning']} holdout={counts['holdout']} against the manifest")
        return 0
    if args.source is None or args.seed is None:
        ap.error("--source and --seed are required (unless --verify)")
    try:
        result = run(args.source, args.seed, args.n, args.dest, args.manifest, args.force)
    except CorpusVerificationError as exc:
        print(f"select_corpus: VERIFICATION FAILED after copying: {exc}", file=sys.stderr)
        return 3
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"select_corpus: {exc}", file=sys.stderr)
        return 1
    print(f"select_corpus: eligible={result['eligible']} n={result['n']} tuning={result['tuning']} holdout={result['holdout']} "
          f"seed={args.seed} -- all files verified against the manifest\nmanifest: {args.manifest}")
    if args.n is None and result['n'] == 150:
        print("select_corpus: source has >= 150 usable samples, so n=150 (75/75) was used")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
