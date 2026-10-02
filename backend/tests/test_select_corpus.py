"""scripts/select_corpus.py: seeded, reproducible, blind-by-construction corpus split."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "select_corpus.py"
spec = importlib.util.spec_from_file_location("select_corpus", SCRIPT)
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "pot"
    (src / "samples" / "2024").mkdir(parents=True)
    (src / "samples" / "2025").mkdir(parents=True)
    for i in range(40):
        folder = "2024" if i % 2 else "2025"
        (src / "samples" / folder / f"sample-{i:03d}.eml").write_bytes(f"Subject: s{i}\r\n\r\nbody {i}\r\n".encode())
    (src / "readme.txt").write_text("not an eml")
    (src / "samples" / "huge.eml").write_bytes(b"x" * (sc.MAX_BYTES + 1))
    return src


def _run(source, tmp_path, seed=7, n=20, **kw):
    dest, manifest = tmp_path / "corpus", tmp_path / "CORPUS_MANIFEST.md"
    return sc.run(source, seed, n, dest, manifest, **kw), dest, manifest


def test_eligibility_is_sorted_and_skips_non_eml_and_oversized(source):
    files = sc.eligible(source)
    assert len(files) == 40
    assert [p.relative_to(source).as_posix() for p in files] == sorted(p.relative_to(source).as_posix() for p in files)


def test_split_is_exactly_even_disjoint_and_complete(source, tmp_path):
    result, dest, _ = _run(source, tmp_path)
    assert result == {"eligible": 40, "tuning": 10, "holdout": 10}
    tuning = {p.name for p in (dest / "tuning").glob("*.eml")}
    holdout = {p.name for p in (dest / "holdout").glob("*.eml")}
    assert len(tuning) == len(holdout) == 10 and tuning.isdisjoint(holdout)


def test_same_seed_same_selection_different_seed_different(source, tmp_path):
    a = sc.split(sc.eligible(source), 7, 20)
    b = sc.split(sc.eligible(source), 7, 20)
    c = sc.split(sc.eligible(source), 8, 20)
    assert a == b and a != c


def test_selection_is_a_pure_function_of_the_sorted_list_and_the_seed(source):
    files = sc.eligible(source)
    assert sc.split(files, 3, 10) == sc.split(list(files), 3, 10)
    assert sc.split(files, 3, 10) != sc.split(files, 4, 10)


@pytest.mark.parametrize("n", [0, 1, 3, 21])
def test_odd_or_tiny_sizes_are_rejected(source, tmp_path, n):
    with pytest.raises(ValueError):
        sc.split(sc.eligible(source), 1, n)


def test_too_few_files_is_rejected(source):
    with pytest.raises(ValueError):
        sc.split(sc.eligible(source), 1, 200)


def test_files_are_copied_as_raw_bytes_under_their_hash(source, tmp_path):
    _, dest, _ = _run(source, tmp_path)
    for p in (dest / "tuning").glob("*.eml"):
        assert hashlib.sha256(p.read_bytes()).hexdigest().startswith(p.stem)


def test_manifest_has_seed_and_hashes_but_no_names_or_content(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path, seed=424242)
    text = manifest.read_text(encoding="utf-8")
    assert "`424242`" in text and "## Tuning (10)" in text and "## Hold-out (10)" in text
    assert "sample-0" not in text and "body " not in text and "2024" not in text
    for p in list((dest / "tuning").glob("*.eml")) + list((dest / "holdout").glob("*.eml")):
        assert hashlib.sha256(p.read_bytes()).hexdigest() in text


def test_refuses_to_resplit_an_existing_corpus(source, tmp_path):
    _run(source, tmp_path)
    with pytest.raises(FileExistsError):
        _run(source, tmp_path, seed=99)


def test_force_replaces_the_split(source, tmp_path):
    _, dest, _ = _run(source, tmp_path, seed=1)
    before = {p.name for p in dest.rglob("*.eml")}
    _run(source, tmp_path, seed=2, force=True)
    assert {p.name for p in dest.rglob("*.eml")} != before


def test_source_map_stays_in_the_local_directory_not_the_manifest(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path)
    assert (dest / "SOURCE_MAP.json").exists()
    assert "SOURCE_MAP" not in manifest.read_text(encoding="utf-8")


def test_missing_source_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        sc.run(tmp_path / "nope", 1, 2, tmp_path / "d", tmp_path / "m.md")
