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
    assert result == {"eligible": 40, "n": 20, "tuning": 10, "holdout": 10}
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


# ---- sizing: 100 by default, 150 when the source is big enough ------------------------------------

def _many(tmp_path, count):
    src = tmp_path / "many"
    src.mkdir()
    for i in range(count):
        (src / f"s{i:04d}.eml").write_bytes(f"Subject: {i}\r\n\r\nx{i}\r\n".encode())
    return src


@pytest.mark.parametrize("count,expected_n", [(100, 100), (149, 100), (150, 150), (400, 150)])
def test_default_size_is_100_or_150_when_enough_samples(tmp_path, count, expected_n):
    result = sc.run(_many(tmp_path, count), 5, None, tmp_path / "c", tmp_path / "m.md")
    assert result["n"] == expected_n and result["tuning"] == result["holdout"] == expected_n // 2


def test_explicit_n_wins_over_the_default(tmp_path):
    assert sc.run(_many(tmp_path, 400), 5, 100, tmp_path / "c", tmp_path / "m.md")["n"] == 100


def test_fewer_than_100_usable_samples_without_explicit_n_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        sc.run(_many(tmp_path, 60), 5, None, tmp_path / "c", tmp_path / "m.md")


# ---- verification ---------------------------------------------------------------------------------

def test_read_manifest_hashes_round_trips(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path)
    sets = sc.read_manifest_hashes(manifest.read_text(encoding="utf-8"))
    assert len(sets["tuning"]) == len(sets["holdout"]) == 10
    assert {h[:16] for h in sets["tuning"]} == {p.stem for p in (dest / "tuning").glob("*.eml")}


def test_verify_passes_on_an_intact_corpus(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path)
    assert sc.verify(dest, manifest) == {"tuning": 10, "holdout": 10}


def test_a_file_quarantined_during_copy_fails_loudly(source, tmp_path, monkeypatch):
    real_copy = sc.shutil.copyfile
    dropped = []

    def flaky(src, dst, *a, **k):
        if not dropped and "tuning" in Path(dst).parts:
            dropped.append(dst)  # silently "quarantine" the first tuning file
            return None
        return real_copy(src, dst, *a, **k)

    monkeypatch.setattr(sc.shutil, "copyfile", flaky)
    with pytest.raises(sc.CorpusVerificationError, match="MISSING"):
        _run(source, tmp_path)


def test_main_exits_3_when_verification_fails(source, tmp_path, monkeypatch, capsys):
    _, dest, manifest = _run(source, tmp_path)
    next((dest / "tuning").glob("*.eml")).unlink()
    assert sc.main(["--verify", "--dest", str(dest), "--manifest", str(manifest)]) == 3
    assert "VERIFICATION FAILED" in capsys.readouterr().err


def test_main_verify_succeeds_on_intact_corpus(source, tmp_path, capsys):
    _, dest, manifest = _run(source, tmp_path)
    assert sc.main(["--verify", "--dest", str(dest), "--manifest", str(manifest)]) == 0
    assert "verified tuning=10 holdout=10" in capsys.readouterr().out


def test_altered_and_empty_and_unexpected_files_are_all_detected(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path)
    files = sorted((dest / "tuning").glob("*.eml"))
    files[0].write_bytes(b"tampered")
    files[1].write_bytes(b"")
    (dest / "tuning" / "ffffffffffffffff.eml").write_bytes(b"extra")
    with pytest.raises(sc.CorpusVerificationError) as exc:
        sc.verify(dest, manifest)
    message = str(exc.value)
    assert "does not match" in message and "is not in the manifest" in message


def test_holdout_problems_are_reported_as_counts_never_names(source, tmp_path):
    _, dest, manifest = _run(source, tmp_path)
    victims = sorted((dest / "holdout").glob("*.eml"))[:3]
    names = [v.stem for v in victims]
    victims[0].unlink()
    victims[1].write_bytes(b"tampered")
    (dest / "holdout" / "eeeeeeeeeeeeeeee.eml").write_bytes(b"extra")
    with pytest.raises(sc.CorpusVerificationError) as exc:
        sc.verify(dest, manifest)
    message = str(exc.value)
    assert "3 hold-out file(s)" in message and "names not shown" in message
    assert not any(n in message for n in names) and "eeeeeeeeeeeeeeee" not in message


def test_verify_rejects_a_manifest_that_is_not_an_even_split(tmp_path):
    bad = tmp_path / "m.md"
    bad.write_text("\n".join(["## Tuning (1)", "", "- `" + "a" * 64 + "`", "", "## Hold-out (0)", ""]), encoding="utf-8")
    with pytest.raises(sc.CorpusVerificationError):
        sc.verify(tmp_path, bad)
