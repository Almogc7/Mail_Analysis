"""Mail_Analysis is self-contained: it imports nothing from outside this repository (other than the standard library and the packages in
requirements.txt), has no path hacks, reads nothing above the repo root, and no tracked file refers to the repository its provider code
once came from by path, URL, environment variable or bridge module."""
import ast
import importlib
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "_local_corpus", "corporaphishing_pot", "_import_src", "__pycache__", "team-config",
             ".pytest_cache", ".claude"}
SKIP_NAMES = {".env", ".denylist.local"}
TEXT_SUFFIXES = {".py", ".md", ".txt", ".yml", ".yaml", ".json", ".ts", ".tsx", ".ps1", ".bat", ".example", ".toml", ".cfg", ".ini", ".html", ".css"}

# Top-level import names that requirements.txt (and pytest's own machinery) legitimately provide.
THIRD_PARTY = {
    "fastapi", "starlette", "uvicorn", "multipart", "pydantic", "dotenv", "bs4", "extract_msg", "authres", "rapidfuzz", "tldextract",
    "requests", "google", "pytest", "_pytest", "httpx",
}
# Modules that live in this repository: the app and test packages, and the helper scripts that import each other.
REPO_LOCAL = {"app", "tests", "conftest", "scripts"} | {p.stem for p in (REPO / "scripts").glob("*.py")}
# Built from pieces so this file does not match its own scan.
FORBIDDEN_TOKENS = ["IOC_ENRICHER" + "_PATH", "IOC_ENRICHER" + "_REF", "ioc-enrichment" + "-tool", "ioc" + "_bridge", "gemini" + "_bridge",
                    "ensure_ioc" + "_enricher_on_path"]


def _files(suffixes):
    for path in REPO.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes and path.name not in SKIP_NAMES:
            continue
        rel = path.relative_to(REPO)
        if any(part in SKIP_DIRS for part in rel.parts) or path.name in SKIP_NAMES or ".local." in path.name or ".sqlite" in path.name:
            continue
        yield path


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module.split(".")[0]


def test_every_python_file_imports_only_stdlib_declared_packages_or_this_repo():
    allowed = set(sys.stdlib_module_names) | THIRD_PARTY | REPO_LOCAL
    outside = sorted(f"{p.relative_to(REPO)}:{line} imports '{name}'" for p in _files({".py"}) for line, name in _imports(p) if name not in allowed)
    assert outside == []


def test_the_declared_third_party_packages_are_really_in_requirements():
    requirements = (REPO / "backend" / "requirements.txt").read_text(encoding="utf-8").lower()
    for package in ("fastapi", "requests", "google-genai", "pydantic", "python-dotenv", "tldextract", "extract-msg", "authres", "rapidfuzz", "beautifulsoup4", "httpx", "pytest"):
        assert package in requirements


def test_the_requirements_have_no_second_repo_and_no_unused_heavy_packages():
    lines = [l.strip() for l in (REPO / "backend" / "requirements.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    assert not any("git+" in l or "://" in l or l.startswith(("-e", ".", "/")) for l in lines)
    for banned in ("pdfplumber", "python-docx", "docx"):
        assert not any(l.lower().startswith(banned) for l in lines)


def test_no_application_code_touches_sys_path_or_reaches_above_the_repository_root():
    problems = []
    for path in (REPO / "backend" / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"sys\.path\.(insert|append)|sys\.path\s*(\+|=)|PYTHONPATH", text):
            problems.append(f"{path.relative_to(REPO)}: changes sys.path")
        depth = len(path.relative_to(REPO).parts)  # parents[depth - 1] is the repository root
        for match in re.finditer(r"parents\[(\d+)\]", text):
            if int(match.group(1)) > depth - 1:
                problems.append(f"{path.relative_to(REPO)}: parents[{match.group(1)}] reaches above the repository")
        if re.search(r"\.parent\.parent\.parent\.parent", text):
            problems.append(f"{path.relative_to(REPO)}: climbs four parents")
    assert problems == []


def test_no_tracked_file_references_the_other_repository_by_variable_url_or_bridge():
    hits = []
    for path in _files(TEXT_SUFFIXES):
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits += [f"{path.relative_to(REPO)}: {token}" for token in FORBIDDEN_TOKENS if token in text]
    assert hits == []


def test_the_old_bridge_modules_and_settings_are_gone():
    for name in ("app.enrichment." + "ioc" + "_bridge", "app.llm." + "gemini" + "_bridge"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(name)
    import app.config as config

    assert not hasattr(config, "IOC_ENRICHER" + "_PATH")
    assert not (REPO / "deploy" / ("IOC_ENRICHER" + "_REF")).exists()


def test_importing_the_app_does_not_put_any_foreign_path_on_sys_path():
    before = list(sys.path)
    import app.enrichment.providers  # noqa: F401
    import app.llm.gemini_client  # noqa: F401
    import app.main  # noqa: F401

    assert [p for p in sys.path if p not in before] == []
    assert not any(Path(p).name.lower() == "ioc_enricher" for p in sys.path if p)


def test_the_providers_construct_with_no_network_and_no_keys_and_report_disabled():
    from app.enrichment.providers import MalwareBazaarClient, ThreatFoxClient, URLScanClient, VirusTotalClient

    for client in (VirusTotalClient(""), URLScanClient(""), ThreatFoxClient(""), MalwareBazaarClient("")):
        assert client.enrich("example.org", "domain")["status"] == "disabled"
