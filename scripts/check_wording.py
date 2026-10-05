#!/usr/bin/env python3
"""V1 word-ban lint, REPORT-ONLY (docs/DESIGN_V2.md section 2.1, criterion V1).

The words safe, clean, legit, benign and harmless are banned as WHOLE words (case-insensitive; "safety" is not "safe") in every user-visible string.
This script finds them and proposes a replacement. It does NOT fail anything by default, it is NOT run by the pre-commit hook, and no test asserts
that the repository has zero hits: it exists so the wording cleanup commit can be written from a complete list, and so V1 can be switched on later.

    scripts/check_wording.py                 report: static scan (backend and frontend source) plus runtime scan (fixtures and the tuning corpus)
    scripts/check_wording.py --static        static scan only (fast; no pipeline run)
    scripts/check_wording.py --json OUT      also write the hits as JSON
    scripts/check_wording.py --strict        exit 1 if any hit exists (for the day V1 is enabled; never used by the hook today)

Two sources of strings, so nothing is missed:
  * STATIC: every string literal in the backend that reads as user-visible text (finding titles and descriptions, coverage and indicator text, log
    calls, prints, HTTP errors, labels), found with the Python AST (comments and docstrings are skipped by the parser); and the frontend source found
    with the TypeScript compiler API through scripts/wording_frontend_strings.mjs (JSX text, title, aria-label, placeholder, alt, label, console
    messages, prose string literals). This finds templates that no fixture triggers.
  * RUNTIME: the pipeline over the fixtures and the TUNING corpus only (the hold-out is never read), scanning the produced fields: findings, applied
    overrides, coverage, indicators, the evidence block and the LLM prompt. A hit that sits in a value that may carry message text is printed as its
    template (quoted parts masked) or withheld.

Exemptions, explicit and closed:
  * the frozen v1 `verdict` value and internal keys, tokens, CSS hooks and type unions (single-word strings, className-style attributes, type positions,
    property names): not user-visible. Single-word banned tokens are COUNTED and listed, never silently dropped;
  * required negated disclaimers, by exact string, in scripts/wording_allowlist.json (empty today);
  * provider raw-data field names ONLY inside the raw-data block (module_results[*].raw_data): the same word in a label, reason or finding fails;
  * message content (parsed_email and the indicator, link, attachment, image and hop fields that hold message text).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path(__file__).with_name("wording_allowlist.json")
BANNED = ("safe", "clean", "legit", "benign", "harmless")
WORD = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(BANNED) + r")(?![A-Za-z0-9_])", re.IGNORECASE)
V1_VALUES = {"malicious", "suspicious", "benign", "inconclusive"}

# backend modules whose prose literals are user-visible text; log calls, prints and HTTP errors are in scope in EVERY module
IN_SCOPE = (
    "app/auth_check/", "app/content_analysis/", "app/enrichment/__init__.py", "app/enrichment/providers/scoring.py", "app/indicators.py",
    "app/coverage.py", "app/evidence.py", "app/scoring/", "app/llm/", "app/api/", "app/feedback.py", "app/main.py", "app/hops.py",
)
USER_KEYWORDS = {"title", "description", "reason", "effect", "detail", "how_to_clear", "note", "text", "label", "message", "summary", "narrative", "error", "subject"}
LOG_NAMES = {"debug", "info", "warning", "error", "exception", "critical"}

# payload paths (indexes normalised to [*]) that hold message content, not application wording
EXEMPT_PATHS = [re.compile(p) for p in (
    r"^parsed_email(\.|$)",
    r"^module_results(\[\*\]|$)",  # a duplicate of findings[*] plus the raw-data block (a provider's own field names are exempt there only)
    r"^indicators\.indicators\[\*\]\.(value|filename)$",
    r"^indicators\.indicators\[\*\]\.pivots\[\*\]\.url$",
    r"^evidence\.links\[\*\]\.(url|url_defanged|host|registrable_domain|display_text)$",
    r"^evidence\.attachments\[\*\]\.(filename|declared_type|detected_type|extension|sha256)$",
    r"^evidence\.images\[\*\]\.(host|url_defanged|filename)$",
    r"^evidence\.sender\.(from_address|reply_to|return_path)(\.|$)",
    r"^evidence\.hop_timeline\[\*\]\.(from_host|by_host|from_ip|protocol|timestamp)$",
)]
EVIDENCE_VALUE = re.compile(r"^findings\[\*\]\.evidence(\.|$)")


# ------------------------------------------------------------------------------------------------------------------------------ basics

def find_banned(text: str) -> list[str]:
    """The banned whole words in `text`, lower-cased, in order. 'safety', 'unsafe' and 'cleanse' do not match."""
    return [m.group(1).lower() for m in WORD.finditer(text)]


def normalise(text: str) -> str:
    return " ".join(text.split())


def load_allowlist(path: Path = ALLOWLIST) -> frozenset[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return frozenset()
    return frozenset(normalise(s) for s in data.get("allowed_exact_strings", []))


def is_allowed(text: str, allowed: frozenset[str]) -> bool:
    return normalise(text) in allowed


def _has_space(text: str) -> bool:
    return any(c.isspace() for c in text.strip())


def is_prose(text: str) -> bool:
    return _has_space(text) and len(re.findall(r"[A-Za-z]{2,}", text)) >= 2


@dataclass
class StringRef:
    file: str
    line: int
    kind: str
    text: str
    in_scope: bool = True


@dataclass
class Hit:
    source: str  # static | runtime
    where: str
    kind: str
    word: str
    text: str
    proposal: str = ""
    basis: str = ""  # rule | review
    tests: list[str] = field(default_factory=list)
    also_static: bool = False


# ------------------------------------------------------------------------------------------------------------------------------ static: backend

def _call_name(func: ast.AST) -> tuple[str, str]:
    """(last name, text of the receiver) of a call target: logger.warning -> ('warning', 'logger')."""
    if isinstance(func, ast.Attribute):
        return func.attr, ast.unparse(func.value)
    if isinstance(func, ast.Name):
        return func.id, ""
    return "", ""


def py_string_refs(source: str, filename: str, in_scope_file: bool) -> tuple[list[StringRef], list[StringRef]]:
    """(string refs, exempt single-word banned tokens) of one Python source. Docstrings and comments are never strings of the program's output."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []
    parents: dict[ast.AST, ast.AST] = {}
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    refs: list[StringRef] = []
    tokens: list[StringRef] = []
    seen_joined: set[int] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or id(node) in docstrings:
            continue
        value = node.value
        if not value.strip():
            continue
        kind, keyword = "prose literal", None
        child, parent = node, parents.get(node)
        while parent is not None and not isinstance(parent, ast.stmt):
            if isinstance(parent, ast.keyword) and keyword is None and parent.arg in USER_KEYWORDS:
                keyword = parent.arg
            if isinstance(parent, ast.Call):
                name, receiver = _call_name(parent.func)
                if name in LOG_NAMES and "log" in receiver.lower():
                    kind = "log message"
                    break
                if name == "print":
                    kind = "cli output"
                    break
                if name == "HTTPException":
                    kind = "api error"
                    break
            child, parent = parent, parents.get(parent)
        else:
            if isinstance(parent, ast.Raise):
                kind = "exception message"
            elif keyword:
                kind = f"api text ({keyword})"
        if isinstance(parents.get(node), ast.JoinedStr):
            joined = parents[node]
            if id(joined) not in seen_joined:
                seen_joined.add(id(joined))
                exprs = [ast.unparse(v.value) for v in joined.values if isinstance(v, ast.FormattedValue)]
                if any(re.search(r"\b(bucket|verdict|base_bucket|final_bucket)\b", e) for e in exprs):
                    template = "".join(v.value if isinstance(v, ast.Constant) else "{" + ast.unparse(v.value) + "}" for v in joined.values)
                    refs.append(StringRef(filename, joined.lineno, "f-string interpolates a verdict value", template,
                                          in_scope_file or kind in ("log message", "cli output", "api error")))
        always_in_scope = kind in ("log message", "cli output", "api error")
        in_scope = always_in_scope or (in_scope_file and kind != "exception message")
        if is_prose(value):
            refs.append(StringRef(filename, node.lineno, kind, value, in_scope))
        elif WORD.search(value) and not _has_space(value):
            tokens.append(StringRef(filename, node.lineno, "single-word token", value, False))
    return refs, tokens


def static_backend(root: Path = ROOT) -> tuple[list[StringRef], list[StringRef]]:
    app = root / "backend" / "app"
    refs: list[StringRef] = []
    tokens: list[StringRef] = []
    if not app.is_dir():
        return refs, tokens
    for path in sorted(app.rglob("*.py")):
        rel = path.relative_to(root / "backend").as_posix()
        scope = any(rel == s or rel.startswith(s) for s in IN_SCOPE)
        r, t = py_string_refs(path.read_text(encoding="utf-8"), "backend/" + rel, scope)
        refs += r
        tokens += t
    for path in sorted(app.rglob("*.json")):
        refs += json_string_refs(path, "backend/" + path.relative_to(root / "backend").as_posix())
    return refs, tokens


def json_string_refs(path: Path, rel: str) -> list[StringRef]:
    """Prose strings in a backend data file (for example the display name of a shared platform). Domain lists and other single tokens are not wording."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    refs: list[StringRef] = []

    def walk(obj, key: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, str(k))
        elif isinstance(obj, list):
            for v in obj:
                walk(v, key)
        elif isinstance(obj, str) and key != "domains" and is_prose(obj):
            refs.append(StringRef(rel, 1, f"data file ({key})", obj, key in ("name", "label", "title")))

    walk(data, "")
    return refs


# ------------------------------------------------------------------------------------------------------------------------------ static: frontend

def frontend_refs(root: Path = ROOT, src_dir: Path | None = None) -> tuple[list[StringRef], list[StringRef], str]:
    """(refs, exempt tokens, warning). Uses node and the TypeScript compiler API; a missing node is reported, never silently skipped."""
    script = root / "scripts" / "wording_frontend_strings.mjs"
    args = ["node", str(script)] + ([str(src_dir)] if src_dir else [])
    try:
        done = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=str(root))
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return [], [], f"frontend scan skipped: {type(exc).__name__}"
    if done.returncode != 0:
        return [], [], "frontend scan failed: " + done.stderr.strip().splitlines()[-1][:200] if done.stderr.strip() else "frontend scan failed"
    data = json.loads(done.stdout)
    refs = [StringRef(s["file"], s["line"], s["kind"], s["text"], True) for s in data["strings"]]
    tokens = [StringRef(s["file"], s["line"], s["kind"], s["text"], False) for s in data["exempt_tokens"]]
    for css in sorted((src_dir or root / "frontend" / "src").rglob("*.css")):
        for n, line in enumerate(css.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r"content\s*:\s*(['\"])(.+?)\1", line)
            if m and is_prose(m.group(2)):
                refs.append(StringRef(css.relative_to(root).as_posix() if root in css.parents else css.as_posix(), n, "css content", m.group(2), True))
    return refs, tokens, ""


# ------------------------------------------------------------------------------------------------------------------------------ runtime payload

def _norm_path(path: str) -> str:
    return re.sub(r"\[\d+\]", "[*]", path)


def _exempt(npath: str) -> bool:
    return any(p.search(npath) for p in EXEMPT_PATHS)


_QUOTED = re.compile(r"'[^']{1,80}'|`[^`]{1,80}`")


def mask_template(text: str, word: str) -> str:
    """The sentence of `text` that holds the banned word, with quoted parts masked, so a runtime hit shows the template and not message text."""
    for sentence in re.split(r"(?<=[.;])\s+", text):
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(word) + r"(?![A-Za-z0-9_])", sentence, re.IGNORECASE):
            return re.sub(r"\d+(\.\d+)?", "#", _QUOTED.sub("'...'", normalise(sentence)))
    return re.sub(r"\d+(\.\d+)?", "#", _QUOTED.sub("'...'", normalise(text)))[:200]


@dataclass
class PayloadHit:
    path: str
    kind: str
    word: str
    text: str  # a masked template, or '' when withheld


def scan_payload(payload, allowed: frozenset[str] = frozenset()) -> list[PayloadHit]:
    """Scan a JSON-like analysis payload. Values AND field names are checked, except in message-content paths and inside the raw-data block (where a
    provider's own field names, for example VirusTotal's `harmless` count, are exempt). The frozen v1 `verdict` value is exempt."""
    hits: list[PayloadHit] = []

    def walk(obj, path: str) -> None:
        npath = _norm_path(path)
        if _exempt(npath):
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                child = f"{path}.{key}" if path else str(key)
                if isinstance(key, str):
                    for word in find_banned(key):
                        if not _exempt(_norm_path(child)):
                            hits.append(PayloadHit(_norm_path(child), "field name", word, ""))
                walk(value, child)
        elif isinstance(obj, (list, tuple)):
            for i, value in enumerate(obj):
                walk(value, f"{path}[{i}]")
        elif isinstance(obj, str):
            if npath == "verdict" and obj in V1_VALUES:
                return
            if is_allowed(obj, allowed):
                return
            for word in dict.fromkeys(find_banned(obj)):
                if EVIDENCE_VALUE.match(npath):
                    hits.append(PayloadHit(npath, "finding evidence value (withheld)", word, ""))
                else:
                    hits.append(PayloadHit(npath, "api text", word, mask_template(obj, word)))

    walk(payload, "")
    return hits


def scan_prompt(prompt: str, allowed: frozenset[str] = frozenset()) -> list[PayloadHit]:
    """The text sent to the LLM. The v1 verdict value on its first line is the frozen internal literal, not wording."""
    cleaned = re.sub(r"Verdict: (malicious|suspicious|benign|inconclusive)", "Verdict: <v1 value>", prompt)
    hits: list[PayloadHit] = []
    for line in cleaned.splitlines():
        if is_allowed(line, allowed):
            continue
        for word in dict.fromkeys(find_banned(line)):
            hits.append(PayloadHit("llm_prompt", "llm prompt", word, mask_template(line, word)))
    return hits


def runtime_hits(allowed: frozenset[str] = frozenset()) -> list[PayloadHit]:
    """The pipeline over the fixtures and the TUNING corpus (never the hold-out), four ways (STRICT and CONFIGURED, clean and unknown enrichment)."""
    import logging

    backend = ROOT / "backend"
    cwd = os.getcwd()
    os.chdir(backend)
    sys.path.insert(0, str(backend))
    logging.getLogger("app").setLevel(logging.ERROR)
    try:
        from app.coverage import build_coverage_report
        from app.evidence import build_evidence
        from app.indicators import build_indicator_pack, visible_pack
        from app.llm.prompting import build_prompt
        from tests import eval as ev

        seen: set[tuple[str, str, str, str]] = set()
        out: list[PayloadHit] = []
        items = ev.collect(None)
        for mode in ev.MODES:
            ev.apply_mode(mode)
            for enrichment in ("clean", "disabled"):
                for path, _label, _source in items:
                    res = ev.analyze(path, enrichment)
                    pack = build_indicator_pack(res.parsed_email, res.module_results)
                    evidence = build_evidence(res.parsed_email, res.module_results, pack)
                    coverage = build_coverage_report(res.parsed_email, res.module_results, evidence)
                    full = res.model_copy(update={"indicators": visible_pack(pack), "evidence": evidence, "coverage_report": coverage})
                    for hit in scan_payload(full.model_dump(mode="json"), allowed) + scan_prompt(build_prompt(full), allowed):
                        key = (hit.path, hit.kind, hit.word, window_around(hit.text, hit.word, 3) if hit.text else "")
                        if key not in seen:
                            seen.add(key)
                            out.append(hit)
        return out
    finally:
        os.chdir(cwd)
        if sys.path and sys.path[0] == str(backend):
            sys.path.pop(0)


# ------------------------------------------------------------------------------------------------------------------------------ proposals

# (pattern, replacement): specific phrases first, so the meaning survives; anything left falls back to a per-word suggestion marked for review
def _phrase(text: str, ignore_case: bool = False) -> re.Pattern:
    """A whole-phrase pattern built from plain text (nothing in it is a regex escape)."""
    return re.compile("(?<![A-Za-z0-9_])" + re.escape(text) + "(?![A-Za-z0-9_])", re.IGNORECASE if ignore_case else 0)


# (phrase, replacement, ignore case): specific phrases first, so the meaning survives; anything left falls back to a per-word suggestion marked for review
_PHRASES: list[tuple[str, str, bool]] = [
    ("absence of a detection is not evidence that it is clean", "absence of a detection is not evidence that nothing is wrong with it", True),
    ("UNKNOWN, not clean", "UNKNOWN, not a pass", False),
    ("unknown on reputation, not clean", "unknown on reputation, not a pass", True),
    ("trust a benign call", "trust a 'No indicators found' call", True),
    ("Microsoft Safe Links", "Microsoft link wrapper", False),
    ("not the same as clean", "not the same as a pass", True),
    ("'benign'", "'No indicators found'", False),
    ("not clean", "not a pass", True),
    ("checked and clean", "checked and found nothing", True),
    ("it is clean", "it passed", True),
    ("does not make the content safe", "does not show that the content can be trusted", True),
    ("not that the content is safe", "not that the content can be trusted", True),
    ("that the message is safe", "that the message can be trusted", True),
    ("is not a clean single", "is not a plain single", True),
    ("not a clean", "not a plain", True),
    ("Common in benign mail", "Common in ordinary mail", False),
    ("common in benign mail", "common in ordinary mail", False),
    ("benign mail", "ordinary mail", True),
    ("benign senders", "ordinary senders", True),
    ("benign newsletter", "ordinary newsletter", True),
    ("benign verdict", "'No indicators found' verdict", True),
    ("benign", "ordinary", True),
]
_RULES: list[tuple[re.Pattern, str]] = [(_phrase(phrase, ci), repl) for phrase, repl, ci in _PHRASES]
_FALLBACK = {"safe": "trustworthy", "clean": "plain", "legit": "genuine", "benign": "ordinary", "harmless": "not malicious"}


def propose(text: str) -> tuple[str, str]:
    """(proposed text, 'rule' | 'review'). 'review' means no specific phrase rule fired and a per-word suggestion was used."""
    out, basis = text, "rule"
    product_name = bool(_phrase("Safe Links").search(text))
    for pattern, repl in _RULES:
        out = pattern.sub(repl, out)
    if find_banned(out):
        basis = "review"
        out = WORD.sub(lambda m: _FALLBACK[m.group(1).lower()], out)
    if out == text:
        basis = "review"
    if product_name:
        basis = "decision: a product name; either allowlist the exact name 'Microsoft Safe Links' or display 'Microsoft link wrapper'"
    return out, basis


# ------------------------------------------------------------------------------------------------------------------------------ tests that assert a string

_ASSERTION_LIKE = re.compile(r"assert|expect\(|getBy|findBy|queryBy|toContain|toHaveText|toMatch|\bin\b.*(?:text|description|title|reason|note)|==|re\.search|match\(")


def _test_files(root: Path) -> list[Path]:
    files = [p for p in (root / "backend" / "tests").rglob("*.py") if p.name != "test_check_wording.py"] if (root / "backend" / "tests").is_dir() else []
    fe = root / "frontend" / "src"
    if fe.is_dir():
        files += [p for p in fe.rglob("*") if re.search(r"\.test\.(ts|tsx)$", p.name)]
    return sorted(files)


def _squash(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def window_around(text: str, word: str, size: int = 2, after: int | None = None) -> str:
    tokens = re.findall(r"[A-Za-z0-9]+", text)
    after = size if after is None else after
    for i, tok in enumerate(tokens):
        if tok.lower() == word:
            return " ".join(t.lower() for t in tokens[max(0, i - size): i + after + 1])
    return word


def find_tests(root: Path, hits: list[Hit]) -> None:
    index: list[tuple[str, int, str]] = []
    for path in _test_files(root):
        rel = path.relative_to(root).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")) or '"""' in line:
                continue  # comments and docstring lines are not assertions
            if not (_ASSERTION_LIKE.search(line) or re.search(r"[\"'`]", line)):
                continue  # plain prose
            sq = _squash(line)
            if sq:
                index.append((rel, n, sq))
    for hit in hits:
        needles = {window_around(hit.text, hit.word, 2, 2), window_around(hit.text, hit.word, 1, 0), window_around(hit.text, hit.word, 0, 1)}
        needles = {n for n in needles if len(n.split()) >= 2}
        hit.tests = sorted({f"{rel}:{n}" for rel, n, sq in index if any(nd in sq for nd in needles)})[:8]


# ------------------------------------------------------------------------------------------------------------------------------ report

def possible_hits(refs: list[StringRef]) -> list[StringRef]:
    """f-strings that interpolate a verdict value: the v1 literal 'benign' can be rendered at runtime although no banned word is in the source."""
    return [r for r in refs if r.kind == "f-string interpolates a verdict value" and r.in_scope]


def static_hits(refs: list[StringRef], allowed: frozenset[str]) -> list[Hit]:
    hits: list[Hit] = []
    for ref in refs:
        if not ref.in_scope or is_allowed(ref.text, allowed) or ref.kind == "f-string interpolates a verdict value":
            continue
        for word in dict.fromkeys(find_banned(ref.text)):
            proposal, basis = propose(normalise(ref.text))
            hits.append(Hit("static", f"{ref.file}:{ref.line}", ref.kind, word, normalise(ref.text), proposal, basis))
    return hits


def runtime_to_hits(payload_hits: list[PayloadHit], static: list[Hit]) -> list[Hit]:
    static_squashed = [_squash(h.text) for h in static]
    out: list[Hit] = []
    for p in payload_hits:
        hit = Hit("runtime", p.path, p.kind, p.word, p.text)
        if p.text:
            hit.proposal, hit.basis = propose(p.text)
            window = window_around(p.text, p.word, 1, 0)
            hit.also_static = any(window in s for s in static_squashed)
        out.append(hit)
    return out


def print_report(static: list[Hit], runtime: list[Hit], informational: list[StringRef], tokens: list[StringRef], warnings: list[str],
                 possible: list[StringRef] | None = None, out=None) -> None:
    possible = possible or []
    out = out or sys.stdout  # resolved at call time, so a captured or reconfigured stdout is honoured
    p = lambda s="": print(s, file=out)
    p("V1 word-ban lint: REPORT ONLY (nothing is changed, nothing fails)")
    p("Banned as whole words: " + ", ".join(BANNED) + "  ('safety' is not 'safe').")
    for w in warnings:
        p("WARNING: " + w)
    p()
    p(f"== 1. static hits in user-visible strings ({len(static)})")
    for h in sorted(static, key=lambda h: (h.where.rsplit(":", 1)[0], int(h.where.rsplit(":", 1)[1]))):
        p(f"  {h.where} | {h.kind} | {h.word}")
        p(f"      now:      {h.text}")
        p(f"      proposed: {h.proposal}   [{h.basis}]")
        if h.tests:
            p("      may be asserted by (loose match, verify): " + ", ".join(h.tests))
    novel = [h for h in runtime if not h.also_static]
    p()
    p(f"== 1b. f-strings that interpolate a verdict value ({len(possible)}): no banned word in the source, but the v1 literal 'benign' can be rendered at runtime")
    for r in possible:
        p(f"  {r.file}:{r.line}")
        p(f"      template: {normalise(r.text)}")
        p("      proposed: render the verdict through its label map (for example 'No indicators found') instead of the raw literal")
    p()
    p(f"== 2. runtime hits ({len(runtime)} distinct; {len(novel)} not found by the static scan)")
    for h in runtime:
        flag = "also static" if h.also_static else "RUNTIME ONLY"
        p(f"  {h.where} | {h.kind} | {h.word} | {flag}")
        if h.text:
            p(f"      template: {h.text}")
            p(f"      proposed: {h.proposal}   [{h.basis}]")
        else:
            p("      (value withheld: it may contain message text)")
        if h.tests:
            p("      may be asserted by (loose match, verify): " + ", ".join(h.tests))
    p()
    p(f"== 3. informational, NOT in scope (developer-facing text): {len(informational)} string(s) contain a banned word")
    for r in sorted(informational, key=lambda r: (r.file, r.line)):
        p(f"  {r.file}:{r.line} | {r.kind} | {normalise(r.text)[:140]}")
    p()
    by_file: dict[str, int] = {}
    for t in tokens:
        by_file[t.file] = by_file.get(t.file, 0) + 1
    p(f"== 4. exempt single-word tokens (internal keys, the frozen v1 value, type unions): {len(tokens)} in {len(by_file)} file(s); not wording")
    for f, n in sorted(by_file.items()):
        p(f"  {f}: {n}")
    p()
    p(f"summary: {len(static)} static hit(s), {len(possible)} verdict-interpolating f-string(s), {len(novel)} runtime-only hit(s), "
      f"{len(informational)} informational, {len(tokens)} exempt token(s)")


def main(argv: list[str] | None = None, root: Path = ROOT, runtime: bool | None = None) -> int:
    ap = argparse.ArgumentParser(description="V1 word-ban lint, report only")
    ap.add_argument("--static", action="store_true", help="static scan only")
    ap.add_argument("--json", help="also write the hits to this file")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any hit exists")
    ap.add_argument("--no-tests", action="store_true", help="skip the search for tests that assert the strings")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    allowed = load_allowlist()
    warnings: list[str] = []

    be_refs, be_tokens = static_backend(root)
    fe_refs, fe_tokens, warn = frontend_refs(root)
    if warn:
        warnings.append(warn)
    refs, tokens = be_refs + fe_refs, be_tokens + fe_tokens
    static = static_hits(refs, allowed)
    informational = [r for r in refs if not r.in_scope and find_banned(r.text) and not is_allowed(r.text, allowed)]

    do_runtime = (not args.static) if runtime is None else runtime
    rt: list[Hit] = []
    if do_runtime:
        rt = runtime_to_hits(runtime_hits(allowed), static)
    if not args.no_tests:
        find_tests(root, static + rt)
    print_report(static, rt, informational, tokens, warnings, possible_hits(refs))
    if args.json:
        Path(args.json).write_text(json.dumps({"static": [asdict(h) for h in static], "runtime": [asdict(h) for h in rt],
                                               "informational": [asdict(r) for r in informational], "exempt_tokens": [asdict(t) for t in tokens]},
                                              ensure_ascii=False, indent=1), encoding="utf-8")
    return 1 if args.strict and (static or possible_hits(refs) or any(not h.also_static for h in rt)) else 0


if __name__ == "__main__":
    sys.exit(main())
