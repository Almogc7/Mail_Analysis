"""Error analysis over the TUNING split: what evidence exists in the samples the pipeline misses?

    cd backend && python -m tests.error_analysis [--ablate-seeds] [--trusted-receivers fixtures|none]

AGGREGATES ONLY. The output is counts and percentages per evidence bucket: never a subject, address, URL,
host, file name, or any content. Only the tuning split is read (a path containing 'holdout' is refused).
Static analysis only: the parser's existing extraction is used; attachments are classified by file
extension / declared type and are never unpacked, opened, rendered or executed.

A "miss" is a sample whose verdict is not malicious/suspicious (strict: needs_review counts as a miss).
Each bucket is multi-label (a sample can sit in several), so percentages do not add up to 100. The final
"profile" table is mutually exclusive. Counts are shown for the misses and for all samples, so a bucket's
share among misses can be compared with its share overall.

Use it to decide which detections have the most coverage, and to spot buckets the current architecture
cannot address at all (see the "NOT ADDRESSABLE" notes).
"""
from __future__ import annotations

import argparse
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FLAGGED = {"malicious", "suspicious"}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
    "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "mail.ru", "yandex.ru", "yandex.com", "gmx.com",
    "gmx.de", "gmx.net", "web.de", "qq.com", "163.com", "126.com", "zoho.com", "mail.com", "inbox.com", "rediffmail.com",
}
ENGLISH_STOPWORDS = {"the", "and", "to", "of", "a", "in", "is", "you", "that", "for", "it", "with", "this", "your", "are", "be", "on", "as", "have", "we"}
EXT_FAMILIES = {
    "office document": {"doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "odt", "ods", "one"},
    "pdf": {"pdf"},
    "archive / disk image": {"zip", "rar", "7z", "gz", "tar", "iso", "img", "cab", "ace", "arj"},
    "html / svg": {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"},
    "executable / script": {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "jar", "lnk", "msi", "dll", "hta", "wsf", "com", "pif"},
    "image": {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico"},
    "calendar": {"ics", "vcs"},
    "mail message": {"eml", "msg"},
    "text / data": {"txt", "csv", "xml", "json", "log"},
}
CRED_WORDS = ("login", "signin", "sign-in", "verify", "account", "secure", "password", "webmail", "update", "confirm", "owa", "auth")
REDIRECT_WORDS = ("redirect", "click", "track", "/url?", "goto", "away.php", "link.php", "/r/", "out.php", "jump")
TEXT_CRED_WORDS = ("password", "passcode", "sign in", "log in", "login", "verify your", "confirm your", "credentials", "סיסמה", "התחבר", "אימות")


# Candidate detection groups: which misses carry the evidence each would need. Membership means "the evidence
# exists", not "the detector would fire" -- it bounds the possible coverage, it does not promise it.
CANDIDATE_GROUPS: dict[str, tuple[str, ...]] = {
    "A. repair From/Reply-To parsing (unlocks every sender signal)": ("sender: no usable From address",),
    "B. trusted-gateway auth results (config; SPF/DKIM/DMARC failures)": ("auth: a header claims an SPF/DKIM/DMARC failure",),
    "C. URL structure anomalies": (
        "url kind: shortener", "url kind: redirector-looking path or URL in query", "url kind: IP-literal host",
        "url kind: many subdomain levels", "url kind: punycode host", "url kind: link text shows a different address",
        "url kind: credential-style word in host or path", "url kind: known-brand token in the host (not the brand's domain)",
        "url kind: known-brand token in the path", "url kind: legitimate cloud / hosting platform",
    ),
    "D. claimed-entity inference (one dominant unrelated non-platform domain)": ("url: one dominant non-platform domain, unrelated to the sender",),
    "E. sender infrastructure (freemail / server-style / auto-generated / local submission / display-name tricks)": (
        "sender: freemail provider", "sender: server-style hostname as the From domain", "sender: auto-generated-looking mailbox name",
        "sender: a hop is a local submission (not authenticated SMTP)", "sender: display name contains an address",
        "sender: display name carries a known brand",
    ),
    "F. form / credential-harvest markers": (
        "form: <form> in the HTML body", "form: password input", "form: posts to an external URL", "html: <script> present",
        "html: <iframe> present", "html: meta refresh", "html: javascript: link", "text: credential / sign-in wording (en/he lexicon)",
    ),
    "G. attachment-type risk (extension/type only)": ("attachment: any attachment present",),
    "H. weak identity mismatches (Reply-To / Return-Path)": ("sender: Reply-To on a different domain", "sender: Return-Path on a different domain"),
}
_STRUCTURAL_GROUPS = [g for g in CANDIDATE_GROUPS if g[0] in "ABCDEFG"]


def _family(filename: str | None, content_type: str | None) -> str:
    ext = (filename or "").rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
    for family, exts in EXT_FAMILIES.items():
        if ext in exts:
            return family
    ct = (content_type or "").lower()
    if ct.startswith("image/"):
        return "image"
    if "pdf" in ct:
        return "pdf"
    if "html" in ct:
        return "html / svg"
    if "calendar" in ct:
        return "calendar"
    return "other / unknown"


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    cp = ord(ch)
    if cp < 0x250:
        return "latin"
    if 0x0590 <= cp <= 0x05FF:
        return "hebrew"
    if 0x0600 <= cp <= 0x06FF:
        return "arabic"
    if 0x0400 <= cp <= 0x04FF:
        return "cyrillic"
    if 0x4E00 <= cp <= 0x9FFF or 0x3040 <= cp <= 0x30FF or 0xAC00 <= cp <= 0xD7AF:
        return "cjk"
    return "other script"


def features(parsed, result) -> tuple[set[str], str]:
    """(multi-label features as 'group: name' strings, one exclusive profile). Pure static analysis of
    what the parser already extracted; nothing here is ever printed with its value."""
    from bs4 import BeautifulSoup

    from app.auth_check.spoofing import looks_autogenerated_local_part, looks_like_machine_label
    from app.enrichment.policy import classify_host, host_of, platform_of
    from app.parser.preprocess import clean_body_text
    from app.shared.brands import KNOWN_BRANDS
    from app.shared.matching import find_brand_matches, registrable_domain

    f: set[str] = set()
    text, _ = clean_body_text(parsed.body_text, parsed.body_html)
    visible = " ".join(text.split())
    sender_reg = registrable_domain(parsed.from_.domain) if parsed.from_.domain else None

    # --- attachments ---------------------------------------------------------------------------
    non_inline = [a for a in parsed.attachments if not a.is_inline]
    has_att = bool(parsed.attachments)
    if has_att:
        f.add("attachment: any attachment present")
        for fam in {_family(a.filename, a.content_type) for a in parsed.attachments}:
            f.add(f"attachment type: {fam}")
        if len(parsed.attachments) > 1:
            f.add("attachment: more than one")
        if any(a.filename and a.filename.count(".") >= 2 for a in parsed.attachments):
            f.add("attachment: double extension in the file name")

    # --- URLs ----------------------------------------------------------------------------------
    urls = [u for u in parsed.urls if host_of(u.url)]
    has_url = bool(urls)
    if has_url:
        f.add("url: any URL present")
        hosts = {host_of(u.url) for u in urls}
        kinds = set()
        for u in urls:
            host = host_of(u.url) or ""
            parts = urlsplit(u.url)
            low = f"{parts.path}?{parts.query}".lower()
            platform = platform_of(host)
            if platform and platform.kind == "shortener":
                kinds.add("shortener")
            if platform and platform.kind in ("esp_tracker", "link_wrapper"):
                kinds.add("tracker / link wrapper (known platform)")
            if platform and platform.kind in ("cloud_content", "site_builder"):
                kinds.add("legitimate cloud / hosting platform")
            if any(w in low for w in REDIRECT_WORDS) or "http" in parts.query.lower():
                kinds.add("redirector-looking path or URL in query")
            if classify_host(host) in ("ip", "internal") and host.replace(".", "").replace(":", "").isalnum() and host[:1].isdigit():
                kinds.add("IP-literal host")
            if host.count(".") >= 4:
                kinds.add("many subdomain levels")
            if any(label.startswith("xn--") for label in host.split(".")):
                kinds.add("punycode host")
            if u.is_anchor_mismatch:
                kinds.add("link text shows a different address")
            if any(m.kind in ("exact", "fuzzy") for m in find_brand_matches(host.replace("-", " "), KNOWN_BRANDS)) \
                    and registrable_domain(host) not in {registrable_domain(d) for ds in KNOWN_BRANDS.values() for d in ds}:
                kinds.add("known-brand token in the host (not the brand's domain)")
            if find_brand_matches(parts.path.replace("-", " ").replace("/", " "), KNOWN_BRANDS):
                kinds.add("known-brand token in the path")
            if any(w in host or w in parts.path.lower() for w in CRED_WORDS):
                kinds.add("credential-style word in host or path")
            if parts.scheme == "http":
                kinds.add("plain http (no TLS)")
        for k in kinds:
            f.add(f"url kind: {k}")
        regs = {registrable_domain(h) for h in hosts if h}
        if sender_reg and regs and sender_reg not in regs:
            f.add("url: no link points at the sender's own domain")
        non_platform_regs = {registrable_domain(h) for h in hosts if h and not platform_of(h)}
        if len(non_platform_regs) == 1 and sender_reg not in non_platform_regs:
            f.add("url: one dominant non-platform domain, unrelated to the sender")
        if len(non_platform_regs) > 4:
            f.add("url: many distinct domains (5+)")
        if len(urls) == 1:
            f.add("url: exactly one URL")

    # --- form / credential-harvest markers (HTML body only; attachments are not inspected) -----
    if parsed.body_html:
        soup = BeautifulSoup(parsed.body_html, "html.parser")
        if soup.find("form"):
            f.add("form: <form> in the HTML body")
        if soup.find("input", attrs={"type": lambda v: v and v.lower() == "password"}):
            f.add("form: password input")
        if any((fm.get("action") or "").lower().startswith(("http://", "https://")) for fm in soup.find_all("form")):
            f.add("form: posts to an external URL")
        if soup.find("script"):
            f.add("html: <script> present")
        if soup.find("iframe"):
            f.add("html: <iframe> present")
        if soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"}):
            f.add("html: meta refresh")
        if any((a.get("href") or "").lower().startswith("javascript:") for a in soup.find_all("a")):
            f.add("html: javascript: link")
    lowered = visible.lower()
    if any(w in lowered for w in TEXT_CRED_WORDS):
        f.add("text: credential / sign-in wording (en/he lexicon)")

    # --- body shape --------------------------------------------------------------------------
    has_html = bool(parsed.body_html)
    image_atts = [a for a in parsed.attachments if _family(a.filename, a.content_type) == "image"]
    if len(visible) < 40 and (parsed.images or image_atts):
        f.add("body: image-only (almost no visible text)")
    if not visible and not parsed.images and not has_att:
        f.add("body: empty")
    if not has_html and not has_url and not has_att:
        f.add("body: plain text only, no URL, no attachment")
    if has_html and not parsed.body_text:
        f.add("body: HTML only (no text alternative)")

    # --- language / script -------------------------------------------------------------------
    # Link text (<https://...>) is Latin script whatever the language; leave it out of language detection.
    lang_text = " ".join(w for w in visible.split() if "://" not in w)
    scripts = Counter(s for s in (_script_of(c) for c in lang_text) if s)
    total = sum(scripts.values())
    if total >= 20:
        non_latin = {k: v for k, v in scripts.items() if k != "latin"}
        if sum(non_latin.values()) / total >= 0.3:
            f.add(f"language: non-Latin script ({max(non_latin, key=non_latin.get)})")
        else:
            words = [w.strip(".,!?;:()\"'").lower() for w in lang_text.split()]
            if len(words) >= 30 and sum(1 for w in words if w in ENGLISH_STOPWORDS) / len(words) < 0.06:
                f.add("language: Latin script but probably not English")
    elif total:
        f.add("language: too little text to tell")

    # --- sender --------------------------------------------------------------------------------
    sender_dom = (parsed.from_.domain or "").lower()
    if sender_dom in FREEMAIL:
        f.add("sender: freemail provider")
    local = (parsed.from_.address or "").rsplit("@", 1)[0]
    if sender_reg and sender_dom != sender_reg and looks_like_machine_label(sender_dom[: -len(sender_reg)].rstrip(".").split(".")[0]):
        f.add("sender: server-style hostname as the From domain")
    if local and looks_autogenerated_local_part(local):
        f.add("sender: auto-generated-looking mailbox name")
    if any(h.is_local_submission for h in parsed.received_chain):
        f.add("sender: a hop is a local submission (not authenticated SMTP)")
    if parsed.from_.display_name and "@" in parsed.from_.display_name:
        f.add("sender: display name contains an address")
    if parsed.from_.display_name and find_brand_matches(parsed.from_.display_name, KNOWN_BRANDS):
        f.add("sender: display name carries a known brand")
    if parsed.reply_to and parsed.reply_to[0].domain and registrable_domain(parsed.reply_to[0].domain) != sender_reg:
        f.add("sender: Reply-To on a different domain")
    if parsed.return_path and parsed.return_path.domain and registrable_domain(parsed.return_path.domain) != sender_reg:
        f.add("sender: Return-Path on a different domain")
    if not parsed.from_.domain:
        f.add("sender: no usable From address")
    to_domains = {t.domain for t in parsed.to if t.domain}
    if sender_dom and to_domains == {sender_dom}:
        f.add("sender: From domain equals every recipient domain")

    # --- auth headers ----------------------------------------------------------------------------
    auth = next((m for m in result.module_results if m.module == "auth_check"), None)
    claims = ((auth.raw_data or {}).get("auth_headers", {}).get("claims", [])) if auth else []
    f.add("auth: Authentication-Results present" if parsed.authentication_results_raw else "auth: no Authentication-Results header")
    f.add("auth: Received-SPF present" if parsed.received_spf else "auth: no Received-SPF header")
    if any(c.get("result") in ("fail", "softfail", "permerror") for c in claims):
        f.add("auth: a header claims an SPF/DKIM/DMARC failure")
    if any(c.get("result") == "pass" for c in claims):
        f.add("auth: a header claims a pass")

    # --- parser health -------------------------------------------------------------------------
    if parsed.parse_warnings:
        f.add("parser: parse warnings present")
    if not parsed.received_chain:
        f.add("parser: no Received headers")

    # --- exclusive profile ---------------------------------------------------------------------
    if has_att and not has_url:
        profile = "attachment, no URL"
    elif has_att and has_url:
        profile = "URL and attachment"
    elif has_url:
        profile = "URL(s), no attachment"
    elif "body: image-only (almost no visible text)" in f or "body: empty" in f:
        profile = "no URL/attachment: image-only or empty body"
    else:
        profile = "no URL, no attachment: text only"
    return f, profile


def analyze_sample(path: Path):
    from app.parser import parse_email_file
    from tests.eval import analyze

    result = analyze(path, "clean")
    parsed = parse_email_file(path.read_bytes(), path.name)
    return result, parsed


def report(rows: list[tuple[str, set[str], str, list[str]]], out) -> None:
    """rows: (verdict, features, profile, signal names). Prints aggregates only."""
    n = len(rows)
    misses = [r for r in rows if r[0] not in FLAGGED]
    hits = n - len(misses)
    print(f"samples: {n}   flagged (strict): {hits}   misses: {len(misses)}   verdicts: "
          f"{dict(Counter(r[0] for r in rows))}", file=out)
    if not misses:
        print("no misses to analyze", file=out)
        return
    miss_counts = Counter(feat for r in misses for feat in r[1])
    all_counts = Counter(feat for r in rows for feat in r[1])

    def table(title: str, prefix_filter) -> None:
        keys = sorted((k for k in all_counts if prefix_filter(k)), key=lambda k: (-miss_counts[k], k))
        if not keys:
            return
        print(f"\n{title}", file=out)
        print(f"  {'bucket':72} {'misses':>12} {'all':>10}", file=out)
        for k in keys:
            m = miss_counts[k]
            print(f"  {k:72} {m:>4} ({100 * m // len(misses):>3}%) {all_counts[k]:>4}/{n}", file=out)

    groups = [
        ("ATTACHMENTS", lambda k: k.startswith("attachment")),
        ("URLS", lambda k: k.startswith("url")),
        ("FORM / CREDENTIAL-HARVEST MARKERS", lambda k: k.startswith(("form", "html", "text: cred"))),
        ("BODY SHAPE", lambda k: k.startswith("body")),
        ("LANGUAGE", lambda k: k.startswith("language")),
        ("SENDER", lambda k: k.startswith("sender")),
        ("AUTH HEADERS", lambda k: k.startswith("auth")),
        ("PARSER HEALTH", lambda k: k.startswith("parser")),
    ]
    for title, flt in groups:
        table(title, flt)

    print("\nPROFILE (mutually exclusive) -- what a miss primarily offers a detector", file=out)
    prof_miss = Counter(r[2] for r in misses)
    prof_all = Counter(r[2] for r in rows)
    for k, v in sorted(prof_miss.items(), key=lambda kv: -kv[1]):
        print(f"  {k:72} {v:>4} ({100 * v // len(misses):>3}%) {prof_all[k]:>4}/{n}", file=out)

    print("\nCANDIDATE SIGNAL GROUPS: misses that carry the evidence each would need (an upper bound on its coverage)", file=out)
    for name, feats in CANDIDATE_GROUPS.items():
        c = sum(1 for r in misses if any(f in r[1] for f in feats))
        print(f"  {name:100} {c:>3} ({100 * c // len(misses):>3}%)", file=out)
    residual = [r for r in misses if not any(any(f in r[1] for f in CANDIDATE_GROUPS[g]) for g in _STRUCTURAL_GROUPS)]
    reached = len(misses) - len(residual)
    print(f"  {'union of A-G (any structural evidence at all)':100} {reached:>3} ({100 * reached // len(misses):>3}%)", file=out)
    print(f"  {'RESIDUAL: no evidence in A-G -- needs content understanding or external data':100} {len(residual):>3} ({100 * len(residual) // len(misses):>3}%)", file=out)

    print("\nEXISTING SIGNALS that fired at all on misses (signal names only)", file=out)
    fired = Counter(s for r in misses for s in set(r[3]))
    for s, c in fired.most_common(8):
        print(f"  {c:>4}  {s}", file=out)
    none_fired = sum(1 for r in misses if not r[3])
    print(f"  {none_fired:>4}  misses with NO non-info finding at all", file=out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ablate-seeds", action="store_true")
    ap.add_argument("--trusted-receivers", choices=("fixtures", "none"), default="fixtures")
    ap.add_argument("--corpus-dir", type=Path, help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    corpus = args.corpus_dir or FIXTURES / "_local_corpus"
    tuning = corpus / "tuning"
    if "holdout" in str(tuning).lower():
        print("error_analysis: refusing to read a hold-out path", file=sys.stderr)
        return 2
    files = sorted(tuning.glob("*.eml"))
    if not files:
        print("error_analysis: no tuning corpus found (run scripts/select_corpus.py)", file=sys.stderr)
        return 1

    import app.config as app_config
    from tests.eval import FIXTURE_TRUSTED_RECEIVERS, _ablate_seeds
    from app.feedback import signal_names

    app_config.TRUSTED_RECEIVER_PATTERNS = list(FIXTURE_TRUSTED_RECEIVERS) if args.trusted_receivers == "fixtures" else []
    if args.ablate_seeds:
        _ablate_seeds()

    rows = []
    for path in files:
        result, parsed = analyze_sample(path)
        feats, profile = features(parsed, result)
        rows.append((result.verdict, feats, profile, signal_names(result)))
    print(f"error analysis -- TUNING split only, aggregates only (ablate_seeds={args.ablate_seeds}, "
          f"trusted_receivers={args.trusted_receivers})")
    report(rows, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
