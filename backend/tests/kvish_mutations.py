"""Mutation analysis on the sanitized Kvish fixture ONLY (never the hold-out): which parts of the message does the verdict
depend on?

    cd backend && python -m tests.kvish_mutations [--ablate-seeds]

Each mutation edits the PARSED message (display name, call-to-action link, hot-linked images, sender identity) and
re-runs the whole pipeline in STRICT and CONFIGURED mode. Nothing here changes a weight or a rule; it reports what the
verdict depends on. The Return-Path, Received chain and body text are left as they were, so a "different sender" mutation
changes the From identity only.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import eval as ev  # noqa: E402

FIXTURE = ev.FIXTURES / "malicious" / "kvish6_invoice_phish.eml"
FLAGGED = ev.FLAGGED

# Edits to the message itself ...
CONTENT_MUTATIONS = ("no_display_name", "direct_cta", "no_hotlinked_images")
# ... and who it appears to come from.
SENDERS = ("as_is", "unrelated_hosting_domain", "freemail")
# ... and how the message entered the mail system: the original local submission on the hosting box, or authenticated SMTP.
ORIGINS = ("local_submission", "authenticated_smtp")


def _freemail_address() -> str:
    return "account.team" + "@" + "gmail" + ".com"  # built at runtime: no real-domain address literal in the source


def mutate(parsed, content: tuple[str, ...], sender: str, origin: str = "local_submission"):
    edits: dict = {}
    if "no_display_name" in content:
        edits["from_"] = parsed.from_.model_copy(update={"display_name": None})
    if "direct_cta" in content:
        # the SendGrid click tracker is replaced by a direct link to an unrelated host
        edits["urls"] = [
            u.model_copy(update={"url": "https://pay.example.net/invoice"}) if (urlsplit(u.url).hostname or "").endswith("sendgrid.net") else u
            for u in parsed.urls
        ]
    if "no_hotlinked_images" in content:
        edits["images"] = []
    if origin == "authenticated_smtp":
        chain = list(parsed.received_chain)  # newest first: the LAST hop is where the message entered
        chain[-1] = chain[-1].model_copy(update={"is_local_submission": False, "authenticated": True, "protocol": "ESMTPSA"})
        edits["received_chain"] = chain
    mutated = parsed.model_copy(update=edits)
    if sender == "unrelated_hosting_domain":
        address, domain = "owner@shop-site.example.net", "shop-site.example.net"
    elif sender == "freemail":
        address = _freemail_address()
        domain = address.split("@")[1]
    else:
        return mutated
    return mutated.model_copy(update={"from_": mutated.from_.model_copy(update={"address": address, "domain": domain})})


def cases() -> list[tuple[str, tuple[str, ...], str, str]]:
    out = []
    for origin in ORIGINS:
        for sender in SENDERS:
            for r in range(len(CONTENT_MUTATIONS) + 1):
                for combo in itertools.combinations(CONTENT_MUTATIONS, r):
                    out.append(("+".join(combo) or "unmodified", combo, sender, origin))
    return out


def run_case(parsed, content, sender, mode: str, origin: str = "local_submission"):
    ev.apply_mode(mode)
    result = ev.analyze_parsed(mutate(parsed, content, sender, origin), "clean")
    signals = sorted({f.evidence["signal"] for f in result.findings if f.evidence.get("structural") and f.evidence.get("signal")})
    families = sorted({f.evidence["family"] for f in result.findings if f.evidence.get("structural") and f.evidence.get("family")})
    return result.verdict, signals, families


def table(parsed) -> list[dict]:
    rows = []
    for label, combo, sender, origin in cases():
        row = {"mutation": label, "sender": sender, "origin": origin}
        for mode in ev.MODES:
            verdict, signals, families = run_case(parsed, combo, sender, mode, origin)
            row[mode] = {"verdict": verdict, "signals": signals, "families": families}
        rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if "--ablate-seeds" in argv:
        ev._ablate_seeds()
    from app.parser import parse_email_file

    parsed = parse_email_file(FIXTURE.read_bytes(), FIXTURE.name)
    rows = table(parsed)
    print(f"Kvish mutation table (ablate_seeds={'--ablate-seeds' in argv}); verdict in STRICT / CONFIGURED; '>=S' = suspicious or malicious")
    print(f"{'origin':20} {'sender':26} {'content mutation':48} {'STRICT':12} {'CONFIGURED':12} signals (STRICT)")
    for r in rows:
        print(f"{r['origin']:20} {r['sender']:26} {r['mutation']:48} {r['strict']['verdict']:12} {r['configured']['verdict']:12} {','.join(r['strict']['signals']) or '-'}")
    flagged = sum(r["strict"]["verdict"] in FLAGGED for r in rows)
    flagged_c = sum(r["configured"]["verdict"] in FLAGGED for r in rows)
    print(f"\nreach >= suspicious: STRICT {flagged}/{len(rows)}, CONFIGURED {flagged_c}/{len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
