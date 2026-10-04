"""Suggest TRUSTED_RECEIVER_PATTERNS from mail you already have. Works fully offline: it only reads the headers of the files you name.

    python scripts/suggest_trusted_receivers.py reported_mail.eml [more.eml ...]

For every host that wrote an Authentication-Results / Received-SPF header it prints whether that host is also a hop in the
Received chain (the app only trusts a header whose host is BOTH named in the header AND a hop of the message) and a ready-made,
anchored pattern. Then YOU choose: trust only the gateway that belongs to your organisation, the first inbound hop inside it.

It prints host names only, never subjects, addresses or content. It does not edit any file.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.auth_check.spf_dkim_dmarc import UNKNOWN_AUTHSERV, evaluate_authentication  # noqa: E402
from app.parser import parse_email_file  # noqa: E402


def anchored(host: str) -> str:
    return "^" + re.escape(host) + "$"


def analyse(path: Path) -> list[dict]:
    parsed = parse_email_file(path.read_bytes(), path.name)
    auth = evaluate_authentication(parsed.authentication_results_raw, parsed.received_spf, parsed.received_chain, [], headers=parsed.headers)
    hop_hosts = [(h.by_host or "").strip(".").lower() for h in parsed.received_chain]  # newest first
    seen: dict[str, dict] = {}
    for claim in auth["claims"]:
        host = (claim.get("host") or "").strip(".").lower()
        entry = seen.setdefault(host or "(no host)", {"host": host, "methods": set(), "source": set()})
        entry["methods"].add(f"{claim['method']}={claim['result']}")
        entry["source"].add(claim["source"])
    rows = []
    for host, entry in seen.items():
        hop_positions = [i for i, h in enumerate(hop_hosts) if h and host and (h == host or h.split(".")[0] == host.split(".")[0] and h.endswith(host.split(".", 1)[-1]))]
        rows.append({
            "host": host,
            "eligible": bool(hop_positions) and host != UNKNOWN_AUTHSERV,
            "hop_number_from_you": (min(hop_positions) + 1) if hop_positions else None,
            "hops_total": len(hop_hosts),
            "no_authserv": host in ("", UNKNOWN_AUTHSERV, "(no host)"),
            "methods": sorted(entry["methods"]),
        })
    return sorted(rows, key=lambda r: (r["hop_number_from_you"] is None, r["hop_number_from_you"] or 0))


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    paths = [Path(a) for a in argv if not a.startswith("-")]
    if not paths:
        print(__doc__)
        return 2
    candidates: dict[str, int] = {}
    for path in paths:
        print(f"== {path.name}")
        rows = analyse(path)
        if not rows:
            print("   no Authentication-Results or Received-SPF header found in this file")
        for r in rows:
            if r["no_authserv"]:
                print(f"   header with NO host name (e.g. some Microsoft headers): {', '.join(r['methods'])}")
                print("      cannot be tied to a hop; trusted only if you add the placeholder pattern ^unknown-authserv$ on purpose")
                continue
            where = f"hop {r['hop_number_from_you']} of {r['hops_total']} counting from the receiving end" if r["eligible"] else "NOT a hop of this message"
            print(f"   {r['host']}  [{where}]  {', '.join(r['methods'])}")
            if r["eligible"]:
                candidates[r["host"]] = candidates.get(r["host"], 0) + 1
    if not candidates:
        print("\nNo host qualifies (a header's host must also be a Received hop). Nothing to suggest.")
        return 1
    print("\nHosts that qualify (named in a header AND a hop of the message):")
    for host, n in sorted(candidates.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"   {host}   (in {n} of {len(paths)} file(s))   pattern {anchored(host)}")
    print("\nTrust ONLY the gateway that is yours. Then put one line like this in backend/.env (JSON; this is already escaped):")
    print("   TRUSTED_RECEIVER_PATTERNS=" + json.dumps([anchored(h) for h in sorted(candidates)]))
    print("\nOnly do this if that gateway removes or overwrites any authentication headers arriving from outside; otherwise a sender can")
    print("forge a header that names it. Never trust a host that is the sender's own server.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
