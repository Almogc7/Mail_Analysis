"""Build git-filter-repo --replace-text rules from the untracked .denylist.local plus every RFC1918 literal found in the
guard-scoped files of the history. Write the rules file OUTSIDE the repository (it holds the strings to redact).
Prints counts only, never a matched string. See docs/HISTORY_CLEANUP_PLAN.md.

    python scripts/history_cleanup_rules.py <path-outside-repo/rules.txt>
"""
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1])
sys.path.insert(0, str(SRC / "scripts"))
import check_fixtures as cf  # noqa: E402


def git(*a):
    return subprocess.run(["git", *a], cwd=SRC, capture_output=True, check=True).stdout


rules: list[str] = []
patterns = cf._load_lines(cf.DENYLIST)
for i, pat in enumerate(patterns, 1):
    re.compile(pat)  # must be valid
    assert "==>" not in pat
    rules.append(f"regex:(?i){pat}==>REDACTED-{i}")

# every RFC1918 literal that appears anywhere in history (files scanned the way the guard scans them)
rfc = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ips: set[str] = set()
for c in git("rev-list", "--all").decode().split():
    for n in git("diff-tree", "--no-commit-id", "-r", "--name-only", "--diff-filter=AMR", "-z", "--root", c).decode().split("\0"):
        if not n or not n.startswith(cf.SCAN_DIRS) or Path(n).suffix in cf.SKIP_SUFFIXES or any(p in cf.SKIP_PARTS for p in Path(n).parts):
            continue
        data = git("show", f"{c}:{n}")
        for view in cf._texts_for(n, data):
            for m in cf._IPV4.finditer(view):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if any(ip in net for net in rfc):
                    ips.add(str(ip))
for k, ip in enumerate(sorted(ips)):
    esc = ip.replace(".", r"\.")
    rules.append(rf"regex:(?<![\d.]){esc}(?![\d.])==>192.0.2.{10 + k}")

OUT.write_text("\n".join(rules) + "\n", encoding="utf-8")
print(f"rules written: {len(rules)} (denylist patterns {len(patterns)}, distinct RFC1918 literals {len(ips)})")
