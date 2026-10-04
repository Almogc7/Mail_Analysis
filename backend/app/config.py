import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Provider API keys for the lookup sources (app/enrichment/providers). A source without a key reports "disabled" and its
# indicators are shown as UNKNOWN, never clean.
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Per-email enrichment caps (Module 3) -- bound worst-case runtime/API usage.
MAX_URLS_TO_ENRICH = int(os.getenv("MAX_URLS_TO_ENRICH", "10"))
MAX_HASHES_TO_ENRICH = int(os.getenv("MAX_HASHES_TO_ENRICH", "10"))

# Module 6 (LLM second opinion) is OFF unless LLM_ENABLED is set to 1/true/yes/on. While off, nothing is sent to
# any external model. When on, only the verdict, numbers and finding titles are sent, with addresses,
# hostnames, URLs, file names, IPs and internal-looking names replaced by placeholders (app/llm/prompting.py).
LLM_ENABLED = os.getenv("LLM_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}

# Module 6 (Gemini second opinion) -- get_chat_client() exposes no timeout of its own.
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "25"))

# Gateway banner / subject-tag stripping (see app/parser/preprocess.py). JSON arrays of
# regexes, read from the environment so tenant-specific wording lives ONLY in the untracked
# backend/.env, e.g.  GATEWAY_BANNER_PATTERNS='["external sender warning text"]'
def _json_pattern_list(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be a JSON array of regex strings: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{name} must be a JSON array of regex strings")
    return value


GATEWAY_BANNER_PATTERNS = _json_pattern_list("GATEWAY_BANNER_PATTERNS")
GATEWAY_SUBJECT_TAG_PATTERNS = _json_pattern_list("GATEWAY_SUBJECT_TAG_PATTERNS")

# Hostname regexes of receivers whose Received-SPF / Authentication-Results you trust (see
# app/auth_check/spf_dkim_dmarc.py). Empty by default: with none configured, SPF/DKIM/DMARC are
# "not_evaluated". Tenant-specific hostnames live ONLY in the untracked backend/.env.
TRUSTED_RECEIVER_PATTERNS = _json_pattern_list("TRUSTED_RECEIVER_PATTERNS")

# Known-sender list: registrable domains whose mail you positively recognise (your suppliers, your own domains). A
# 'benign' verdict needs a sender on this list in addition to verified authentication (app/scoring/overrides.py): an
# authenticated message only proves WHO sent it, not that the sender is legitimate -- attackers authenticate their own
# domains. Read from an UNTRACKED JSON file (default backend/known_senders.local.json, override with
# KNOWN_SENDERS_FILE): {"domains": ["example.com", ...]}. EMPTY BY DEFAULT: with no list, nothing can be benign.
def _load_known_sender_domains() -> frozenset[str]:
    file = Path(os.getenv("KNOWN_SENDERS_FILE") or Path(__file__).resolve().parents[1] / "known_senders.local.json")
    if not file.exists():
        return frozenset()
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{file.name} must be JSON: {exc}") from exc
    domains = data.get("domains") if isinstance(data, dict) else None
    if not isinstance(domains, list) or not all(isinstance(d, str) and d.strip() for d in domains):
        raise ValueError(f'{file.name} must be {{"domains": ["example.com", ...]}}')
    return frozenset(d.strip().strip(".").lower() for d in domains)


KNOWN_SENDER_DOMAINS = _load_known_sender_domains()

# Enrichment privacy policy (see app/enrichment/policy.py). By default only HOSTNAMES leave this machine: the
# path and query of a URL (where per-recipient tracking tokens live) are never sent unless a provider is
# named in ENRICHMENT_PATH_QUERY_PROVIDERS (opt-in, default none). Providers named in
# ENRICHMENT_DISABLED_PROVIDERS are never called; their indicators are reported UNKNOWN, never clean.
# Valid names: virustotal, urlscan, threatfox, malwarebazaar. ENRICHMENT_GRANULARITY: hostname | registrable.
ENRICHMENT_DISABLED_PROVIDERS = _json_pattern_list("ENRICHMENT_DISABLED_PROVIDERS")
ENRICHMENT_PATH_QUERY_PROVIDERS = _json_pattern_list("ENRICHMENT_PATH_QUERY_PROVIDERS")
ENRICHMENT_GRANULARITY = os.getenv("ENRICHMENT_GRANULARITY", "hostname")

# Local analyst feedback log (app/feedback.py): SQLite, gitignored, hashes/verdicts/signal names only.
FEEDBACK_DB = Path(os.getenv("FEEDBACK_DB", str(Path(__file__).resolve().parents[1] / "feedback.local.sqlite")))

# /analyze route upload limit.
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(25 * 1024 * 1024)))

# How long a FINISHED analysis (and the message body text inside it) stays in memory, in seconds. 0 = never expire. The store is memory-only:
# nothing is written to disk and a restart clears it.
JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "1800"))
