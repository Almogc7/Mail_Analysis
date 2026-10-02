import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Path to the sibling IOC_Enricher repo, inserted into sys.path by enrichment/ioc_bridge.py.
# Default assumes the standard layout: <projects>/Mail_Analysis/backend/app/config.py and
# <projects>/IOC_Enricher as siblings. Resolved from this file's location (not cwd) so it
# works the same whether the app is launched from backend/ or the repo root.
_DEFAULT_IOC_ENRICHER_PATH = Path(__file__).resolve().parents[3] / "IOC_Enricher"
IOC_ENRICHER_PATH = Path(os.getenv("IOC_ENRICHER_PATH", str(_DEFAULT_IOC_ENRICHER_PATH))).resolve()

# Mail_Analysis's own copies of provider API keys — deliberately separate from
# IOC_Enricher's .env so this app never depends on that repo's env being loaded.
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
