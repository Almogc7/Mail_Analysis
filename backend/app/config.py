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
