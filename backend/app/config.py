import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Path to the sibling IOC_Enricher repo, inserted into sys.path by enrichment/ioc_bridge.py.
IOC_ENRICHER_PATH = Path(os.getenv("IOC_ENRICHER_PATH", "../IOC_Enricher")).resolve()

# Mail_Analysis's own copies of provider API keys — deliberately separate from
# IOC_Enricher's .env so this app never depends on that repo's env being loaded.
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
