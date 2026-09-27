"""Bridge into the sibling IOC_Enricher repo's provider clients and scorer.

IOC_Enricher has no pyproject.toml — it's a set of flat modules at its repo root that
import each other with bare names (`from ioc_analysis import IOCAnalyzer`, etc.), relying
on being on sys.path. We insert its repo root once here, matching the pattern IOC_Enricher's
own CI already uses (PYTHONPATH=<repo_root>), rather than modifying that repo.

Module 3 (URL/attachment-hash enrichment) is a later milestone — this stub only wires up
the import path so it's ready to build against.
"""

import sys

from app.config import IOC_ENRICHER_PATH

_bridged = False


def ensure_ioc_enricher_on_path() -> None:
    global _bridged
    if _bridged:
        return
    path_str = str(IOC_ENRICHER_PATH)
    if not IOC_ENRICHER_PATH.exists():
        raise FileNotFoundError(
            f"IOC_ENRICHER_PATH does not exist: {IOC_ENRICHER_PATH}. "
            "Set IOC_ENRICHER_PATH in backend/.env to the IOC_Enricher repo root."
        )
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    _bridged = True
