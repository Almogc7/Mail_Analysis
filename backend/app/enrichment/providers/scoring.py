"""Turns provider answers into a 0-100 risk number with its components (the explanation shown to the analyst).

Originated in the author's IOC_Enricher project; maintained here independently. Only the providers Mail_Analysis queries contribute
(VirusTotal, ThreatFox, MalwareBazaar, urlscan.io). The AbuseIPDB, OTX and domain-age (RDAP) weights below, and the matching
"unknown" entries in source_statuses, are kept ONLY so the payload and the environment variable names stay exactly as before; no code
path here uses them.

This number feeds the enrichment findings. A provider that did not answer ("status" is not "ok") contributes nothing: it is UNKNOWN
and the enrichment module reports it as such; it is never counted as clean.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ScoreConfig:
    vt_malicious_weight: int = 8
    vt_malicious_cap: int = 50
    vt_suspicious_weight: int = 4
    vt_suspicious_cap: int = 15
    abuse_confidence_divisor: int = 2
    abuse_confidence_cap: int = 30
    abuse_report_threshold: int = 10
    abuse_report_bonus: int = 10
    otx_pulse_weight: int = 3
    otx_pulse_cap: int = 20
    threatfox_match_bonus: int = 25
    malwarebazaar_match_bonus: int = 25
    urlscan_hit_low_bonus: int = 8
    urlscan_hit_high_threshold: int = 10
    urlscan_hit_high_bonus: int = 15
    domain_age_very_new_days: int = 7
    domain_age_very_new_bonus: int = 25
    domain_age_new_days: int = 30
    domain_age_new_bonus: int = 15
    domain_age_recent_days: int = 90
    domain_age_recent_bonus: int = 5

    @classmethod
    def from_env(cls) -> "ScoreConfig":
        return cls(
            vt_malicious_weight=int(os.getenv("IOC_VT_MALICIOUS_WEIGHT", "8")),
            vt_malicious_cap=int(os.getenv("IOC_VT_MALICIOUS_CAP", "50")),
            vt_suspicious_weight=int(os.getenv("IOC_VT_SUSPICIOUS_WEIGHT", "4")),
            vt_suspicious_cap=int(os.getenv("IOC_VT_SUSPICIOUS_CAP", "15")),
            abuse_confidence_divisor=int(os.getenv("IOC_ABUSE_CONFIDENCE_DIVISOR", "2")),
            abuse_confidence_cap=int(os.getenv("IOC_ABUSE_CONFIDENCE_CAP", "30")),
            abuse_report_threshold=int(os.getenv("IOC_ABUSE_REPORT_THRESHOLD", "10")),
            abuse_report_bonus=int(os.getenv("IOC_ABUSE_REPORT_BONUS", "10")),
            otx_pulse_weight=int(os.getenv("IOC_OTX_PULSE_WEIGHT", "3")),
            otx_pulse_cap=int(os.getenv("IOC_OTX_PULSE_CAP", "20")),
            threatfox_match_bonus=int(os.getenv("IOC_THREATFOX_MATCH_BONUS", "25")),
            malwarebazaar_match_bonus=int(os.getenv("IOC_MALWAREBAZAAR_MATCH_BONUS", "25")),
            urlscan_hit_low_bonus=int(os.getenv("IOC_URLSCAN_HIT_LOW_BONUS", "8")),
            urlscan_hit_high_threshold=int(os.getenv("IOC_URLSCAN_HIT_HIGH_THRESHOLD", "10")),
            urlscan_hit_high_bonus=int(os.getenv("IOC_URLSCAN_HIT_HIGH_BONUS", "15")),
            domain_age_very_new_days=int(os.getenv("IOC_DOMAIN_AGE_VERY_NEW_DAYS", "7")),
            domain_age_very_new_bonus=int(os.getenv("IOC_DOMAIN_AGE_VERY_NEW_BONUS", "25")),
            domain_age_new_days=int(os.getenv("IOC_DOMAIN_AGE_NEW_DAYS", "30")),
            domain_age_new_bonus=int(os.getenv("IOC_DOMAIN_AGE_NEW_BONUS", "15")),
            domain_age_recent_days=int(os.getenv("IOC_DOMAIN_AGE_RECENT_DAYS", "90")),
            domain_age_recent_bonus=int(os.getenv("IOC_DOMAIN_AGE_RECENT_BONUS", "5")),
        )


class RiskScorer:
    @staticmethod
    def explain(
        ioc_type: str,
        vt: Dict[str, Any],
        config: Optional[ScoreConfig] = None,
        threatfox: Optional[Dict[str, Any]] = None,
        malwarebazaar: Optional[Dict[str, Any]] = None,
        urlscan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        config = config or ScoreConfig.from_env()
        components: List[Dict[str, Any]] = []

        if vt.get("status") == "ok":
            vt_malicious = min(vt.get("malicious", 0) * config.vt_malicious_weight, config.vt_malicious_cap)
            if vt_malicious:
                components.append(
                    {
                        "source": "virustotal",
                        "label": "VT malicious detections",
                        "contribution": vt_malicious,
                        "raw_value": vt.get("malicious", 0),
                    }
                )

            vt_suspicious = min(vt.get("suspicious", 0) * config.vt_suspicious_weight, config.vt_suspicious_cap)
            if vt_suspicious:
                components.append(
                    {
                        "source": "virustotal",
                        "label": "VT suspicious detections",
                        "contribution": vt_suspicious,
                        "raw_value": vt.get("suspicious", 0),
                    }
                )

        threatfox = threatfox or {}
        if threatfox.get("status") == "ok" and threatfox.get("matched"):
            families = threatfox.get("malware_families") or []
            label = "ThreatFox malware match"
            if families:
                label += f" ({', '.join(families[:2])})"
            components.append(
                {
                    "source": "threatfox",
                    "label": label,
                    "contribution": config.threatfox_match_bonus,
                    "raw_value": threatfox.get("match_count", 0),
                }
            )

        malwarebazaar = malwarebazaar or {}
        if (
            ioc_type in {"md5", "sha1", "sha256"}
            and malwarebazaar.get("status") == "ok"
            and malwarebazaar.get("matched")
        ):
            components.append(
                {
                    "source": "malwarebazaar",
                    "label": f"MalwareBazaar known sample ({malwarebazaar.get('signature') or 'unclassified'})",
                    "contribution": config.malwarebazaar_match_bonus,
                    "raw_value": malwarebazaar.get("signature"),
                }
            )

        urlscan = urlscan or {}
        if urlscan.get("status") == "ok":
            total_hits = urlscan.get("total_results", 0)
            if total_hits >= config.urlscan_hit_high_threshold:
                components.append(
                    {
                        "source": "urlscan",
                        "label": f"URLScan high hit count ({total_hits} scans)",
                        "contribution": config.urlscan_hit_high_bonus,
                        "raw_value": total_hits,
                    }
                )
            elif total_hits > 0:
                components.append(
                    {
                        "source": "urlscan",
                        "label": f"URLScan hit count ({total_hits} scans)",
                        "contribution": config.urlscan_hit_low_bonus,
                        "raw_value": total_hits,
                    }
                )

        total = max(min(sum(component["contribution"] for component in components), 100), 0)
        return {
            "total": total,
            "components": components,
            "source_statuses": {
                "virustotal": vt.get("status", "unknown"),
                "abuseipdb": "unknown",  # not queried by this app; key kept so the payload shape is unchanged
                "alienvault_otx": "unknown",
                "urlscan": urlscan.get("status", "unknown"),
                "threatfox": threatfox.get("status", "unknown"),
                "malwarebazaar": malwarebazaar.get("status", "unknown"),
                "rdap": "unknown",
            },
            "config": asdict(config),
        }
