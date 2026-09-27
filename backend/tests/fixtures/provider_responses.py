"""Realistic recorded response *shapes* for IOC_Enricher's provider clients, used to
build stub responses in test_enrichment.py. These are not live network replays -- just
hand-shaped dicts matching IOC_Enricher.py's real enrich() return shape, so mapping logic
is exercised against realistic data without any network call in the test suite.

The hash values below are the well-known, publicly published EICAR antivirus test file
hashes (a standard, harmless industry test string) -- safe to reference, not real malware.
"""

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0"

CLEAN_VT_URL_RESULT = {
    "status": "ok",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 70,
    "undetected": 5,
    "reputation": 0,
    "tags": [],
    "categories": {},
}

MALICIOUS_VT_URL_RESULT = {
    "status": "ok",
    "malicious": 12,
    "suspicious": 3,
    "harmless": 40,
    "undetected": 8,
    "reputation": -20,
    "tags": ["phishing"],
    "categories": {"Sophos": "phishing and fraud"},
}

NO_MATCH_THREATFOX_RESULT = {"status": "ok", "matched": False, "match_count": 0}

MATCHED_THREATFOX_RESULT = {
    "status": "ok",
    "matched": True,
    "match_count": 2,
    "malware_families": ["redline_stealer"],
    "threat_types": ["payload_delivery"],
    "tags": ["stealer"],
    "confidence_level": 90,
    "first_seen": "2025-06-01 12:00:00",
}

NO_MATCH_MALWAREBAZAAR_RESULT = {"status": "ok", "matched": False}

MATCHED_MALWAREBAZAAR_RESULT = {
    "status": "ok",
    "matched": True,
    "file_name": "invoice.exe",
    "file_type": "exe",
    "signature": "RedLineStealer",
    "tags": ["exe", "redline"],
    "first_seen": "2025-06-01",
    "reporter": "some_reporter",
}

CLEAN_URLSCAN_RESULT = {"status": "ok", "query": "page.url:\"x\"", "total_results": 0, "sample_urls": [], "sample_domains": [], "sample_countries": [], "screenshots": []}

RATE_LIMITED_RESULT = {"status": "rate_limited", "error": "Provider rate limit reached", "http_status": 429}

NOT_APPLICABLE_RESULT = {"enabled": False, "status": "not_applicable", "error": "unsupported type"}
