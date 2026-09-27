# Small curated list for v1 — brand name to its legitimate domain(s).
# Extend as needed; false negatives here just mean "not flagged", not "safe".
# Used by both auth_check.spoofing (fuzzy-matched against the From display name) and
# content_analysis.brand_impersonation (exact-phrase-matched against body content) --
# the matching algorithm differs per use case, but the brand/domain data is shared here
# so it's defined exactly once.
KNOWN_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "meta.com"],
}

# Used only by auth_check.spoofing's fuzzy display-name match.
FUZZY_MATCH_THRESHOLD = 80
