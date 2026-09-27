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
    # Regional (Israeli) starter set -- added after a real phishing email impersonating
    # "kvish6" went undetected purely because this list had zero regional coverage. The
    # "kvish6" entry is confirmed from that real case; the rest are a best-effort starter
    # set of likely-relevant major brands, not vetted -- extend/correct as needed.
    "kvish6": ["kvish6.co.il"],
    "bank hapoalim": ["bankhapoalim.co.il"],
    "bank leumi": ["leumi.co.il"],
    "discount bank": ["discountbank.co.il"],
    "fibi": ["fibi.co.il"],
    "israel post": ["israelpost.co.il"],
}

# Used only by auth_check.spoofing's fuzzy display-name match.
FUZZY_MATCH_THRESHOLD = 80
