"""The reason class of every finding kind (docs/DESIGN_V2.md D16 and D22). DATA ONLY: nothing under scoring/ imports this yet (a test pins that).

Verdict v2 counts a finding as a reason only when it is above info severity, and counts reasons only as DIFFERENT CLASSES. The closed set of classes:
auth, enrichment, content, sender, link, claim.

Rules
  * One explicit class per finding code, written out below; never computed from the module name. Every code in app/finding_codes.py has exactly one entry and no entry exists for an
    unknown code (tests enforce both).
  * A kind that carries a family tag in the registry (sender, link, claim: the `evidence.family` tag the structural floor reads) takes THAT tag as its class, whichever module produces
    it: a display-name finding built by auth_check is a claim, a click-tracker finding built by content_analysis is a link.
  * A kind with no family tag takes an explicit class from auth, enrichment or content.
  * Info-severity findings and gaps are never reasons, but they still get a class so the table is total. For the kinds whose severity varies the class is fixed; only the
    above-info rule varies, and that rule belongs to the router, not to this table.
  * Frozen like the codes: tests/fixtures/reason_classes_frozen.json pins the table, and a change to one without the other fails the tests. A changed class is a deliberate,
    reviewed edit of both in one commit (and, once Phase B uses the table, a model_version bump).
"""
from __future__ import annotations

CLASSES = ("auth", "enrichment", "content", "sender", "link", "claim")
UNTAGGED_CLASSES = ("auth", "enrichment", "content")  # a kind with no family tag takes one of these

REASON_CLASS: dict[str, str] = {
    # ---- auth_check: what the receiving infrastructure established ----------------------------------------------------------------------
    "AUTH_SPF_CHECK_FAILED": "auth",
    "AUTH_DKIM_CHECK_FAILED": "auth",
    "AUTH_DMARC_CHECK_FAILED": "auth",
    "AUTH_SPF_NOT_EVALUATED": "auth",
    "AUTH_DKIM_NOT_EVALUATED": "auth",
    "AUTH_DMARC_NOT_EVALUATED": "auth",
    "AUTH_ALL_METHODS_PASSED": "auth",
    "AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED": "auth",
    "AUTH_DKIM_FAILURE_CLAIMED_UNTRUSTED": "auth",
    "AUTH_DMARC_FAILURE_CLAIMED_UNTRUSTED": "auth",
    "AUTH_SPF_TRUSTED_RESULT_BELOW_HOP": "auth",
    "AUTH_DKIM_TRUSTED_RESULT_BELOW_HOP": "auth",
    "AUTH_DMARC_TRUSTED_RESULT_BELOW_HOP": "auth",
    "AUTH_UNTRUSTED_CLAIMS_IGNORED": "auth",
    # ---- auth_check: sender identity ------------------------------------------------------------------------------------------------------
    "AUTH_IDENTITY_RETURN_PATH_MISMATCH": "auth",        # untagged; ambiguous (could be read as sender): see the Phase B step 4 report
    "AUTH_IDENTITY_REPLY_TO_MISMATCH": "auth",           # untagged; ambiguous, as above
    "AUTH_IDENTITY_DISPLAY_NAME_SPOOF": "claim",         # tag claim (C1)
    "AUTH_IDENTITY_DISPLAY_NAME_FUZZY": "auth",          # untagged; ambiguous (a fuzzy twin of the claim finding): see the report
    "AUTH_IDENTITY_MACHINE_SENDER_BRAND": "sender",      # tag sender (S1)
    "AUTH_IDENTITY_LOCAL_SUBMISSION": "sender",          # tag sender (S2)
    "AUTH_IDENTITY_FREE_MAILBOX_BRAND": "sender",        # tag sender (S3)
    "AUTH_FROM_HEADER_AMBIGUOUS": "auth",                # untagged; a header-parse note
    # ---- auth_check: alignment ----------------------------------------------------------------------------------------------------------------
    "AUTH_ALIGN_SPF_ALIGNED": "auth",
    "AUTH_ALIGN_SPF_OTHER_DOMAIN": "auth",
    "AUTH_ALIGN_DKIM_ALIGNED": "auth",
    "AUTH_ALIGN_DKIM_OTHER_DOMAIN": "auth",
    "AUTH_ALIGN_NONE_ALIGNED": "auth",
    # ---- auth_check: claims ---------------------------------------------------------------------------------------------------------------
    "AUTH_CLAIM_ENTITY_MISMATCH_UNSIGNED": "claim",      # tag claim (C2)
    "AUTH_CLAIM_DECOY_LINKS": "claim",                   # tag claim (C3)
    "AUTH_CLAIM_BODY_BRAND_MENTION": "auth",             # untagged (C1b, info); ambiguous (a claim-style signal): see the report
    # ---- enrichment -------------------------------------------------------------------------------------------------------------------------
    "ENRICH_SKIPPED_PER_EMAIL_LIMIT": "enrichment",
    "ENRICH_INCOMPLETE_PROVIDER_NO_RESULT": "enrichment",
    "ENRICH_INCOMPLETE_INTERNAL_HOST": "enrichment",
    "ENRICH_INCOMPLETE_SHARED_PLATFORM": "enrichment",
    "ENRICH_REPUTATION_HOST_SUSPICIOUS": "enrichment",
    "ENRICH_REPUTATION_HASH_KNOWN_MALICIOUS": "enrichment",
    "ENRICH_PROVIDERS_NO_USABLE_ANSWER": "enrichment",
    # ---- content_analysis ------------------------------------------------------------------------------------------------------------------
    "CONTENT_URGENCY_LANGUAGE": "content",
    "CONTENT_BRAND_LINK_MISMATCH": "content",            # untagged; ambiguous (mentions a brand, links elsewhere): see the report
    "CONTENT_GREETING_PERSONAL_CLAIM": "content",
    "CONTENT_LANGUAGE_UNSUPPORTED": "content",
    "CONTENT_LANGUAGE_NO_TEXT": "content",
    "CONTENT_LANGUAGE_UNDETERMINED": "content",
    "CONTENT_LINK_TRACKER_PLATFORM_MISMATCH": "link",    # tag link (L1)
    "CONTENT_LINK_HOTLINKED_ASSETS": "link",             # tag link (L2)
    "CONTENT_LINK_REDIRECTOR": "link",                   # tag link (L3)
}
