"""The reason class and the reason eligibility of every finding kind (docs/DESIGN_V2.md D16 and D22). DATA ONLY: nothing under scoring/ imports this yet (a test pins that).

Verdict v2 counts a finding as a reason only when it is above info severity AND its kind is eligible, and counts reasons only as DIFFERENT CLASSES. The closed set of classes:
auth, enrichment, content, sender, link, claim.

Class rules
  * One explicit class per finding code, written out below; never computed from the module name. Every code in app/finding_codes.py has exactly one entry and no entry exists for an
    unknown code (tests enforce both).
  * A kind that carries a family tag in the registry (sender, link, claim: the `evidence.family` tag the structural floor reads) takes THAT tag as its class, whichever module produces
    it: a display-name finding built by auth_check is a claim, a click-tracker finding built by content_analysis is a link.
  * A kind with no family tag takes an explicit class from auth, enrichment or content.
  * Info-severity findings and gaps are never reasons, but they still get a class so the table is total. For the kinds whose severity varies the class is fixed.

Eligibility rule (`counts_as_reason`)
  A kind counts as a reason only if (1) its severity can be above info AND (2) it is a real signal about the message: not a gap (a check that did not run), not a parse note, and not
  an untrusted claim (a result written below the trust boundary). The flag says whether the KIND may ever count. For a kind whose severity varies, the router still applies the
  above-info rule to the severity actually produced; this table does not. Every entry has a short, content-free `reason` saying why it does or does not count.

Known limitation (D22): AUTH_IDENTITY_DISPLAY_NAME_SPOOF is a claim and AUTH_IDENTITY_DISPLAY_NAME_FUZZY is auth. The fuzzy kind is DELIBERATELY untagged so that it cannot feed the
structural floor, so a spoof and its near-miss would count as two classes if both appeared on one message.

Frozen like the codes: tests/fixtures/reason_classes_frozen.json pins the table, and a change to one without the other fails the tests. A changed entry is a deliberate, reviewed edit of
both in one commit (and, once Phase B uses the table, a model_version bump).
"""
from __future__ import annotations

from typing import NamedTuple

CLASSES = ("auth", "enrichment", "content", "sender", "link", "claim")
UNTAGGED_CLASSES = ("auth", "enrichment", "content")  # a kind with no family tag takes one of these


class ReasonEntry(NamedTuple):
    cls: str
    counts_as_reason: bool
    reason: str  # short, content-free: why this kind does or does not count


def _y(cls: str, reason: str) -> ReasonEntry:
    return ReasonEntry(cls, True, reason)


def _n(cls: str, reason: str) -> ReasonEntry:
    return ReasonEntry(cls, False, reason)


_INFO = "info severity: never a reason"

REASON_TABLE: dict[str, ReasonEntry] = {
    # ---- auth_check: what the receiving infrastructure established ----------------------------------------------------------------------
    "AUTH_SPF_CHECK_FAILED": _y("auth", "a trusted receiver's failed result about this message"),
    "AUTH_DKIM_CHECK_FAILED": _y("auth", "a trusted receiver's failed result about this message"),
    "AUTH_DMARC_CHECK_FAILED": _y("auth", "a trusted receiver's failed result about this message"),
    "AUTH_SPF_NOT_EVALUATED": _n("auth", "gap: info severity, the method was not evaluated by a trusted receiver"),
    "AUTH_DKIM_NOT_EVALUATED": _n("auth", "gap: info severity, the method was not evaluated by a trusted receiver"),
    "AUTH_DMARC_NOT_EVALUATED": _n("auth", "gap: info severity, the method was not evaluated by a trusted receiver"),
    "AUTH_ALL_METHODS_PASSED": _n("auth", _INFO),
    "AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED": _n("auth", "untrusted claim: the result was written below the trust boundary, so it is shown but never counted"),
    "AUTH_DKIM_FAILURE_CLAIMED_UNTRUSTED": _n("auth", "untrusted claim: the result was written below the trust boundary, so it is shown but never counted"),
    "AUTH_DMARC_FAILURE_CLAIMED_UNTRUSTED": _n("auth", "untrusted claim: the result was written below the trust boundary, so it is shown but never counted"),
    "AUTH_SPF_TRUSTED_RESULT_BELOW_HOP": _n("auth", _INFO),
    "AUTH_DKIM_TRUSTED_RESULT_BELOW_HOP": _n("auth", _INFO),
    "AUTH_DMARC_TRUSTED_RESULT_BELOW_HOP": _n("auth", _INFO),
    "AUTH_UNTRUSTED_CLAIMS_IGNORED": _n("auth", _INFO),
    # ---- auth_check: sender identity ------------------------------------------------------------------------------------------------------
    "AUTH_IDENTITY_RETURN_PATH_MISMATCH": _y("auth", "a weak but real signal in the message's own headers; common with mail services"),
    "AUTH_IDENTITY_REPLY_TO_MISMATCH": _y("auth", "a real signal in the message's own headers (replies are redirected)"),
    "AUTH_IDENTITY_DISPLAY_NAME_SPOOF": _y("claim", "a real signal: the display name claims a brand the sending domain does not own"),
    "AUTH_IDENTITY_DISPLAY_NAME_FUZZY": _y("auth", "a real signal (fuzzy display-name match); deliberately untagged, so it cannot feed the structural floor"),
    "AUTH_IDENTITY_MACHINE_SENDER_BRAND": _y("sender", "a real structural signal about who sent the message"),
    "AUTH_IDENTITY_LOCAL_SUBMISSION": _y("sender", "a real structural signal about how the message entered the path"),
    "AUTH_IDENTITY_FREE_MAILBOX_BRAND": _y("sender", "a real structural signal about who sent the message"),
    "AUTH_FROM_HEADER_AMBIGUOUS": _n("auth", "parse note: informational, weight 0, it describes how the header was written and not what the message does"),
    # ---- auth_check: alignment ----------------------------------------------------------------------------------------------------------------
    "AUTH_ALIGN_SPF_ALIGNED": _n("auth", _INFO),
    "AUTH_ALIGN_SPF_OTHER_DOMAIN": _n("auth", _INFO),
    "AUTH_ALIGN_DKIM_ALIGNED": _n("auth", _INFO),
    "AUTH_ALIGN_DKIM_OTHER_DOMAIN": _n("auth", _INFO),
    "AUTH_ALIGN_NONE_ALIGNED": _y("auth", "computed only when a trusted receiver evaluated both SPF and DKIM; neither authenticated the From domain"),
    # ---- auth_check: claims ---------------------------------------------------------------------------------------------------------------
    "AUTH_CLAIM_ENTITY_MISMATCH_UNSIGNED": _y("claim", "a real structural signal: links belong to another entity and the message is unsigned"),
    "AUTH_CLAIM_DECOY_LINKS": _y("claim", "a real structural signal: the claimed entity's own domain is linked but did not send it"),
    "AUTH_CLAIM_BODY_BRAND_MENTION": _n("auth", _INFO),
    # ---- enrichment -------------------------------------------------------------------------------------------------------------------------
    "ENRICH_SKIPPED_PER_EMAIL_LIMIT": _n("enrichment", "gap: the indicator was not looked up because of a limit, so nothing is known about it"),
    "ENRICH_INCOMPLETE_PROVIDER_NO_RESULT": _n("enrichment", "gap: info severity, a provider gave no usable answer"),
    "ENRICH_INCOMPLETE_INTERNAL_HOST": _n("enrichment", "gap: info severity, never sent to an external service"),
    "ENRICH_INCOMPLETE_SHARED_PLATFORM": _n("enrichment", "gap: info severity, a shared platform with no reputation lookup"),
    "ENRICH_REPUTATION_HOST_SUSPICIOUS": _y("enrichment", "a real signal: a lookup scored the host above zero"),
    "ENRICH_REPUTATION_HASH_KNOWN_MALICIOUS": _y("enrichment", "a real signal: a lookup scored the attachment hash above zero"),
    "ENRICH_PROVIDERS_NO_USABLE_ANSWER": _n("enrichment", "gap: info severity, a summary of providers without an answer"),
    # ---- content_analysis ------------------------------------------------------------------------------------------------------------------
    "CONTENT_URGENCY_LANGUAGE": _y("content", "a real signal in the message text"),
    "CONTENT_BRAND_LINK_MISMATCH": _y("content", "a real signal: a brand named in the body is linked to a different domain"),
    "CONTENT_GREETING_PERSONAL_CLAIM": _y("content", "a real signal in the message text"),
    "CONTENT_LANGUAGE_UNSUPPORTED": _n("content", "gap: info severity, content heuristics were not applied to this language"),
    "CONTENT_LANGUAGE_NO_TEXT": _n("content", "gap: info severity, there was no readable text"),
    "CONTENT_LANGUAGE_UNDETERMINED": _n("content", "gap: info severity, the language could not be confirmed"),
    "CONTENT_LINK_TRACKER_PLATFORM_MISMATCH": _y("link", "a real structural signal about the message's links"),
    "CONTENT_LINK_HOTLINKED_ASSETS": _y("link", "a real structural signal about the message's images and links"),
    "CONTENT_LINK_REDIRECTOR": _y("link", "a real structural signal about the message's links"),
}

# The class of every code, as the earlier table exposed it.
REASON_CLASS: dict[str, str] = {code: entry.cls for code, entry in REASON_TABLE.items()}
