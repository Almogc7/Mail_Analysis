"""The registry of finding kinds: one stable, content-free CODE per kind of finding (docs/DESIGN_V2.md, D22).

A finding's title can contain an indicator (a host, a hash, a brand, a file name), so it cannot be used to refer to a KIND of finding. The `code` can: it names the kind, never the
instance. Later data (the feedback log, dispositions, the reason classes of verdict v2) will reference these codes, so the rules below are strict.

Rules
  * Format: uppercase letters, digits and underscores only, matching CODE_PATTERN, named MODULE_AREA_SIGNAL (for example AUTH_ALIGN_SPF_ALIGNED). The prefix is the module:
    AUTH (auth_check), ENRICH (enrichment), CONTENT (content_analysis).
  * A code NEVER contains a brand, host, address, domain, file name or any text taken from a message, and never one of the words the V1 wording ban forbids as a word of its own.
  * A code identifies a KIND. The same kind always gets the same code however its title varies (a different brand, host or method name in the title is the same kind).
    A kind whose wording differs only by the authentication method (SPF, DKIM, DMARC) has one code per method.
  * Codes are FROZEN once committed. Never rename or reuse one: a changed meaning is a NEW code, and the old entry stays here with `retired=True` and a `note` saying what replaced
    it. tests/fixtures/finding_codes_frozen.json pins every code with its module, family and signal; changing the registry without updating it, in the same commit, fails the tests.
  * `severity` is the usual severity of the kind; `severity_varies` says the producer sets another one in some cases (named in the description). `family` and `signal` are the
    structural tags the finding already carries in `evidence` (the families the verdict floors read); they are None for kinds that carry no such tag.
  * `description` is the TEMPLATE of what the finding says, with <placeholders>, never a real value.

`code(name)` returns the name after checking that it is registered, so a typo at a producer fails at once instead of shipping an unknown code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CODE_PATTERN = re.compile("^[A-Z][A-Z0-9_]{3,63}$")  # no backslash: nothing in it to mangle
MODULE_PREFIX = {"auth_check": "AUTH_", "enrichment": "ENRICH_", "content_analysis": "CONTENT_"}


@dataclass(frozen=True)
class FindingKind:
    code: str
    module: str
    severity: str
    description: str
    severity_varies: bool = False
    family: str | None = None  # sender | link | claim: the structural family the finding carries in evidence
    signal: str | None = None  # S1..S3, L1..L3, C1, C1b, C2, C3: the signal id the finding carries in evidence
    retired: bool = False
    note: str = ""


def _k(code: str, module: str, severity: str, description: str, *, varies: bool = False, family: str | None = None, signal: str | None = None) -> FindingKind:
    return FindingKind(code, module, severity, description, severity_varies=varies, family=family, signal=signal)


_A, _E, _C = "auth_check", "enrichment", "content_analysis"

REGISTRY: tuple[FindingKind, ...] = (
    # ---- auth_check: results a trusted receiver established (one code per method) -------------------------------------------------------------
    _k("AUTH_SPF_CHECK_FAILED", _A, "high", "<METHOD> authentication result was '<result>' (reported by a trusted receiver). High for fail, medium for softfail or permerror.", varies=True),
    _k("AUTH_DKIM_CHECK_FAILED", _A, "high", "<METHOD> authentication result was '<result>' (reported by a trusted receiver). High for fail, medium for softfail or permerror.", varies=True),
    _k("AUTH_DMARC_CHECK_FAILED", _A, "high", "<METHOD> authentication result was '<result>' (reported by a trusted receiver). High for fail, medium for softfail or permerror.", varies=True),
    _k("AUTH_SPF_NOT_EVALUATED", _A, "info", "No trusted receiver evaluated <METHOD>; the text names the reason (no trusted receivers configured, a claim from an untrusted source, a receiver that evaluated SPF only, or no result)."),
    _k("AUTH_DKIM_NOT_EVALUATED", _A, "info", "No trusted receiver evaluated <METHOD>; the text names the reason (no trusted receivers configured, a claim from an untrusted source, a receiver that evaluated SPF only, or no result)."),
    _k("AUTH_DMARC_NOT_EVALUATED", _A, "info", "No trusted receiver evaluated <METHOD>; the text names the reason (no trusted receivers configured, a claim from an untrusted source, a receiver that evaluated SPF only, or no result)."),
    _k("AUTH_ALL_METHODS_PASSED", _A, "info", "A trusted receiver reported SPF, DKIM and DMARC all passed. This authenticates the sending infrastructure and domain; it says nothing about what the message contains."),
    _k("AUTH_SPF_FAILURE_CLAIMED_UNTRUSTED", _A, "low", "A header from '<host>' reports <METHOD> '<result>', but that host is not a configured trusted receiver, so it is a weak signal only."),
    _k("AUTH_DKIM_FAILURE_CLAIMED_UNTRUSTED", _A, "low", "A header from '<host>' reports <METHOD> '<result>', but that host is not a configured trusted receiver, so it is a weak signal only."),
    _k("AUTH_DMARC_FAILURE_CLAIMED_UNTRUSTED", _A, "low", "A header from '<host>' reports <METHOD> '<result>', but that host is not a configured trusted receiver, so it is a weak signal only."),
    _k("AUTH_SPF_TRUSTED_RESULT_BELOW_HOP", _A, "info", "The trusted <METHOD> result sits below the Received line of the hop that added it; a reason to look closer, not proof of forgery."),
    _k("AUTH_DKIM_TRUSTED_RESULT_BELOW_HOP", _A, "info", "The trusted <METHOD> result sits below the Received line of the hop that added it; a reason to look closer, not proof of forgery."),
    _k("AUTH_DMARC_TRUSTED_RESULT_BELOW_HOP", _A, "info", "The trusted <METHOD> result sits below the Received line of the hop that added it; a reason to look closer, not proof of forgery."),
    _k("AUTH_UNTRUSTED_CLAIMS_IGNORED", _A, "info", "<n> SPF/DKIM/DMARC claim(s) in the headers were not added by a configured trusted receiver and have no effect on the verdict."),
    # ---- auth_check: sender identity -------------------------------------------------------------------------------------------------------
    _k("AUTH_IDENTITY_RETURN_PATH_MISMATCH", _A, "low", "The From domain '<domain>' differs from the Return-Path domain '<domain>'. Common with legitimate mail services; a weak signal on its own."),
    _k("AUTH_IDENTITY_REPLY_TO_MISMATCH", _A, "medium", "The From domain '<domain>' differs from the Reply-To domain '<domain>'. A common pattern to redirect replies."),
    _k("AUTH_IDENTITY_DISPLAY_NAME_SPOOF", _A, "medium", "The From display name contains the brand '<brand>' as a whole word but the sending domain '<domain>' is not one of that brand's known domains.", family="claim", signal="C1"),
    _k("AUTH_IDENTITY_DISPLAY_NAME_FUZZY", _A, "medium", "The From display name is one character away from the brand '<brand>' and the sending domain '<domain>' is not one of its known domains. Fuzzy match only."),
    _k("AUTH_IDENTITY_MACHINE_SENDER_BRAND", _A, "medium", "The <source> references '<brand>', but the sender looks machine-provisioned: <indicators>.", family="sender", signal="S1"),
    _k("AUTH_IDENTITY_LOCAL_SUBMISSION", _A, "low", "The first hop is a local submission (not authenticated SMTP): the message was injected by a process on '<host>'. A weak signal on its own.", family="sender", signal="S2"),
    _k("AUTH_IDENTITY_FREE_MAILBOX_BRAND", _A, "medium", "The display name claims '<brand>' but the sender is a free consumer mailbox ('<domain>'), where anyone can choose any display name.", family="sender", signal="S3"),
    _k("AUTH_FROM_HEADER_AMBIGUOUS", _A, "low", "The From header is not a plain, unambiguous single 'Display <address>' (<reasons>). Informational: does not affect the score by itself."),
    # ---- auth_check: alignment -------------------------------------------------------------------------------------------------------------
    _k("AUTH_ALIGN_SPF_ALIGNED", _A, "info", "SPF authenticated the sending infrastructure and the envelope domain equals the From domain '<domain>'; it says nothing about what the message contains."),
    _k("AUTH_ALIGN_SPF_OTHER_DOMAIN", _A, "info", "SPF authenticated '<domain>', which is not the From domain '<domain>', so it says nothing about the visible sender."),
    _k("AUTH_ALIGN_DKIM_ALIGNED", _A, "info", "The message carries a valid DKIM signature from '<domain>', the From domain's registrable domain; it says nothing about what the message contains."),
    _k("AUTH_ALIGN_DKIM_OTHER_DOMAIN", _A, "info", "The valid DKIM signature is from '<domain>', not the From domain '<domain>': the signer is a third party and vouches for nothing about the From identity."),
    _k("AUTH_ALIGN_NONE_ALIGNED", _A, "medium", "A trusted receiver evaluated SPF and DKIM, but neither authenticated the From domain '<domain>'. Nothing ties the visible sender to an authenticated identity."),
    _k("AUTH_ALIGN_NONE_ALIGNED_FALLBACK", _A, "medium", "As AUTH_ALIGN_NONE_ALIGNED, but the envelope domain compared with the From domain '<domain>' was taken from a header the sender controls (<source>) because the trusted SPF result carried no domain. Added after AUTH_ALIGN_NONE_ALIGNED was frozen; that code is unchanged and now means the domain came from the trusted result."),
    # ---- auth_check: claims (what the message presents itself as, against who sent it) ---------------------------------------------------------
    _k("AUTH_CLAIM_ENTITY_MISMATCH_UNSIGNED", _A, "low", "<n> of <m> non-platform link and image hosts belong to '<domain>', unrelated to the sending domain '<domain>', and the message has no DKIM-Signature header.", family="claim", signal="C2"),
    _k("AUTH_CLAIM_DECOY_LINKS", _A, "medium", "The display name or subject names an entity whose own domain is linked (<names>), but the message was not sent from that entity's domain '<domain>'.", family="claim", signal="C3"),
    _k("AUTH_CLAIM_BODY_BRAND_MENTION", _A, "info", "The body mentions <brands>. Common in ordinary mail; it adds a little to the score and never counts toward the corroboration floor.", signal="C1b"),
    # ---- enrichment ------------------------------------------------------------------------------------------------------------------------
    _k("ENRICH_SKIPPED_PER_EMAIL_LIMIT", _E, "low", "<kind> '<value>' was not looked up because this email exceeded the per-email enrichment limit; the riskiest indicators are looked up first. It is UNKNOWN."),
    _k("ENRICH_INCOMPLETE_PROVIDER_NO_RESULT", _E, "info", "<provider> returned no usable result (status: <status>). This indicator is UNKNOWN on that source."),
    _k("ENRICH_INCOMPLETE_INTERNAL_HOST", _E, "info", "'<host>' looks internal (no public DNS name or a private or loopback address), so it was never sent to any external service. It is UNKNOWN."),
    _k("ENRICH_INCOMPLETE_SHARED_PLATFORM", _E, "info", "'<host>' is on <platform> (<kind>), a shared platform whose domains host content anyone can create, so no reputation lookup was made. UNINFORMATIVE."),
    _k("ENRICH_REPUTATION_HOST_SUSPICIOUS", _E, "low", "A link host (or URL) scored above zero in the reputation lookups; the text lists the components. Severity follows the score (low, medium, high, critical).", varies=True),
    _k("ENRICH_REPUTATION_HASH_KNOWN_MALICIOUS", _E, "low", "An attachment hash scored above zero in the lookups; the text lists the components. Severity follows the score (low, medium, high, critical).", varies=True),
    _k("ENRICH_PROVIDERS_NO_USABLE_ANSWER", _E, "info", "Some enrichment providers did not give a usable answer; the affected indicators are UNKNOWN (<provider: status xN>)."),
    # ---- content_analysis ------------------------------------------------------------------------------------------------------------------
    _k("CONTENT_URGENCY_LANGUAGE", _C, "low", "Matched <n> urgency or pressure phrase(s): <phrases>. Low for one or two matches (medium from two, high from four).", varies=True),
    _k("CONTENT_BRAND_LINK_MISMATCH", _C, "high", "The body mentions brand(s) [<brands>], but a link displaying '<text>' actually points to '<domain>'."),
    _k("CONTENT_GREETING_PERSONAL_CLAIM", _C, "medium", "The email opens with a generic greeting ('<greeting>') but claims personalised or account-specific action is needed: <phrases>."),
    _k("CONTENT_LANGUAGE_UNSUPPORTED", _C, "info", "Content analysis has lexicons for English and Hebrew only; this text looks like <language> (<reason>), so the phrase and brand heuristics were not applied."),
    _k("CONTENT_LANGUAGE_NO_TEXT", _C, "info", "There is no readable text (<reason>), so content coverage is reduced."),
    _k("CONTENT_LANGUAGE_UNDETERMINED", _C, "info", "The language of the text could not be confirmed (<reason>), so it is not known whether the English and Hebrew heuristics apply."),
    _k("CONTENT_LINK_TRACKER_PLATFORM_MISMATCH", _C, "medium", "A link goes through the click tracker of <platforms>, but nothing in the sending path involves that platform.", family="link", signal="L1"),
    _k("CONTENT_LINK_HOTLINKED_ASSETS", _C, "low", "<n> of <m> images load from '<domain>', which is not the sender's domain and also hosts links in the message (or is named in the sender or subject).", family="link", signal="L2"),
    _k("CONTENT_LINK_REDIRECTOR", _C, "low", "A link hides its destination behind a URL shortener or carries another URL in its query string.", family="link", signal="L3"),
)

BY_CODE: dict[str, FindingKind] = {k.code: k for k in REGISTRY}


def code(name: str) -> str:
    """The code itself, after checking it is registered (a typo fails here, at the producer, not later in the data)."""
    if name not in BY_CODE:
        raise KeyError(f"unregistered finding code {name!r}: add it to app/finding_codes.py (and the frozen snapshot) first")
    return name
