"""The wording of verdict v2 (docs/DESIGN_V2.md 2.1, 2.3; docs/PHASE_B_PREREGISTRATION.md 1.1): the four tier labels and every fixed string of `verdict_v2`.

Every string here is the application's own, fixed text: nothing is taken from a message. The V1 word ban applies to all of it (a test and the wording lint check it). A reason that rests on a finding takes its text
from the finding registry's content-free TEMPLATE (app/finding_codes.py), never from the finding's title, because a title can carry a host, a brand or an address; the reason points at the finding itself
by `evidence_ref`, where the page already shows the real title. The how-to-clear sentences of blockers that already exist in the coverage report are reused from it, word for word.
"""
from __future__ import annotations

from app.coverage import HOW_TO_CLEAR

TIER_KEYS = {"T1": "confirmed_malicious", "T2": "suspicious", "T3": "needs_analyst", "T4": "no_indicators_found"}
TIER_LABELS = {
    "confirmed_malicious": "Confirmed malicious",
    "suspicious": "Suspicious",
    "needs_analyst": "Needs analyst",
    "no_indicators_found": "No indicators found",
}

# Reasons that do not rest on a finding: the score, the conflict, the gaps of a Needs analyst result, the positive evidence of No indicators found.
PSEUDO_REASON_TEXT = {
    "weighted_score_band": "The weighted score is in the suspicious band and the evidence comes from two different classes.",
    "weighted_score_70_or_more": "The weighted score is 70 or more.",
    "evidence_conflict": "A provider flagged an indicator on a domain from your known-sender or own-domain list: a conflict that the analyst decides, never a confirmed verdict.",
    "signals_present": "Something was flagged, but not enough to call it suspicious.",
    "no_signals_insufficient_evidence": "Nothing was flagged, and nothing positive was established either.",
    "low_confidence": "Too few of the checks could be completed to call a result.",
    "trusted_aligned_dkim_or_dmarc_pass": "A trusted receiver verified an aligned DKIM signature or a DMARC pass.",
    "sender_on_known_list": "The sender's domain is on your known-sender list.",
}
PSEUDO_REASON_KIND = {
    "weighted_score_band": "score", "weighted_score_70_or_more": "score", "evidence_conflict": "evidence_conflict",
    "signals_present": "gap", "no_signals_insufficient_evidence": "gap", "low_confidence": "gap",
    "trusted_aligned_dkim_or_dmarc_pass": "positive_evidence", "sender_on_known_list": "positive_evidence",
}

HARD_EVIDENCE_TEXT = {
    "H1": "The attachment's SHA-256 is a known malware sample (MalwareBazaar).",
    "H2": "ThreatFox lists this indicator with a confidence of at least 75.",
    "H3": "VirusTotal reports at least 10 engines malicious for this indicator.",
}

# One entry per blocker code of backend/tests/fixtures/blocker_codes_frozen.json: (what is not checked, how to clear it). A how-to-clear that exists in the coverage report is reused from it.
_QR = HOW_TO_CLEAR["qr_not_decoded"]
BLOCKER_TEXT: dict[str, tuple[str, str]] = {
    "qr_not_decoded": ("An image attachment was not decoded for QR codes.", _QR),
    "inline_image_not_decoded": ("An image embedded in the message (a cid: part) was not decoded for QR codes.", _QR),
    "data_uri_image_not_decoded": ("An image embedded in the HTML (a data: source) was not decoded for QR codes.", _QR),
    "static_analysis_off": ("An attachment of an active or unrecognised type was not examined.", HOW_TO_CLEAR["content_never_opened"]),
    "html_attachment_unanalysed": ("An HTML attachment was not analysed.", HOW_TO_CLEAR["html_attachment_unanalysed"]),
    "archive_contents_unexamined": ("An archive or disk image was not examined.", HOW_TO_CLEAR["archive_contents_unexamined"]),
    "nested_message_unexamined": ("A nested message was not examined as a message of its own.", "Open the inner message separately and analyse it."),
    "calendar_invite_unexamined": ("A calendar invite was not examined.", "Read the invite's location, description and links by hand."),
    "redirects_not_resolved": ("A shortener or redirector was not resolved.", HOW_TO_CLEAR["redirects_not_resolved"]),
    "shared_platform": ("A link on a shared platform was not looked at.", HOW_TO_CLEAR["shared_platform"]),
    "internal_host_not_sent": ("An internal-looking host was not looked up.", HOW_TO_CLEAR["internal_host_not_sent"]),
    "language_unsupported": ("The message is in a language the checks cannot read.", HOW_TO_CLEAR["language_unsupported"]),
    "no_readable_text": ("The message has no readable text.", HOW_TO_CLEAR["no_readable_text"]),
    "no_trusted_receiver_hop": ("No trusted receiver wrote an authentication result for this message.", HOW_TO_CLEAR["no_trusted_receiver_hop"]),
    "from_header_unparseable": ("The sender address could not be established.", HOW_TO_CLEAR["from_header_unparseable"]),
    "parse_failure": ("A part of the message could not be parsed.", "Read the original message by hand: that part was not checked."),
    "parse_limit": ("A size or depth limit was reached while parsing the message.", "Read the original message by hand: the rest was not checked."),
    "parse_timeout": ("Parsing the message took too long and was stopped.", "Read the original message by hand: the rest was not checked."),
    "unknown_finding_code": ("A finding of an unrecognised kind was produced.", "Update the finding registry so every kind of finding is known."),
}
# The how-to-clear of the receiver blocker depends on its detail.
BLOCKER_HOW_TO_CLEAR_BY_DETAIL = {("no_trusted_receiver_hop", "not_configured"): HOW_TO_CLEAR["no_trusted_receivers_configured"]}

DETAIL_TEXT = {
    "pdf": "a PDF", "office_legacy": "a legacy Office file", "office_zip": "an Office file", "executable": "an executable", "script": "a script", "shortcut": "a shortcut file",
    "unknown_type": "a file of an unrecognised type", "no_first_bytes": "a file whose type could not be read", "archive": "an archive", "disk_image": "a disk image",
    "rfc822": "an attached message", "outlook_msg": "an Outlook message", "not_configured": "no trusted receiver is configured", "no_matching_hop": "receivers are configured but none matched",
    "missing": "no sender address", "malformed": "a malformed sender address", "body_extract_failed": "the message body", "attachment_read_failed": "an attachment",
    "header_parse_failed": "a header", "mime_structure_error": "the message structure", "unrecognised_flag": "an unrecognised failure",
}


def tier_label(tier_key: str) -> str:
    return TIER_LABELS[tier_key]


def blocker_text(code: str, detail: str | None) -> tuple[str, str]:
    """(text, how_to_clear) of a blocker item: its fixed text, with the detail's phrase in brackets when there is one."""
    text, how = BLOCKER_TEXT[code]
    if detail:
        text = f"{text} ({DETAIL_TEXT[detail]})"
    return text, BLOCKER_HOW_TO_CLEAR_BY_DETAIL.get((code, detail), how)
