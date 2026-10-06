"""Metadata-level blocker detection for verdict v2 (docs/DESIGN_V2.md 2.3; codes pinned in backend/tests/fixtures/blocker_codes_frozen.json).

`derive_blockers(parts, parsed_flags)` is a PURE function: no I/O, no network, no logging, deterministic, and it never mutates its input. It is NOT wired into the pipeline, the API or the frontend
(`verdict_v2` does not exist); only tests and read-only scripts call it. It returns a sorted list of blocker ITEMS, content-free: {"code": a frozen blocker code, "detail": a member of the closed
DETAILS enum or None}, never a name, an address or any text of the message. The detail says WHICH kind of thing blocked (a pdf, a legacy Office file, an executable, a receiver that is not configured);
the frozen code table does not change, and `blocker_codes(items)` gives the plain sorted code list that the tier function takes as its `blockers` input.

WHAT IT READS (metadata only). For every attachment or inline part: the declared filename, the declared content type, the size and the FIRST BYTES (at most 16 are used, supplied by the caller). Also
the count of `data:` image sources, the parsed From address (or none), structured parse flags (a code and a part id, never an error text), and the language and coverage flags the app already holds.

WHAT IT NEVER DOES. It never opens, decompresses or parses a file: no zip, OLE, PDF or archive reading. A type is read from the magic number at the start of the file (or, for text, from the leading
characters); a RENAMED FILE IS CAUGHT because the magic number wins over the extension. The declared name and type only ADD a blocker where the magic number cannot tell two things apart (a ZIP may be an
Office file; an OLE container may be a .msg) or where there is no recognisable magic; they never remove one.

PHASE C IS NOT DERIVED HERE: encryption flags (an encrypted Office or PDF file, a password-protected archive) and anything that needs structure parsing. NOTHING IS LOST FOR T4: an attachment of an active
or container type that was not examined already blocks T4 (2.3), and a ZIP-family, OLE, PDF, executable or script attachment is reported here as exactly that, so an encrypted or password-protected file
is stopped by the blocker of its type until Phase C can say more.

CONSERVATIVE BY CONSTRUCTION. Anything the metadata cannot positively identify is a blocker, never clean: a part with no first bytes, an unrecognised type, a missing or malformed From, a missing
language or coverage flag, an unrecognised parse flag. A remote, hot-linked image is NOT a blocker (it has no pixels to decode and is not a part of the message): it is not an input at all, and a
`remote_image_count` flag, if given, is ignored.
"""
from __future__ import annotations

from typing import Any

MAGIC_BYTES_USED = 16  # the caller supplies at most this many leading bytes; the function never looks past them

# The codes this module can return: a subset of backend/tests/fixtures/blocker_codes_frozen.json (a test pins it). `unknown_finding_code` belongs to the tier function, not to this module.
QR = "qr_not_decoded"
INLINE_IMAGE = "inline_image_not_decoded"
DATA_IMAGE = "data_uri_image_not_decoded"
ACTIVE = "static_analysis_off"
HTML = "html_attachment_unanalysed"
CONTAINER = "archive_contents_unexamined"
NESTED = "nested_message_unexamined"
CALENDAR = "calendar_invite_unexamined"
REDIRECTS = "redirects_not_resolved"
SHARED = "shared_platform"
INTERNAL = "internal_host_not_sent"
LANGUAGE = "language_unsupported"
NO_TEXT = "no_readable_text"
NO_HOP = "no_trusted_receiver_hop"
FROM_UNPARSEABLE = "from_header_unparseable"
PARSE_FAILURE, PARSE_LIMIT, PARSE_TIMEOUT = "parse_failure", "parse_limit", "parse_timeout"
DERIVABLE_CODES = frozenset({QR, INLINE_IMAGE, DATA_IMAGE, ACTIVE, HTML, CONTAINER, NESTED, CALENDAR, REDIRECTS, SHARED, INTERNAL, LANGUAGE, NO_TEXT, NO_HOP, FROM_UNPARSEABLE,
                             PARSE_FAILURE, PARSE_LIMIT, PARSE_TIMEOUT})

# The closed enum of `detail` values (pinned by tests/fixtures/blocker_details_frozen.json; the V1 word ban applies). Each is content-free and attaches only to the codes the snapshot lists.
PARSE_FAILURE_DETAILS = ("body_extract_failed", "attachment_read_failed", "header_parse_failed", "mime_structure_error")  # also the parser's structured flag codes
DETAILS = frozenset({"pdf", "office_legacy", "office_zip", "executable", "script", "shortcut", "unknown_type", "no_first_bytes", "archive", "disk_image", "rfc822", "outlook_msg",
                     "not_configured", "no_matching_hop", "missing", "malformed", "unrecognised_flag", *PARSE_FAILURE_DETAILS})


def blocker_codes(items: Any) -> list[str]:
    """The plain sorted list of unique codes of a list of items (what compute_tier takes as `blockers`)."""
    return sorted({item["code"] for item in items})


def _item(code: str, detail: str | None = None) -> tuple[str, str | None]:
    return (code, detail)


# The flags a caller must supply with every message. A missing or None value is read conservatively (as a blocker); these are the values that raise none.
NO_BLOCKING_FLAGS: dict[str, Any] = {
    "data_image_count": 0,
    "from_address": "someone@example.com",
    "parse_flags": [],
    "language_status": "supported",
    "unresolved_redirects": 0,
    "shared_platform_links_unexamined": 0,
    "internal_hosts": 0,
    "trusted_receiver_hop_present": True,
    "trusted_receivers_configured": True,  # optional: when the hop is absent it tells `not_configured` from `no_matching_hop`
}

# a structured parse flag's code -> (blocker code, detail). parse_limit and parse_timeout have no producer yet: no parser limit or timeout exists (see the parser docstrings), so they stay unreachable.
_PARSE_CODES = {"parse_failure": (PARSE_FAILURE, None), "parse_limit": (PARSE_LIMIT, None), "parse_timeout": (PARSE_TIMEOUT, None),
                **{name: (PARSE_FAILURE, name) for name in PARSE_FAILURE_DETAILS}}
# type families
_IMAGE, _PDF, _OLE, _ZIP, _RAR, _7Z, _GZIP, _EXECUTABLE, _SHORTCUT, _CALENDAR, _MESSAGE, _HTML, _SCRIPT, _UNKNOWN = (
    "image", "pdf", "ole", "zip", "rar", "7z", "gzip", "executable", "shortcut", "calendar", "message", "html", "script", "unknown")
_MESSAGE_HEADERS = (b"from:", b"received:", b"return-path:", b"mime-version:", b"message-id:", b"date:", b"subject:", b"to:", b"delivered-to:", b"x-", b"from ")
_HTML_STARTS = (b"<!doctype html", b"<html", b"<head", b"<body", b"<svg", b"<meta", b"<title", b"<form", b"<table", b"<div", b"<iframe", b"<style", b"<?xml", b"<a ", b"<p>")
_SCRIPT_STARTS = (b"<script", b"#!", b"<?php", b"<%")
_SCRIPT_EXTENSIONS = (".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".sh", ".py", ".jar", ".msi", ".scr", ".com", ".exe", ".dll", ".lnk")
_OFFICE_EXTENSIONS = (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".doc", ".xls", ".ppt", ".rtf", ".odt")
_DISK_IMAGE_EXTENSIONS = (".iso", ".img", ".dmg", ".vhd", ".vhdx", ".vmdk")
_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico")
_ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab", ".arj", ".z")


def _ext(name: Any) -> str:
    if not isinstance(name, str) or "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1].strip().lower()


def _leading_text(head: bytes) -> bytes:
    start = head[3:] if head.startswith(b"\xef\xbb\xbf") else head
    return start.lstrip(b" \t\r\n\x00").lower()


def _family(head: bytes) -> str:
    """The type family from the first bytes alone (the magic number). `unknown` when nothing is recognised."""
    if head.startswith(b"\x89PNG\r\n\x1a\n") or head.startswith(b"\xff\xd8\xff") or head[:6] in (b"GIF87a", b"GIF89a"):
        return _IMAGE
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return _IMAGE
    if len(head) >= 10 and head[:2] == b"BM" and head[6:10] == b"\x00\x00\x00\x00":
        return _IMAGE
    if head.startswith(b"%PDF"):
        return _PDF
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _OLE
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _ZIP
    if head.startswith(b"Rar!\x1a\x07"):
        return _RAR
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return _7Z
    if head.startswith(b"\x1f\x8b"):
        return _GZIP
    if head.startswith(b"\x7fELF") or head.startswith(b"MZ"):
        return _EXECUTABLE
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return _SHORTCUT
    text = _leading_text(head)
    if text.startswith(b"begin:vcalendar"):
        return _CALENDAR
    if any(text.startswith(h) for h in _SCRIPT_STARTS):
        return _SCRIPT
    if any(text.startswith(h) for h in _HTML_STARTS):
        return _HTML
    if any(text.startswith(h) for h in _MESSAGE_HEADERS):
        return _MESSAGE
    return _UNKNOWN


def _part_items(part: Any) -> set[tuple[str, str | None]]:
    if not isinstance(part, dict):
        return {_item(ACTIVE, "unknown_type")}  # a part we cannot even describe is not examined
    name, declared = part.get("filename"), part.get("content_type")
    ext = _ext(name)
    declared = declared.lower() if isinstance(declared, str) else ""
    raw = part.get("first_bytes")
    head = bytes(raw[:MAGIC_BYTES_USED]) if isinstance(raw, (bytes, bytearray, memoryview)) else None
    if head is None or (len(head) == 0 and part.get("size") != 0):
        return {_item(ACTIVE, "no_first_bytes")}  # no first bytes: nothing was identified, so nothing was examined
    if len(head) == 0:
        return set()  # a part of size 0 carries nothing to examine
    family = _family(head)
    items: set[tuple[str, str | None]] = set()
    if family == _IMAGE:
        items.add(_item(INLINE_IMAGE if part.get("inline") else QR))
    elif family == _PDF:
        items.add(_item(ACTIVE, "pdf"))
    elif family == _EXECUTABLE:
        items.add(_item(ACTIVE, "executable"))
    elif family == _SHORTCUT:
        items.add(_item(ACTIVE, "shortcut"))
    elif family == _SCRIPT:
        items.add(_item(ACTIVE, "script"))
    elif family == _OLE:
        items.add(_item(ACTIVE, "office_legacy"))
        if ext == ".msg" or "ms-outlook" in declared:
            items.add(_item(NESTED, "outlook_msg"))  # an OLE container cannot be told from a message by its magic: the declared name or type refines it
    elif family == _ZIP:
        items.add(_item(CONTAINER, "archive"))
        if ext in _OFFICE_EXTENSIONS:
            items.add(_item(ACTIVE, "office_zip"))  # a ZIP may be an Office file with macros: the declared name adds, never removes
    elif family in (_RAR, _7Z, _GZIP):
        items.add(_item(CONTAINER, "archive"))
    elif family == _HTML:
        items.add(_item(HTML))
    elif family == _MESSAGE:
        items.add(_item(NESTED, "rfc822"))
    elif family == _CALENDAR:
        items.add(_item(CALENDAR))
    else:
        # no recognisable magic: the declared name and type are the only hints, and they can only add; an unrecognised part is conservative
        if ext in _DISK_IMAGE_EXTENSIONS:
            items.add(_item(CONTAINER, "disk_image"))
        elif ext in _ARCHIVE_EXTENSIONS:
            items.add(_item(CONTAINER, "archive"))
        elif ext == ".ics" or "calendar" in declared:
            items.add(_item(CALENDAR))
        elif ext == ".msg":
            items.add(_item(NESTED, "outlook_msg"))
        elif ext == ".eml" or "rfc822" in declared:
            items.add(_item(NESTED, "rfc822"))
        elif ext in _IMAGE_EXTENSIONS or declared.startswith("image/"):
            items.add(_item(INLINE_IMAGE if part.get("inline") else QR))
        elif ext in (".htm", ".html", ".xhtml", ".svg") or "html" in declared:
            items.add(_item(HTML))
        else:
            items.add(_item(ACTIVE, "unknown_type"))
    return items


def _count_positive(value: Any) -> bool:
    """True when a count flag says there is something (or when it is missing or not a number: unknown is a blocker)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return True
    return value > 0


def derive_blockers(parts: Any, parsed_flags: Any) -> list[dict[str, str | None]]:
    """Blocker items derivable from metadata only (see the module docstring): a sorted list of unique {"code", "detail"} items, codes from the frozen vocabulary, details from DETAILS or None."""
    found: set[tuple[str, str | None]] = set()
    flags = parsed_flags if isinstance(parsed_flags, dict) else {}
    for part in parts if isinstance(parts, (list, tuple)) else [None]:
        found |= _part_items(part)

    if _count_positive(flags.get("data_image_count")):
        found.add(_item(DATA_IMAGE))

    address = flags.get("from_address")
    if not isinstance(address, str) or not address:
        found.add(_item(FROM_UNPARSEABLE, "missing"))
    elif address.count("@") != 1 or any(ch.isspace() for ch in address) or not address.partition("@")[0] or not address.partition("@")[2]:
        found.add(_item(FROM_UNPARSEABLE, "malformed"))

    parse_flags = flags.get("parse_flags")
    if not isinstance(parse_flags, (list, tuple)):
        found.add(_item(PARSE_FAILURE, "unrecognised_flag"))
    else:
        for flag in parse_flags:
            code = flag.get("code") if isinstance(flag, dict) else None
            found.add(_item(*_PARSE_CODES.get(code, (PARSE_FAILURE, "unrecognised_flag"))))  # an unrecognised flag is read as a failure

    language = flags.get("language_status")
    if language in ("supported", "undetermined"):
        pass  # an undetermined language is a partial check today, not a blocker (the coverage report does not block on it)
    elif language == "none":
        found.add(_item(NO_TEXT))
    else:
        found.add(_item(LANGUAGE))  # unsupported, unrecognised or missing

    if _count_positive(flags.get("unresolved_redirects")):
        found.add(_item(REDIRECTS))
    if _count_positive(flags.get("shared_platform_links_unexamined")):
        found.add(_item(SHARED))
    if _count_positive(flags.get("internal_hosts")):
        found.add(_item(INTERNAL))
    if flags.get("trusted_receiver_hop_present") is not True:
        configured = flags.get("trusted_receivers_configured")
        found.add(_item(NO_HOP, "not_configured" if configured is False else ("no_matching_hop" if configured is True else None)))
    return [{"code": code, "detail": detail} for code, detail in sorted(found, key=lambda item: (item[0], item[1] or ""))]
