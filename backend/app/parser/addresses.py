"""Tolerant extraction of addresses from a raw address header (From, Reply-To, To, ...).

Python's strict RFC 5322 parser mis-reads headers that real mail (especially phishing) sends all the time,
most commonly an UNQUOTED display name containing a comma or other specials:

    From: PayPal, Inc. <support@evil.example.net>

It splits at the comma and the "address" it hands back is the fragment "PayPal", with no domain, so every
sender-based signal goes blind on that message. This module reads the header the way a mail client does:
the address is the one in angle brackets, and the display name is whatever precedes it.

No regexes: a small scanner tracks quotes, comments and angle brackets, so the behaviour is explicit.
`reasons` explains every way the header was not a clean single "Display <addr>" form. The result is
informational: ambiguity must never score by itself (a benign sender can have a sloppy header).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from email.header import decode_header, make_header

AMBIGUITY_PREFIX = "header_parse_ambiguity"
_TRIM = " \t\r\n,;"


@dataclass
class ParsedAddresses:
    addresses: list[tuple[str | None, str]] = field(default_factory=list)  # (display_name, addr_spec)
    reasons: list[str] = field(default_factory=list)

    @property
    def primary(self) -> tuple[str | None, str] | None:
        return self.addresses[0] if self.addresses else None

    @property
    def domains(self) -> list[str]:
        return [a.rsplit("@", 1)[-1].lower() for _, a in self.addresses]


def decode_words(text: str) -> str:
    """RFC 2047 encoded words -> text; the original string if it cannot be decoded."""
    if "=?" not in text:
        return text
    try:
        return str(make_header(decode_header(text)))
    except Exception:
        return text


def _scan(raw: str) -> tuple[list[tuple[str, int, int]], bool]:
    """Spans of quoted strings, comments and <angle> groups, plus whether anything was unterminated."""
    spans: list[tuple[str, int, int]] = []
    unterminated = False
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == '"':
            j = i + 1
            while j < n and raw[j] != '"':
                j += 2 if raw[j] == "\\" else 1
            if j >= n:  # no closing quote: an ordinary character, not a span that hides the rest of the header
                unterminated = True
                i += 1
                continue
            spans.append(("quote", i, j))
            i = j + 1
        elif ch == "(":
            depth, j = 1, i + 1
            while j < n and depth:
                if raw[j] == "\\":
                    j += 1
                elif raw[j] == "(":
                    depth += 1
                elif raw[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                unterminated = True
                i += 1
                continue
            spans.append(("comment", i, j - 1))
            i = j
        elif ch == "<":
            j = raw.find(">", i + 1)
            if j == -1:
                unterminated = True
                i += 1
                continue
            spans.append(("angle", i, j))
            i = j + 1
        else:
            i += 1
    return spans, unterminated


def _clean_addr(text: str) -> str | None:
    """A usable addr-spec from the inside of <...> or a bare token, else None."""
    text = text.strip().strip("<>").strip().strip(_TRIM)
    if text.count("@") < 1 or any(c.isspace() for c in text):
        return None
    local, _, domain = text.rpartition("@")
    domain = domain.strip(".>")
    if not local or not domain:
        return None
    return f"{local}@{domain}"


def _unquote(text: str) -> str:
    text = text.strip(_TRIM)
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        inner, out, i = text[1:-1], [], 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                i += 1
            out.append(inner[i])
            i += 1
        return "".join(out).strip()
    return text.replace('"', "").strip()


def _masked(raw: str, spans: list[tuple[str, int, int]]) -> str:
    """The header with quoted strings, comments and <angle> groups blanked: what is left is top-level text."""
    chars = list(raw)
    for _, start, end in spans:
        for k in range(start, min(end, len(chars) - 1) + 1):
            chars[k] = " "
    return "".join(chars)


def parse_address_header(raw: str | None) -> ParsedAddresses:
    result = ParsedAddresses()
    if raw is None or not raw.strip():
        result.reasons.append("empty header")
        return result
    raw = " ".join(raw.split())  # unfold
    spans, unterminated = _scan(raw)
    if unterminated:
        result.reasons.append("unbalanced quote, comment or angle bracket")
    top = _masked(raw, spans)

    angles = [s for s in spans if s[0] == "angle"]
    colon = top.find(":")
    if colon != -1:
        result.reasons.append("group syntax")

    if angles:
        previous_end = colon + 1 if colon != -1 else 0
        for index, (_, start, end) in enumerate(angles):
            address = _clean_addr(raw[start + 1 : end])
            display_raw = raw[previous_end:start]
            previous_end = end + 1
            if address is None:
                continue
            display = decode_words(_unquote(display_raw)) or None
            result.addresses.append((display, address))
            if index == 0 and "," in _masked(display_raw, _scan(display_raw)[0]):
                result.reasons.append("unquoted comma in the display name")
            elif index == 0 and any(c in _masked(display_raw, _scan(display_raw)[0]) for c in "@;"):
                result.reasons.append("unquoted special character in the display name")
    else:
        names = [raw[s + 1 : e] for k, s, e in spans if k == "comment"]
        for token in top.replace(",", " ").replace(";", " ").split():
            address = _clean_addr(token)
            if address:
                result.addresses.append((decode_words(names[len(result.addresses)].strip()) if len(result.addresses) < len(names) else None, address))

    if len(result.addresses) > 1:
        distinct = len(set(result.domains))
        result.reasons.append(f"multiple addresses ({len(result.addresses)}, {distinct} distinct domain{'s' if distinct != 1 else ''})")
    if not result.addresses:
        result.reasons.append("no address found")
    return result
