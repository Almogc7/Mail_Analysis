"""Adapter from a real analysis to the inputs of app/blockers.derive_blockers (docs/DESIGN_V2.md 2.3).

PURE and NOT CALLED BY THE PIPELINE: verdict_v2 does not exist yet. It takes explicit inputs (the ParsedEmail, the module results, the coverage report items) and returns the module's input or its
blocker items; it reads no configuration, files or network. The trusted-receiver configuration is read from the authentication module's recorded result (`trusted_receivers_configured`), exactly where the
coverage report reads it.

What it maps:
  * every attachment and every unlisted part (an inline cid: image, a nameless nested message or calendar part): declared name and type, size, the first bytes the parser kept, and whether it is inline;
  * the parser's metadata: the count of data: image sources, the parsed From address, the structured parse flags;
  * the coverage report's blocking reasons and the content language, which the app already holds, as the flags the module expects. The trusted-receiver row has two blocking reasons: nothing is trusted
    (`no_trusted_receivers_configured`, detail not_configured) and receivers are configured but none matched (`no_trusted_receiver_hop`, detail no_matching_hop).

A first_bytes value is held in memory only: a ParsedEmail rebuilt from JSON has none, and every part is then read conservatively (a blocker), never as clean.
"""
from __future__ import annotations

from typing import Any

from app.blockers import derive_blockers

_RECEIVER_REASONS = {"no_trusted_receiver_hop", "no_trusted_receivers_configured"}


def blocker_inputs(parsed: Any, module_results: list[Any], coverage_items: list[Any]) -> tuple[list[dict], dict]:
    """(parts, parsed_flags) for derive_blockers, from the parsed email, the module results and the coverage report items."""
    parts: list[dict] = []
    for index, attachment in enumerate(parsed.attachments):
        parts.append({"part_id": f"attachment:{index}", "filename": attachment.filename, "content_type": attachment.content_type, "size": attachment.size_bytes,
                      "first_bytes": attachment.first_bytes, "inline": attachment.is_inline})
    for index, part in enumerate(getattr(parsed, "unlisted_parts", []) or []):
        parts.append({"part_id": f"part:{index}", "filename": None, "content_type": part.content_type, "size": part.size_bytes, "first_bytes": part.first_bytes, "inline": part.is_inline})

    blocking_reasons = {item.reason for item in coverage_items if item.blocks_no_indicators}
    content = next((m for m in module_results if m.module == "content_analysis"), None)
    language = ((content.raw_data or {}).get("language") or {}).get("status") if content is not None and content.status == "ok" else None
    flags = {
        "data_image_count": getattr(parsed, "data_image_count", 0),
        "from_address": parsed.from_.address,
        "parse_flags": [{"code": flag.code, "part_id": flag.part_id} for flag in getattr(parsed, "parse_flags", []) or []],
        "language_status": language,
        "unresolved_redirects": 1 if "redirects_not_resolved" in blocking_reasons else 0,
        "shared_platform_links_unexamined": 1 if "shared_platform" in blocking_reasons else 0,
        "internal_hosts": 1 if "internal_host_not_sent" in blocking_reasons else 0,
        "trusted_receiver_hop_present": not (blocking_reasons & _RECEIVER_REASONS),
        "trusted_receivers_configured": "no_trusted_receivers_configured" not in blocking_reasons,
    }
    return parts, flags


def derive_message_blockers(parsed: Any, module_results: list[Any], coverage_items: list[Any]) -> list[dict]:
    """The blocker items of one analysis: derive_blockers over the adapter's inputs."""
    parts, flags = blocker_inputs(parsed, module_results, coverage_items)
    return derive_blockers(parts, flags)
