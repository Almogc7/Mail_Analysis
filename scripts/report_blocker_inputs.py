"""Read-only report (Phase B step 9): what the blocker module (app/blockers.py) would see, built from the existing parsed email, for the FIXTURES and the TUNING corpus only (never the hold-out).

    python scripts/report_blocker_inputs.py

It is NOT imported by the application and changes nothing. For every message it builds the module's input from what the parser exposes TODAY (the parsed attachments, the coverage report and the content
language), runs `derive_blockers`, and prints AGGREGATES only: counts per blocker code, and which inputs the parser does not expose yet. No file name, subject, address, URL or content is printed.

Two variants are counted. "today": the first bytes of an attachment are not exposed by the parser, so every attachment is read conservatively. "with first bytes": the script itself re-reads the raw
.eml with the standard library, takes the first 16 bytes of each attachment payload the way the parser selects attachments, and feeds them in, to show what the parser addition of step 10 would unlock.
Nothing is opened, decompressed or parsed beyond those 16 bytes. The hold-out is never read (tests.eval.collect never collects it).
"""
from __future__ import annotations

import collections
import email
import json
import logging
import sys
from email import policy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from bs4 import BeautifulSoup  # noqa: E402

from app.blockers import blocker_codes, derive_blockers  # noqa: E402
from app.coverage import build_coverage_report  # noqa: E402
from tests import eval as ev  # noqa: E402

ATTACHMENT_CODES = {"static_analysis_off", "html_attachment_unanalysed", "archive_contents_unexamined", "qr_not_decoded"}


def _img_sources(html: str | None) -> list[str]:
    if not html:
        return []
    return [str(img["src"]).strip().lower() for img in BeautifulSoup(html, "html.parser").find_all("img", src=True)]


def first_bytes_from_raw(path: Path, expected: int) -> list[bytes] | None:
    """The first 16 bytes of each attachment payload, selected as eml_parser.py selects them (an attachment or inline part with a filename). None if the count does not match the parsed one."""
    if path.suffix.lower() != ".eml":
        return None
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    heads: list[bytes] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() in ("attachment", "inline") and part.get_filename():
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            heads.append(bytes(payload[:16]))
    return heads if len(heads) == expected else None


def build_inputs(result, path: Path) -> tuple[list[dict], list[dict] | None, dict]:
    """(parts as exposed today, parts with simulated first bytes or None, the flags), from what the pipeline already holds."""
    parsed = result.parsed_email
    items = build_coverage_report(parsed, result.module_results)
    reasons = {i.reason for i in items if i.blocks_no_indicators}
    content = next((m for m in result.module_results if m.module == "content_analysis"), None)
    language = ((content.raw_data or {}).get("language") or {}).get("status") if content is not None else None
    sources = _img_sources(parsed.body_html)
    flags = {
        "data_image_count": sum(1 for s in sources if s.startswith("data:")),  # derivable from body_html today; the parser drops these sources and keeps no count
        "from_address": parsed.from_.address,
        "parse_flags": [],  # not exposed: the parser keeps only free-text parse_warnings
        "language_status": language,
        "unresolved_redirects": 1 if "redirects_not_resolved" in reasons else 0,
        "shared_platform_links_unexamined": 1 if "shared_platform" in reasons else 0,
        "internal_hosts": 1 if "internal_host_not_sent" in reasons else 0,
        # The coverage report gives the trusted-receiver row one of two blocking reasons when no method was evaluated by a trusted receiver: `no_trusted_receivers_configured` (nothing is trusted, as in STRICT)
        # and `no_trusted_receiver_hop` (receivers are configured but none matched). The first version of this adapter looked only for the second, so STRICT showed none (fixed in step 10).
        "trusted_receiver_hop_present": not (reasons & {"no_trusted_receiver_hop", "no_trusted_receivers_configured"}),
        "trusted_receivers_configured": "no_trusted_receivers_configured" not in reasons,
    }
    today = [{"part_id": f"a{i}", "filename": a.filename, "content_type": a.content_type, "size": a.size_bytes, "first_bytes": None, "inline": a.is_inline}
             for i, a in enumerate(parsed.attachments)]
    heads = first_bytes_from_raw(path, len(parsed.attachments))
    simulated = None if heads is None else [{**part, "first_bytes": heads[i]} for i, part in enumerate(today)]
    return today, simulated, flags


def report() -> dict:
    logging.getLogger("app").setLevel(logging.ERROR)
    items = ev.collect(None)
    out: dict = {"messages": len(items), "modes": {}}
    not_exposed = collections.Counter()
    for mode in ev.MODES:
        ev.apply_mode(mode)
        today_codes, fb_codes, fb_details = collections.Counter(), collections.Counter(), collections.Counter()
        any_today = any_fb = 0
        agree = collections.Counter()
        for path, _label, _source in items:
            result = ev.analyze(path, "clean")
            parsed = result.parsed_email
            today, simulated, flags = build_inputs(result, path)
            items_today = derive_blockers(today, flags)
            codes_today = blocker_codes(items_today)
            today_codes.update(codes_today)
            any_today += bool(codes_today)
            if simulated is not None:
                items_fb = derive_blockers(simulated, flags)
                codes_fb = blocker_codes(items_fb)
                fb_details.update(f"{i['code']}/{i['detail']}" for i in items_fb if i["detail"])
            else:
                codes_fb = codes_today if not today else None  # a message with attachments whose bytes cannot be simulated (.msg) is left out of this variant
            if codes_fb is not None:
                fb_codes.update(codes_fb)
                any_fb += bool(codes_fb)
                coverage_reasons = {i.reason for i in build_coverage_report(parsed, result.module_results) if i.blocks_no_indicators} & ATTACHMENT_CODES
                if (set(codes_fb) & ATTACHMENT_CODES) != coverage_reasons:
                    agree["messages_where_attachment_codes_differ_from_the_coverage_report"] += 1
                agree["messages_compared"] += 1
            if mode == ev.MODES[0]:  # the inputs the parser does not expose do not depend on the mode
                if parsed.attachments:
                    not_exposed["messages_with_attachments"] += 1
                    not_exposed["attachments_whose_first_bytes_are_not_exposed"] += len(parsed.attachments)
                    if path.suffix.lower() != ".eml":
                        not_exposed["messages_with_attachments_that_are_msg_files"] += 1
                sources = _img_sources(parsed.body_html)
                if any(s.startswith("data:") for s in sources):
                    not_exposed["messages_with_data_image_sources"] += 1
                    not_exposed["data_image_sources_dropped_by_the_parser"] += sum(1 for s in sources if s.startswith("data:"))
                if any(s.startswith("cid:") for s in sources):
                    not_exposed["messages_with_cid_images"] += 1
                    if not any(a.is_inline for a in parsed.attachments):
                        not_exposed["messages_with_cid_images_and_no_inline_part_recorded"] += 1
                if parsed.parse_warnings:
                    not_exposed["messages_with_free_text_parse_warnings"] += 1
                if not parsed.from_.address:
                    not_exposed["messages_with_no_parsed_from_address"] += 1
        out["modes"][mode] = {
            "messages_with_any_blocker_today": any_today,
            "messages_with_any_blocker_with_first_bytes": any_fb,
            "codes_today": dict(sorted(today_codes.items())),
            "codes_with_first_bytes": dict(sorted(fb_codes.items())),
            "details_with_first_bytes": dict(sorted(fb_details.items())),
            "agreement_with_the_coverage_report": dict(agree),
        }
    ev.apply_mode("configured")
    out["not_exposed_by_the_parser_today"] = dict(sorted(not_exposed.items()))
    return out


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(report(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
