"""The read-only blocker-input report (scripts/report_blocker_inputs.py): aggregates only, no content, and the first-bytes simulation it uses to show what step 10 would unlock."""
import importlib.util
import json
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.blockers import blocker_codes, derive_blockers
from app.parser import parse_email_file
from tests import eval as ev

ROOT = Path(__file__).resolve().parents[2]
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 40


@pytest.fixture(scope="module")
def report_module():
    spec = importlib.util.spec_from_file_location("report_blocker_inputs", ROOT / "scripts" / "report_blocker_inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _message_with_png(path: Path) -> Path:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = "attachment test"
    msg.set_content("see attached")
    msg.add_attachment(PNG, maintype="image", subtype="png", filename="photo.dat")
    path.write_bytes(bytes(msg))
    return path


def test_the_first_bytes_come_from_the_attachment_payload_capped_at_16_and_drive_the_magic_number_detection(report_module, tmp_path):
    path = _message_with_png(tmp_path / "m.eml")
    parsed = parse_email_file(path.read_bytes(), path.name)
    heads = report_module.first_bytes_from_raw(path, len(parsed.attachments))
    assert heads is not None and len(heads) == 1 and len(heads[0]) == 16 and heads[0].startswith(b"\x89PNG")
    part = {"part_id": "a0", "filename": parsed.attachments[0].filename, "content_type": parsed.attachments[0].content_type, "size": parsed.attachments[0].size_bytes,
            "first_bytes": heads[0], "inline": parsed.attachments[0].is_inline}
    flags = {"data_image_count": 0, "from_address": parsed.from_.address, "parse_flags": [], "language_status": "supported", "unresolved_redirects": 0,
             "shared_platform_links_unexamined": 0, "internal_hosts": 0, "trusted_receiver_hop_present": True, "trusted_receivers_configured": True}
    assert blocker_codes(derive_blockers([part], flags)) == ["qr_not_decoded"]
    assert blocker_codes(derive_blockers([{**part, "first_bytes": None}], flags)) == ["static_analysis_off"]  # as exposed today: no first bytes, read conservatively


def test_the_simulation_is_skipped_when_the_attachment_count_does_not_match_or_the_file_is_not_an_eml(report_module, tmp_path):
    path = _message_with_png(tmp_path / "m.eml")
    assert report_module.first_bytes_from_raw(path, 5) is None
    other = tmp_path / "m.msg"
    other.write_bytes(path.read_bytes())
    assert report_module.first_bytes_from_raw(other, 1) is None


@pytest.mark.slow
def test_the_report_prints_aggregates_only_and_no_content(report_module):
    out = report_module.report()
    ev.apply_mode("configured")
    text = json.dumps(out)
    assert out["messages"] >= 7 and set(out["modes"]) == {"strict", "configured"}
    for mode in out["modes"].values():
        assert set(mode) == {"messages_with_any_blocker_today", "messages_with_any_blocker_with_first_bytes", "codes_today", "codes_with_first_bytes", "details_with_first_bytes",
                       "agreement_with_the_coverage_report"}
        assert all(isinstance(v, int) for v in mode["codes_today"].values())
    assert "not_exposed_by_the_parser_today" in out
    for fragment in ("kvish", ".eml", ".msg", "@", "http"):
        assert fragment not in text, f"the report must not carry {fragment!r}"


def test_the_script_is_not_imported_by_the_app():
    for path in sorted((ROOT / "backend" / "app").rglob("*.py")):
        assert "report_blocker_inputs" not in path.read_text(encoding="utf-8"), path


def _fixture(name):
    return ev.FIXTURES / name


def _receiver_blocker(report_module, fixture, mode):
    ev.apply_mode(mode)
    try:
        result = ev.analyze(_fixture(fixture), "clean")
        today, _sim, flags = report_module.build_inputs(result, _fixture(fixture))
        return flags, [(i["code"], i["detail"]) for i in derive_blockers(today, flags) if i["code"] == "no_trusted_receiver_hop"]
    finally:
        ev.apply_mode("configured")


def test_in_strict_no_receiver_is_trusted_so_every_message_gets_the_receiver_blocker_with_not_configured(report_module):
    for fixture in ("malicious/kvish6_invoice_phish.eml", "benign/synthetic/06_hebrew_newsletter_esp.eml", "benign/synthetic/02_safelinks_wrapped_internal.eml"):
        flags, found = _receiver_blocker(report_module, fixture, "strict")
        assert flags["trusted_receivers_configured"] is False and flags["trusted_receiver_hop_present"] is False, fixture
        assert found == [("no_trusted_receiver_hop", "not_configured")], fixture


def test_in_configured_a_message_whose_trusted_receiver_wrote_a_result_has_no_receiver_blocker_and_one_without_gets_no_matching_hop(report_module):
    flags, found = _receiver_blocker(report_module, "benign/synthetic/06_hebrew_newsletter_esp.eml", "configured")
    assert flags["trusted_receiver_hop_present"] is True and found == []
    flags, found = _receiver_blocker(report_module, "benign/synthetic/02_safelinks_wrapped_internal.eml", "configured")
    assert flags["trusted_receivers_configured"] is True and flags["trusted_receiver_hop_present"] is False
    assert found == [("no_trusted_receiver_hop", "no_matching_hop")]


@pytest.mark.slow
def test_the_report_counts_the_receiver_blocker_on_every_message_in_strict(report_module):
    out = report_module.report()
    ev.apply_mode("configured")
    assert out["modes"]["strict"]["codes_today"]["no_trusted_receiver_hop"] == out["messages"]
    assert 0 < out["modes"]["configured"]["codes_today"]["no_trusted_receiver_hop"] < out["messages"] / 4
