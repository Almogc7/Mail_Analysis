"""The adapter from a real analysis to derive_blockers (app/blockers_adapter.py): pure, not called by the pipeline."""
import ast
from pathlib import Path

from app.blockers import blocker_codes
from app.blockers_adapter import blocker_inputs, derive_message_blockers
from app.contracts.analysis import CoverageItem
from app.contracts.email import Attachment, EmailAddress, ParsedEmail, UnlistedPart
from app.contracts.findings import ModuleResult

BACKEND = Path(__file__).resolve().parents[1]
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def _parsed(**over) -> ParsedEmail:
    base = dict(source_format="eml", from_=EmailAddress(address="sender@example.com", domain="example.com"), raw_size_bytes=1)
    base.update(over)
    return ParsedEmail(**base)


def _attachment(first_bytes=PNG, filename="a.dat", inline=False, size=100) -> Attachment:
    return Attachment(filename=filename, content_type="application/octet-stream", size_bytes=size, sha256="0" * 64, sha1="0" * 40, md5="0" * 32, is_inline=inline, first_bytes=first_bytes)


def _content(status="supported") -> ModuleResult:
    return ModuleResult(module="content_analysis", status="ok", findings=[], raw_data={"language": {"status": status}})


def _item(reason, blocks=True) -> CoverageItem:
    return CoverageItem(area="x", status="not_checked", reason=reason, blocks_no_indicators=blocks, how_to_clear="")


def test_attachments_and_unlisted_parts_become_parts_with_their_first_bytes_and_inline_flag():
    parsed = _parsed(attachments=[_attachment(PNG, "a.dat")], unlisted_parts=[UnlistedPart(content_type="image/png", size_bytes=20, is_inline=True, has_content_id=True, first_bytes=PNG)])
    parts, _flags = blocker_inputs(parsed, [_content()], [])
    assert [(p["part_id"], p["filename"], p["first_bytes"], p["inline"]) for p in parts] == [("attachment:0", "a.dat", PNG, False), ("part:0", None, PNG, True)]


def test_the_flags_carry_the_parser_metadata_and_the_language():
    from app.contracts.email import ParseFlag

    parsed = _parsed(data_image_count=2, parse_flags=[ParseFlag(code="header_parse_failed", part_id="header:date")])
    _parts, flags = blocker_inputs(parsed, [_content("none")], [])
    assert flags["data_image_count"] == 2 and flags["from_address"] == "sender@example.com" and flags["language_status"] == "none"
    assert flags["parse_flags"] == [{"code": "header_parse_failed", "part_id": "header:date"}]


def test_the_two_receiver_reasons_map_to_not_configured_and_no_matching_hop():
    not_configured = derive_message_blockers(_parsed(), [_content()], [_item("no_trusted_receivers_configured")])
    assert {(i["code"], i["detail"]) for i in not_configured} == {("no_trusted_receiver_hop", "not_configured")}
    no_match = derive_message_blockers(_parsed(), [_content()], [_item("no_trusted_receiver_hop")])
    assert {(i["code"], i["detail"]) for i in no_match} == {("no_trusted_receiver_hop", "no_matching_hop")}
    assert derive_message_blockers(_parsed(), [_content()], [_item("evaluated_by_trusted_receiver", blocks=False)]) == []


def test_the_coverage_blocking_reasons_become_their_codes_and_a_non_blocking_item_adds_nothing():
    items = [_item("redirects_not_resolved"), _item("shared_platform"), _item("internal_host_not_sent"), _item("images_not_examined", blocks=False)]
    assert blocker_codes(derive_message_blockers(_parsed(), [_content()], items)) == ["internal_host_not_sent", "redirects_not_resolved", "shared_platform"]


def test_a_content_module_that_did_not_run_is_read_conservatively():
    assert blocker_codes(derive_message_blockers(_parsed(), [], [])) == ["language_unsupported"]
    assert blocker_codes(derive_message_blockers(_parsed(), [ModuleResult(module="content_analysis", status="error", findings=[])], [])) == ["language_unsupported"]


def test_first_bytes_that_did_not_survive_a_json_round_trip_are_read_conservatively_never_as_clean():
    parsed = _parsed(attachments=[_attachment(PNG, "a.dat")])
    rebuilt = ParsedEmail.model_validate_json(parsed.model_dump_json())  # first_bytes is excluded from serialisation, so it is gone
    assert rebuilt.attachments[0].first_bytes == b""
    assert blocker_codes(derive_message_blockers(rebuilt, [_content()], [])) == ["static_analysis_off"]
    assert blocker_codes(derive_message_blockers(parsed, [_content()], [])) == ["qr_not_decoded"]


def test_an_older_parsed_email_without_the_new_fields_still_works():
    class Old:
        attachments = []
        from_ = EmailAddress(address="sender@example.com")

    assert derive_message_blockers(Old(), [_content()], []) == []
    parts, flags = blocker_inputs(Old(), [_content()], [])
    assert parts == [] and flags["data_image_count"] == 0 and flags["parse_flags"] == []


def test_the_adapter_is_pure_and_only_the_v2_input_builder_calls_it():
    tree = ast.parse((BACKEND / "app" / "blockers_adapter.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "typing", "app.blockers"}, imported
    assert "blockers_adapter" in (BACKEND / "app" / "scoring" / "v2_inputs.py").read_text(encoding="utf-8")  # the one intended caller: the verdict v2 input builder
    for path in sorted((BACKEND / "app").rglob("*.py")):
        if path.name in ("blockers.py", "blockers_adapter.py", "v2_inputs.py"):
            continue
        source = path.read_text(encoding="utf-8")
        assert "blockers_adapter" not in source and "from app.blockers" not in source and "import blockers" not in source, path
