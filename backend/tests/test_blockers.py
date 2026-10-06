"""Metadata-level blocker detection (app/blockers.py; docs/DESIGN_V2.md 2.3; codes in tests/fixtures/blocker_codes_frozen.json).

The function reads only metadata the caller supplies (declared name and type, size, at most 16 first bytes, counts and flags). Nothing here opens or parses a file: the inputs are bytes literals.
Phase C (encryption flags, anything that needs structure parsing) is NOT derived, and nothing is lost for T4: an unexamined active or container type already blocks it, which the tests below pin."""
import ast
import copy
import json
from pathlib import Path

import pytest

from app import blockers as B
from app.blockers import DERIVABLE_CODES, NO_BLOCKING_FLAGS, derive_blockers

BACKEND = Path(__file__).resolve().parents[1]
FROZEN = json.loads((BACKEND / "tests" / "fixtures" / "blocker_codes_frozen.json").read_text(encoding="utf-8"))["codes"]

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00"
GIF = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff"
BMP = b"BM\x36\x00\x0c\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00"
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 "
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00"
ZIP = b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00"
RAR = b"Rar!\x1a\x07\x01\x00\xcf\x90s\x00\x00\r\x00\x00"
SEVENZ = b"7z\xbc\xaf\x27\x1c\x00\x04\x8d\x9b\xd5\x0f\x00\x00\x00\x00"
GZIP = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xed\xbd\x07\x60"
ELF = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
PE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
LNK = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
HTML_TEXT = b"<!DOCTYPE html>\n<html>"
HTML_BOM = b"\xef\xbb\xbf  \r\n<html lang"
SCRIPT_TEXT = b"<script>var x=1;"
SHEBANG = b"#!/bin/sh\necho hi\n"
MESSAGE_TEXT = b"Received: from mx"
CALENDAR_TEXT = b"BEGIN:VCALENDAR\r\nVER"
PLAIN = b"Hello, here is the"


def part(first_bytes, filename="file.bin", content_type=None, size=1000, inline=False):
    return {"part_id": "p1", "filename": filename, "content_type": content_type, "size": size, "first_bytes": first_bytes, "inline": inline}


def flags(**over):
    out = copy.deepcopy(NO_BLOCKING_FLAGS)
    out.update(over)
    return out


def codes_of(*parts, **flag_over):
    return derive_blockers(list(parts), flags(**flag_over))


def test_a_message_with_nothing_unexamined_has_no_blocker():
    assert derive_blockers([], flags()) == []
    assert codes_of(part(b"", size=0)) == []  # a part of size 0 carries nothing to examine


# ---- one test per blocker code derivable in this step -------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("magic", [PNG, JPEG, GIF, BMP, WEBP])
def test_an_image_attachment_gives_qr_not_decoded(magic):
    assert codes_of(part(magic, "pic.dat")) == ["qr_not_decoded"]


@pytest.mark.parametrize("magic", [PNG, JPEG, GIF, BMP, WEBP])
def test_an_inline_cid_image_gives_inline_image_not_decoded(magic):
    assert codes_of(part(magic, "logo.dat", inline=True)) == ["inline_image_not_decoded"]


def test_data_image_sources_give_data_uri_image_not_decoded():
    assert codes_of(data_image_count=1) == ["data_uri_image_not_decoded"]
    assert codes_of(data_image_count=0) == []


@pytest.mark.parametrize("magic", [PDF, OLE, PE, ELF, LNK, SCRIPT_TEXT, SHEBANG])
def test_an_active_type_gives_static_analysis_off(magic):
    assert codes_of(part(magic, "doc.dat")) == ["static_analysis_off"]


def test_an_office_file_in_a_zip_by_its_declared_name_adds_static_analysis_off_to_the_container_blocker():
    assert codes_of(part(ZIP, "report.docm")) == ["archive_contents_unexamined", "static_analysis_off"]


def test_an_html_attachment_gives_html_attachment_unanalysed_even_after_a_bom_and_whitespace():
    assert codes_of(part(HTML_TEXT, "page.dat")) == ["html_attachment_unanalysed"]
    assert codes_of(part(HTML_BOM, "page.dat")) == ["html_attachment_unanalysed"]


@pytest.mark.parametrize("magic", [ZIP, RAR, SEVENZ, GZIP])
def test_an_archive_gives_archive_contents_unexamined(magic):
    assert codes_of(part(magic, "x.dat")) == ["archive_contents_unexamined"]


@pytest.mark.parametrize("name", ["backup.iso", "disk.vhd", "setup.img"])
def test_a_disk_image_by_its_declared_name_gives_archive_contents_unexamined(name):
    assert codes_of(part(b"\x00" * 16, name)) == ["archive_contents_unexamined"]  # the magic of a disk image is not in the first 16 bytes


def test_a_nested_message_gives_nested_message_unexamined_by_text_by_declared_type_and_for_an_ole_msg():
    assert codes_of(part(MESSAGE_TEXT, "m.dat")) == ["nested_message_unexamined"]
    assert codes_of(part(b"\x00" * 16, "m.eml", "message/rfc822")) == ["nested_message_unexamined"]
    assert codes_of(part(OLE, "mail.msg")) == ["nested_message_unexamined", "static_analysis_off"]  # an OLE container is also an unexamined active type


def test_a_calendar_invite_gives_calendar_invite_unexamined():
    assert codes_of(part(CALENDAR_TEXT, "invite.dat")) == ["calendar_invite_unexamined"]
    assert codes_of(part(b"\x00" * 16, "invite.ics", "text/calendar")) == ["calendar_invite_unexamined"]


def test_the_existing_coverage_flags_give_their_codes():
    assert codes_of(unresolved_redirects=2) == ["redirects_not_resolved"]
    assert codes_of(shared_platform_links_unexamined=1) == ["shared_platform"]
    assert codes_of(internal_hosts=1) == ["internal_host_not_sent"]
    assert codes_of(trusted_receiver_hop_present=False) == ["no_trusted_receiver_hop"]
    assert codes_of(language_status="unsupported") == ["language_unsupported"]
    assert codes_of(language_status="none") == ["no_readable_text"]


def test_an_undetermined_language_is_not_a_blocker_as_in_the_coverage_report_today():
    assert codes_of(language_status="undetermined") == []


@pytest.mark.parametrize("address", [None, "", "no-at-sign", "two@@signs.example", "a@b@c.example", "spaced out@example.com", "@example.com", "user@"])
def test_a_missing_or_malformed_from_gives_from_header_unparseable(address):
    assert codes_of(from_address=address) == ["from_header_unparseable"]


def test_structured_parse_flags_give_failure_limit_and_timeout():
    for code in ("parse_failure", "parse_limit", "parse_timeout"):
        assert codes_of(parse_flags=[{"code": code, "part_id": "p2"}]) == [code]
    assert codes_of(parse_flags=[{"code": "parse_limit", "part_id": "a"}, {"code": "parse_timeout", "part_id": "b"}]) == ["parse_limit", "parse_timeout"]


def test_an_unrecognised_parse_flag_is_read_as_a_failure():
    assert codes_of(parse_flags=[{"code": "something_new", "part_id": "p"}]) == ["parse_failure"]


# ---- a renamed file is caught: the magic number wins over the extension ------------------------------------------------------------------------------------------------

def test_an_exe_renamed_pdf_is_an_active_executable_not_a_document():
    assert codes_of(part(PE, "invoice.pdf", "application/pdf")) == ["static_analysis_off"]


def test_an_html_file_renamed_txt_is_an_html_attachment():
    assert codes_of(part(HTML_TEXT, "notes.txt", "text/plain")) == ["html_attachment_unanalysed"]


def test_a_pdf_renamed_png_is_an_active_type_and_not_an_image():
    assert codes_of(part(PDF, "photo.png", "image/png")) == ["static_analysis_off"]


def test_a_zip_renamed_jpg_is_a_container_and_not_an_image():
    assert codes_of(part(ZIP, "holiday.jpg", "image/jpeg")) == ["archive_contents_unexamined"]


def test_a_png_renamed_exe_is_an_image_by_its_magic():
    assert codes_of(part(PNG, "setup.exe")) == ["qr_not_decoded"]


def test_a_script_renamed_txt_by_its_leading_text_is_active():
    assert codes_of(part(SHEBANG, "readme.txt", "text/plain")) == ["static_analysis_off"]


# ---- a remote image is not a blocker ----------------------------------------------------------------------------------------------------------------------------------------

def test_a_remote_hot_linked_image_is_not_a_blocker():
    assert derive_blockers([], flags(remote_image_count=7)) == []
    assert codes_of(part(b"", size=0), remote_image_count=3) == []


# ---- conservative: anything unknown is a blocker, never clean -----------------------------------------------------------------------------------------------------------------

def test_a_part_without_first_bytes_or_with_an_unrecognised_type_is_a_blocker():
    assert codes_of(part(None)) == ["static_analysis_off"]
    assert codes_of(part(b"", size=None)) == ["static_analysis_off"]
    assert codes_of(part("not bytes")) == ["static_analysis_off"]
    assert codes_of(part(PLAIN, "notes.txt", "text/plain")) == ["static_analysis_off"]  # plain text is not positively identified as inert from 16 bytes
    assert codes_of(None) == ["static_analysis_off"]  # a part list that is not a list
    assert codes_of({"not": "a part"}) == ["static_analysis_off"]


def test_a_missing_flag_is_read_conservatively():
    assert derive_blockers([], {}) == sorted(["data_uri_image_not_decoded", "from_header_unparseable", "parse_failure", "language_unsupported", "redirects_not_resolved",
                                              "shared_platform", "internal_host_not_sent", "no_trusted_receiver_hop"])
    assert derive_blockers([], None)  # not even a dict: everything is unknown
    assert codes_of(language_status="klingon") == ["language_unsupported"]
    assert codes_of(internal_hosts=True) == ["internal_host_not_sent"]  # a boolean is not a count


def test_only_the_first_16_bytes_are_used_and_a_longer_input_is_capped():
    assert derive_blockers([part(PDF + b"x" * 100)], flags()) == derive_blockers([part(PDF)], flags()) == ["static_analysis_off"]
    assert codes_of(part(b"x" * 20 + b"%PDF-1.7")) == ["static_analysis_off"]  # the magic is not at the start: unknown, and unknown is a blocker too
    assert B.MAGIC_BYTES_USED == 16


# ---- nothing is lost for T4: Phase C types are stopped by the type blocker ------------------------------------------------------------------------------------------------------

def test_an_encrypted_or_password_protected_file_is_stopped_by_its_type_until_phase_c():
    encrypted_zip = b"PK\x03\x04\x14\x00\x01\x00\x08\x00\x00\x00\x00\x00"  # general-purpose flag bit 0 set: encrypted. Not read: only the magic is
    assert codes_of(part(encrypted_zip, "secret.zip")) == ["archive_contents_unexamined"]
    assert codes_of(part(PDF, "locked.pdf")) == ["static_analysis_off"]
    assert codes_of(part(OLE, "locked.xls")) == ["static_analysis_off"]
    assert not set(FROZEN) - DERIVABLE_CODES - {"unknown_finding_code"}, "every frozen blocker code except the tier function's own is derivable here"


# ---- the vocabulary is the frozen one ---------------------------------------------------------------------------------------------------------------------------------------

def test_every_code_returned_is_in_the_frozen_table_and_every_derivable_code_is_reachable():
    inputs = [
        [part(PNG)], [part(PNG, inline=True)], [part(PDF)], [part(HTML_TEXT)], [part(ZIP, "a.docx")], [part(MESSAGE_TEXT)], [part(CALENDAR_TEXT)], [part(None)],
    ]
    reached: set[str] = set()
    for parts in inputs:
        reached |= set(derive_blockers(parts, flags()))
    for over in (dict(data_image_count=2), dict(from_address=None), dict(parse_flags=[{"code": "parse_failure", "part_id": "x"}]), dict(parse_flags=[{"code": "parse_limit", "part_id": "x"}]),
                 dict(parse_flags=[{"code": "parse_timeout", "part_id": "x"}]), dict(language_status="unsupported"), dict(language_status="none"), dict(unresolved_redirects=1),
                 dict(shared_platform_links_unexamined=1), dict(internal_hosts=1), dict(trusted_receiver_hop_present=False)):
        reached |= set(derive_blockers([], flags(**over)))
    assert reached == set(DERIVABLE_CODES)
    assert reached <= set(FROZEN)
    assert "unknown_finding_code" not in reached and DERIVABLE_CODES == set(FROZEN) - {"unknown_finding_code"}


def test_the_returned_list_is_sorted_and_has_no_duplicates():
    out = codes_of(part(PNG), part(PNG), part(PDF), part(PDF), data_image_count=3, from_address=None)
    assert out == sorted(set(out))


# ---- pure: no I/O, determinism, no mutation, not wired -------------------------------------------------------------------------------------------------------------------------

def test_the_module_imports_nothing_that_reads_files_or_the_network_and_calls_no_io():
    tree = ast.parse((BACKEND / "app" / "blockers.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "typing"}, imported  # no zipfile, olefile, tarfile, gzip, os, pathlib, io, socket, urllib, logging, time or random
    calls = {getattr(n.func, "id", getattr(n.func, "attr", "")) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"open", "print", "input", "exec", "eval", "read", "write", "getLogger", "urlopen", "listdir", "walk"}, calls


def test_the_function_is_deterministic_and_never_mutates_its_input():
    parts = [part(bytearray(PNG)), part(PDF, "a.pdf"), part(ZIP, "b.zip", inline=False)]
    parsed = flags(parse_flags=[{"code": "parse_limit", "part_id": "p9"}], data_image_count=1)
    before_parts, before_flags = copy.deepcopy(parts), copy.deepcopy(parsed)
    first = derive_blockers(parts, parsed)
    assert parts == before_parts and parsed == before_flags
    assert derive_blockers(copy.deepcopy(parts), copy.deepcopy(parsed)) == first == derive_blockers(parts, parsed)
    first.append("tampered")
    assert derive_blockers(parts, parsed) != first


def test_no_content_leaves_the_function_only_codes_from_the_vocabulary_are_returned():
    """The part list carries names and bytes; the output carries neither."""
    out = codes_of(part(PDF, "secret-merger-plan-q3.pdf", "application/pdf"), from_address="ceo@example.com")
    assert out == ["static_analysis_off"] and "merger" not in json.dumps(out)


def test_nothing_in_the_app_imports_the_blocker_module_yet_so_it_is_not_wired():
    for path in sorted((BACKEND / "app").rglob("*.py")):
        if path.name == "blockers.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[-1] != "blockers" and not any(a.name == "blockers" for a in node.names), path
            elif isinstance(node, ast.Import):
                assert not any(a.name.split(".")[-1] == "blockers" for a in node.names), path
