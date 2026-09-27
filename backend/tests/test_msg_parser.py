from pathlib import Path

import pytest

from app.parser.msg_parser import parse_msg
from app.parser.normalize import to_parsed_email

FIXTURES = Path(__file__).parent / "fixtures" / "samples"
SAMPLE_MSG = FIXTURES / "sample.msg"

pytestmark = pytest.mark.skipif(
    not SAMPLE_MSG.exists(),
    reason=(
        "No .msg fixture present. .msg files can't be easily synthesized in pure Python "
        "(OLE compound-file format) -- drop a real, sanitized sample at "
        "backend/tests/fixtures/samples/sample.msg (strip real PII/body content first) "
        "to exercise this test."
    ),
)


def test_msg_parses_without_crashing():
    raw_bytes = SAMPLE_MSG.read_bytes()
    parsed = to_parsed_email(parse_msg(raw_bytes))

    assert parsed.source_format == "msg"
    assert parsed.raw_size_bytes == len(raw_bytes)
