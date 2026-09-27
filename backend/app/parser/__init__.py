from app.parser.eml_parser import parse_eml
from app.parser.msg_parser import parse_msg
from app.parser.normalize import to_parsed_email


def parse_email_file(raw_bytes: bytes, filename: str) -> "ParsedEmail":  # noqa: F821
    """Dispatch to the right format-specific parser based on file extension, then normalize."""
    from app.contracts.email import ParsedEmail  # local import avoids a cycle at module load

    if filename.lower().endswith(".msg"):
        raw = parse_msg(raw_bytes)
    else:
        raw = parse_eml(raw_bytes)
    result: ParsedEmail = to_parsed_email(raw)
    return result


__all__ = ["parse_eml", "parse_msg", "to_parsed_email", "parse_email_file"]
