"""ParsedEmail.data_image_count: how many <img> tags carry a data: source (a number, no content; additive)."""
import re
from email.message import EmailMessage

import pytest

from app.parser import parse_email_file
from app.parser.normalize import _count_data_images, _extract_images_from_html
from tests import eval as ev

DATA = "data:image/png;base64,iVBORw0KGgo="


def _parse(html: str):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "rcpt@example.com"
    msg["Subject"] = "data image test"
    msg.set_content("plain part")
    msg.add_alternative(html, subtype="html")
    return parse_email_file(bytes(msg), "m.eml")


@pytest.mark.parametrize("html, expected", [
    ("<p>no images</p>", 0),
    (f'<img src="{DATA}">', 1),
    (f'<img src="{DATA}"><img src="{DATA}">', 2),  # the same data source twice counts twice
    ('<img src="DATA:image/gif;base64,R0lGOD==">', 1),  # the scheme is case-insensitive
    ('<img src="  data:image/jpeg;base64,/9j/4AAQ">', 1),  # leading whitespace is stripped
    ('<img src="da\tta:image/png;base64,AAAA">', 1),  # control characters inside a URL are dropped, as the browsers do
    ('<img src="https://img.example/a.png"><img src="http://img.example/b.png">', 0),  # remote images are not counted
    ('<img src="cid:logo123">', 0),  # a cid: reference is not a data: source
    (f'<a href="{DATA}">link</a>', 0),  # not an image tag
    (f'<div style="background:url({DATA})"></div>', 0),  # CSS backgrounds are not counted (stated limitation)
    (f'<img src="https://img.example/a.png"><img src="{DATA}"><img src="cid:x">', 1),
])
def test_the_count_is_the_number_of_img_tags_with_a_data_source(html, expected):
    assert _count_data_images(html) == expected
    assert _parse(html).data_image_count == expected


def test_no_html_body_gives_zero():
    assert _count_data_images(None) == 0 and _count_data_images("") == 0


def test_the_images_list_still_holds_only_remote_images_and_is_unchanged():
    html = f'<img src="https://img.example/a.png" alt="x"><img src="{DATA}"><img src="cid:x"><img src="https://img.example/a.png">'
    images = _extract_images_from_html(html)
    assert [i.url for i in images] == ["https://img.example/a.png"]
    parsed = _parse(html)
    assert [i.url for i in parsed.images] == ["https://img.example/a.png"] and parsed.data_image_count == 1


def test_the_field_carries_only_a_number_never_the_source():
    parsed = _parse(f'<img src="{DATA}">')
    assert parsed.model_dump()["data_image_count"] == 1 and type(parsed.data_image_count) is int
    assert all("data:" not in image.url for image in parsed.images)  # the sources themselves are not copied anywhere new


def test_the_default_is_zero_so_an_older_parsed_email_still_builds():
    from app.contracts.email import EmailAddress, ParsedEmail

    assert ParsedEmail(source_format="eml", from_=EmailAddress(), raw_size_bytes=1).data_image_count == 0


def test_over_every_fixture_and_the_tuning_corpus_the_count_equals_an_independent_regex_count():
    tag = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*([\"'])\s*data:", re.IGNORECASE)
    total = 0
    for path, _label, _source in ev.collect(None):
        parsed = parse_email_file(path.read_bytes(), path.name)
        assert parsed.data_image_count == len(tag.findall(parsed.body_html or "")), "differs from the independent count"
        total += parsed.data_image_count
    assert total >= 1  # the corpus does contain a data: image (the step 9 report found one message)
