"""Named inline text remains body content and forensic attachment data."""

import base64
import json
import quopri

import pytest

import mailparser

_HEADERS = (
    b"Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n"
    b"From: alice@example.com\r\nTo: bob@example.com\r\n"
    b"MIME-Version: 1.0\r\n"
)


def _entity(content_type, disposition, payload, extra_headers=b""):
    headers = b"Content-Type: " + content_type + b"\r\n"
    if disposition is not None:
        headers += b"Content-Disposition: " + disposition + b"\r\n"
    return headers + extra_headers + b"\r\n" + payload


def _multipart(parts, boundary, disposition=None, subtype=b"mixed"):
    payload = (
        b"".join(b"--" + boundary + b"\r\n" + part + b"\r\n" for part in parts)
        + b"--"
        + boundary
        + b"--\r\n"
    )
    content_type = b"multipart/" + subtype + b"; boundary=" + boundary
    return _entity(content_type, disposition, payload)


@pytest.mark.parametrize("media_type", [b"text/plain", b"text/html"])
@pytest.mark.parametrize("name_source", ["filename", "name"])
def test_named_inline_text_and_attachment(media_type, name_source):
    """Explicit inline text gains a body view without changing metadata."""
    content_type = media_type
    disposition = b"inline"
    if name_source == "filename":
        disposition += b'; filename="note.txt"'
    else:
        content_type += b'; name="note.txt"'
    payload = b"hello" if media_type == b"text/plain" else b"<p>hello</p>"
    raw = _HEADERS + _entity(
        content_type,
        disposition,
        payload,
        b"Content-ID: <text@example.com>\r\n",
    )
    parsed = mailparser.parse_from_bytes(raw)

    assert parsed.attachments == [
        {
            "filename": "note.txt",
            "safe_filename": "note.txt",
            "payload": base64.b64encode(payload).decode("ascii"),
            "binary": True,
            "mail_content_type": media_type.decode("ascii"),
            "content-id": "<text@example.com>",
            "content-disposition": disposition.decode("ascii"),
            "charset": None,
            "content_transfer_encoding": "base64",
        }
    ]
    expected = [payload.decode("ascii")]
    assert parsed.text_plain == (expected if media_type == b"text/plain" else [])
    assert parsed.text_html == (expected if media_type == b"text/html" else [])
    assert parsed.body == payload.decode("ascii")
    assert parsed.has_defects is False
    assert json.loads(parsed.mail_json)["body"] == parsed.body


@pytest.mark.parametrize(
    ("disposition", "has_body", "has_attachment"),
    [
        (None, True, False),
        (b"inline", True, False),
        (b"x-custom", True, False),
        (b"attachment", False, True),
        (b'attachment; filename="note.txt"', False, True),
        (b'x-custom; filename="note.txt"', False, True),
    ],
)
def test_existing_disposition_controls(disposition, has_body, has_attachment):
    """The enhancement leaves existing unnamed and non-inline behavior."""
    parsed = mailparser.parse_from_bytes(
        _HEADERS + _entity(b"text/plain", disposition, b"hello")
    )

    assert parsed.body == ("hello" if has_body else "")
    assert bool(parsed.attachments) is has_attachment
    if has_attachment:
        assert base64.b64decode(parsed.attachments[0]["payload"]) == b"hello"


def test_name_without_inline_stays_attachment_only():
    """A legacy Content-Type name alone does not opt into body inclusion."""
    parsed = mailparser.parse_from_bytes(
        _HEADERS + _entity(b'text/plain; name="note.txt"', None, b"hello")
    )

    assert parsed.body == ""
    assert parsed.attachments[0]["filename"] == "note.txt"


@pytest.mark.parametrize(
    ("charset", "cte"),
    [
        ("utf-8", None),
        ("utf-8", "base64"),
        ("iso-8859-1", "quoted-printable"),
        ("iso-8859-1", "8bit"),
        ("iso-8859-1", "binary"),
    ],
)
def test_named_inline_decodes_once_as_body_and_keeps_bytes(charset, cte):
    """The ordinary body decoder handles transfer encoding and charset."""
    payload = "Caf\u00e9".encode(charset)
    wire = payload
    if cte == "base64":
        wire = base64.b64encode(payload)
    elif cte == "quoted-printable":
        wire = quopri.encodestring(payload)
    headers = (
        b"Content-Transfer-Encoding: " + cte.encode("ascii") + b"\r\n" if cte else b""
    )
    parsed = mailparser.parse_from_bytes(
        _HEADERS
        + _entity(
            b"text/plain; charset=" + charset.encode("ascii"),
            b'INLINE; filename="note.txt"',
            wire,
            headers,
        )
    )

    assert parsed.text_plain == ["Caf\u00e9"]
    assert base64.b64decode(parsed.attachments[0]["payload"]) == payload
    assert parsed.attachments[0]["charset"] == charset
    assert parsed.attachments[0]["content-disposition"] == (
        'INLINE; filename="note.txt"'
    )
    assert parsed.has_defects is False


def test_named_inline_unicode_string_input():
    """Already-decoded string input uses the same body path as before."""
    raw = _HEADERS + _entity(
        b"text/plain; charset=utf-8",
        b'inline; filename="note.txt"',
        "Caf\u00e9".encode(),
        b"Content-Transfer-Encoding: 8bit\r\n",
    )
    parsed = mailparser.parse_from_string(raw.decode("utf-8"))

    assert parsed.text_plain == ["Caf\u00e9"]
    assert len(parsed.attachments) == 1


@pytest.mark.parametrize(
    ("media_type", "disposition"),
    [
        (b"image/png", b"inline"),
        (b"image/png", b'inline; filename="image.png"'),
        (b"application/plain", b'inline; filename="sample.bin"'),
        (b"application/html", b'inline; filename="sample.bin"'),
    ],
)
def test_inline_binary_and_nontext_parts_remain_attachments(media_type, disposition):
    """Content-ID and text-like subtypes do not promote binary media."""
    payload = b"\x00\x80\xff\r\n"
    parsed = mailparser.parse_from_bytes(
        _HEADERS
        + _entity(
            media_type,
            disposition,
            base64.b64encode(payload),
            b"Content-ID: <image@example.com>\r\nContent-Transfer-Encoding: base64\r\n",
        )
    )

    assert parsed.body == ""
    assert parsed.text_plain == parsed.text_html == []
    assert len(parsed.attachments) == 1
    assert base64.b64decode(parsed.attachments[0]["payload"]) == payload
    assert parsed.attachments[0]["content-id"] == "<image@example.com>"


def test_nested_inline_siblings_and_explicit_attachment():
    """Collect nested inline text while retaining explicit text files."""
    plain = _entity(b"text/plain", b'inline; filename="body.txt"', b"plain body")
    html = _entity(b"text/html", b'inline; filename="body.html"', b"<p>html body</p>")
    attachment = _entity(
        b"text/plain", b'attachment; filename="private.txt"', b"private"
    )
    raw = _HEADERS + _multipart(
        [_multipart([plain, html], b"alternative", subtype=b"alternative"), attachment],
        b"outer",
    )
    parsed = mailparser.parse_from_bytes(raw)

    assert parsed.text_plain == ["plain body"]
    assert parsed.text_html == ["<p>html body</p>"]
    assert "private" not in parsed.body
    assert [a["filename"] for a in parsed.attachments] == [
        "body.txt",
        "body.html",
        "private.txt",
    ]
    assert base64.b64decode(parsed.attachments[2]["payload"]) == b"private"


@pytest.mark.parametrize("wrapper", ["multipart", "message"])
@pytest.mark.parametrize(
    ("disposition", "presented"),
    [(b"attachment", False), (b"x-custom", False), (None, False), (b"inline", True)],
)
def test_named_inline_respects_container_disposition(wrapper, disposition, presented):
    """A named attached ancestor cannot expose newly included inline text."""
    child = _entity(b"text/plain", b'inline; filename="child.txt"', b"inside")
    inner = _multipart([child], b"inner")
    if wrapper == "message":
        container = _entity(
            b'message/rfc822; name="forwarded.eml"',
            disposition,
            _HEADERS + inner,
        )
    else:
        container = _multipart([inner], b"container", disposition)
        container = container.replace(
            b"boundary=container\r\n",
            b'boundary=container; name="bundle.mime"\r\n',
            1,
        )
    visible = _entity(b"text/plain", b'inline; filename="visible.txt"', b"outside")
    parsed = mailparser.parse_from_bytes(
        _HEADERS + _multipart([visible, container], b"outer")
    )

    assert parsed.text_plain == (["outside", "inside"] if presented else ["outside"])
    child_attachment = next(
        a for a in parsed.attachments if a["filename"] == "child.txt"
    )
    assert base64.b64decode(child_attachment["payload"]) == b"inside"
    assert parsed.message is not None
    assert any(
        p.get_payload(decode=True) == b"inside"
        for p in parsed.message.walk()
        if not p.is_multipart()
    )


@pytest.mark.parametrize(
    ("actual_charset", "declared_charset", "text", "fallback"),
    [
        ("utf-8", "gb2312", "\u4f60\u597d\u4e16\u754c", True),
        ("gb2312", "gb2312", "\u4f60\u597d\u4e16\u754c", False),
        ("iso-8859-1", "iso-8859-1", "Caf\u00e9", False),
    ],
)
@pytest.mark.parametrize("named_inline", [False, True])
def test_body_charset_recovery_keeps_original_bytes(
    actual_charset, declared_charset, text, fallback, named_inline
):
    """Malformed declarations do not trigger stdlib replacement decoding."""
    payload = text.encode(actual_charset)
    disposition = b'inline; filename="text.txt"' if named_inline else None
    parsed = mailparser.parse_from_bytes(
        _HEADERS
        + _entity(
            b"text/plain; charset=" + declared_charset.encode("ascii"),
            disposition,
            payload,
            b"Content-Transfer-Encoding: 8bit\r\n",
        )
    )

    assert parsed.text_plain == [text]
    assert parsed.message is not None
    assert parsed.message.get_payload(decode=True) == payload
    if named_inline:
        assert base64.b64decode(parsed.attachments[0]["payload"]) == payload
    assert parsed.has_defects is fallback
    if fallback:
        assert "CharsetDecodeDefect" in parsed.defects_categories
        evidence = json.dumps(parsed.defects)
        assert "gb2312" in evidence and "utf-8" in evidence


def test_body_unrecoverable_charset_keeps_visible_and_raw_evidence():
    """When neither charset works, retain the octet and mark display loss."""
    payload = b"visible\xfftail"
    parsed = mailparser.parse_from_bytes(
        _HEADERS
        + _entity(
            b"text/plain; charset=gb2312",
            b'inline; filename="text.txt"',
            payload,
            b"Content-Transfer-Encoding: 8bit\r\n",
        )
    )

    assert parsed.text_plain == ["visible\ufffdtail"]
    assert parsed.message is not None
    assert parsed.message.get_payload(decode=True) == payload
    assert base64.b64decode(parsed.attachments[0]["payload"]) == payload
    assert parsed.has_defects is True
    assert "CharsetDecodeDefect" in parsed.defects_categories
    assert "replacement characters" in json.dumps(parsed.defects)


@pytest.mark.parametrize("charset", [b"unicode_escape", b"raw_unicode_escape"])
@pytest.mark.parametrize("inline", [False, True])
def test_charset_cannot_inject_surrogates_into_json(charset, inline):
    """A codec-produced surrogate cannot break UTF-8 output consumers."""
    raw = _HEADERS + _entity(
        b"text/plain; charset=" + charset,
        b'inline; filename="evidence.txt"' if inline else None,
        base64.b64encode(b"\\ud800"),
        b"Content-Transfer-Encoding: base64\r\n",
    )
    parsed = mailparser.parse_from_bytes(raw)
    assert parsed.mail_json.encode("utf-8")
    assert parsed.text_plain == [r"\ud800"]
    assert parsed.has_defects is True
    assert "CharsetDecodeDefect" in parsed.defects_categories
    assert parsed.message is not None
    assert parsed.message.get_payload(decode=True) == b"\\ud800"
    if inline:
        assert base64.b64decode(parsed.attachments[0]["payload"]) == b"\\ud800"
