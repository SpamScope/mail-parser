"""Raw UTF-8 MIME metadata survives every public input boundary."""

import base64
import email
import json

import pytest

import mailparser

_PAYLOAD = bytes(range(256))
_HEADERS = (
    b"Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n"
    b"From: alice@example.com\r\nTo: bob@example.com\r\n"
    b"MIME-Version: 1.0\r\n"
)


def _parse(raw, factory, tmp_path):
    if factory == "file":
        path = tmp_path / "metadata.eml"
        path.write_bytes(raw)
        return mailparser.parse_from_file(path)
    if factory == "string":
        return mailparser.parse_from_string(raw.decode("utf-8", "surrogateescape"))
    return mailparser.parse_from_bytes(raw)


@pytest.mark.parametrize("factory", ["file", "bytes", "string"])
@pytest.mark.parametrize("parameter", ["filename", "name"])
def test_raw_utf8_mime_metadata_and_payload(factory, parameter, tmp_path):
    """Named attachments preserve Unicode metadata and exact bytes."""
    filename = "ФНС_РФ558.zip"
    content_id = "<pièce@exemple.example>"
    content_type = "application/octet-stream"
    disposition = "attachment"
    if parameter == "filename":
        disposition += f'; filename="{filename}"'
    else:
        content_type += f'; name="{filename}"'
    raw = (
        _HEADERS
        + (
            f"Content-Type: {content_type}\r\n"
            f"Content-Disposition: {disposition}\r\n"
            f"Content-ID: {content_id}\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
        ).encode()
        + base64.b64encode(_PAYLOAD)
    )
    mail = _parse(raw, factory, tmp_path)
    attachment = mail.attachments[0]
    assert attachment["filename"] == attachment["safe_filename"] == filename
    assert attachment["content-disposition"] == disposition
    assert attachment["content-id"] == content_id
    assert base64.b64decode(attachment["payload"]) == _PAYLOAD
    assert not mail.has_defects
    destination = tmp_path / "attachments"
    destination.mkdir()
    mail.write_attachments(destination)
    assert (destination / filename).read_bytes() == _PAYLOAD
    assert mail.message is not None
    original = (
        email.message_from_string(raw.decode())
        if factory == "string"
        else email.message_from_bytes(raw)
    )
    assert list(mail.message.raw_items()) == list(original.raw_items())
    assert mail.message.get_payload(decode=True) == _PAYLOAD
    attachments_json = mail.attachments_json
    assert isinstance(attachments_json, str)
    assert json.loads(attachments_json)[0]["filename"] == filename


@pytest.mark.parametrize("factory", ["file", "bytes", "string"])
def test_rfc2231_continuation_still_decodes(factory, tmp_path):
    """The UTF-8 view preserves RFC 2231 parameter continuation semantics."""
    raw = (
        _HEADERS + b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment;\r\n"
        b" filename*0*=utf-8''caf%C3%A9; filename*1=.bin\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(_PAYLOAD)
    )
    mail = _parse(raw, factory, tmp_path)
    assert mail.attachments[0]["filename"] == "café.bin"
    assert base64.b64decode(mail.attachments[0]["payload"]) == _PAYLOAD
    assert not mail.has_defects


@pytest.mark.parametrize("factory", ["file", "bytes", "string"])
def test_invalid_mime_octets_remain_evidence(factory, tmp_path):
    """Undecodable metadata stays visibly damaged with exact raw evidence."""
    raw = (
        _HEADERS + b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="a\xffb.bin"\r\n'
        b"Content-ID: <a\xffb@example.com>\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(_PAYLOAD)
    )
    mail = _parse(raw, factory, tmp_path)
    assert mail.attachments[0]["filename"] == "a\ufffdb.bin"
    assert mail.attachments[0]["content-id"] == "<a\ufffdb@example.com>"
    assert base64.b64decode(mail.attachments[0]["payload"]) == _PAYLOAD
    assert mail.has_defects
    assert "MimeHeaderDefect" in mail.defects_categories
    evidence = " ".join(mail.defects[-1]["mime-headers"])
    assert "content-disposition[0]" in evidence
    assert "content-id[0]" in evidence
    assert "\\xff" in evidence
    assert "part 0" in evidence
    assert mail.message is not None
    assert "\udcff" in dict(mail.message.raw_items())["Content-Disposition"]
    mail.mail_json.encode("utf-8")


def test_repeated_mime_header_keeps_occurrence_evidence(tmp_path):
    """A malformed later field cannot hide behind a valid first value."""
    raw = (
        _HEADERS + b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="valid.bin"\r\n'
        b'Content-Disposition: attachment; filename="bad\xff.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(_PAYLOAD)
    )
    mail = _parse(raw, "bytes", tmp_path)
    assert mail.attachments[0]["filename"] == "valid.bin"
    assert mail.has_defects
    assert "content-disposition[1]" in mail.defects[-1]["mime-headers"][0]
    assert "\\xff" in mail.defects[-1]["mime-headers"][0]
    assert base64.b64decode(mail.attachments[0]["payload"]) == _PAYLOAD


def test_metadata_defects_retain_mime_part_context(tmp_path):
    """Each sibling keeps its own payload and raw metadata evidence."""
    raw = (
        _HEADERS + b'Content-Type: multipart/mixed; boundary="part"\r\n\r\n'
        b"--part\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="good.bin"\r\n\r\ngood\r\n'
        b"--part\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="bad\xff.bin"\r\n\r\nbad\r\n'
        b"--part--\r\n"
    )
    mail = _parse(raw, "bytes", tmp_path)
    assert [a["filename"] for a in mail.attachments] == ["good.bin", "bad�.bin"]
    assert [base64.b64decode(a["payload"]) for a in mail.attachments] == [
        b"good",
        b"bad",
    ]
    assert "part 2" in mail.defects[-1]["mime-headers"][0]


@pytest.mark.parametrize("charset", ["unicode_escape", "raw_unicode_escape"])
@pytest.mark.parametrize("parameter", ["filename", "name"])
def test_encoded_filename_cannot_produce_surrogate(charset, parameter):
    """Malformed decoded Unicode stays literal with MIME defect evidence."""
    word = f"=?{charset}?b?XHVkODAw?="
    header = (
        f'Content-Disposition: attachment; filename="{word}"\r\n'
        if parameter == "filename"
        else f'Content-Type: text/plain; name="{word}"\r\n'
    )
    mail = mailparser.parse_from_bytes(header.encode() + b"\r\nbody")
    assert mail.mail_json.encode("utf-8")
    assert mail.attachments[0]["filename"] == word
    assert mail.has_defects is True
    assert "MimeHeaderDefect" in mail.defects_categories
    assert word in str(mail.defects)
    assert base64.b64decode(mail.attachments[0]["payload"]) == b"body"
