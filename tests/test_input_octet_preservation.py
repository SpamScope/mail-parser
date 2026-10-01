"""File inputs preserve the same evidence and payloads as byte inputs."""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

import mailparser
from mailparser.exceptions import MailParserRecursionError

_HEADERS = (
    b"Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n"
    b"From: alice@example.com\r\n"
    b"To: bob@example.com\r\n"
)


def _parse_pair(tmp_path, raw):
    path = tmp_path / "message.eml"
    path.write_bytes(raw)
    return mailparser.parse_from_file(path), mailparser.parse_from_bytes(raw)


@pytest.mark.parametrize(
    ("bad", "escaped"),
    [
        (b"\xff", r"\udcff"),
        (b"\xc3", r"\udcc3"),
        (b"\xc0\xaf", r"\udcc0\udcaf"),
        (b"\xed\xa0\x80", r"\udced\udca0\udc80"),
    ],
)
@pytest.mark.parametrize(
    "template", [b"a%s@example.com", b"a@ex%s.example", b'"a%s"@example.com']
)
def test_file_invalid_octets_remain_evidence(tmp_path, bad, escaped, template):
    """Dropping malformed UTF-8 must not manufacture a valid sender."""
    address = template % bad
    raw = _HEADERS.replace(b"alice@example.com", address) + b"\r\nbody"
    parsed, reference = _parse_pair(tmp_path, raw)
    expected = [
        {
            "reason": "invalid-utf8",
            "raw": template.decode("ascii") % escaped,
            "recovered": False,
            "candidates": [],
            "header": "from",
            "occurrence": 0,
        }
    ]

    assert parsed.from_ == reference.from_ == []
    assert parsed.to == reference.to == [("", "bob@example.com")]
    assert parsed.has_defects is True
    assert parsed.address_header_defects == expected
    assert parsed.address_header_defects == reference.address_header_defects
    assert parsed.defects_categories == reference.defects_categories
    assert parsed.defects == reference.defects
    assert parsed.message is not None
    assert reference.message is not None
    raw_items = list(parsed.message.raw_items())
    assert raw_items == list(reference.message.raw_items())
    raw_from = dict(parsed.message.raw_items())["From"]
    assert raw_from.encode("ascii", "surrogateescape") == address
    output = json.loads(parsed.mail_json.encode("utf-8"))
    assert output["address_header_defects"] == expected
    assert output["has_defects"] is True


@pytest.mark.parametrize("bad_occurrence", [0, 1])
def test_file_neighbors_and_occurrences(tmp_path, bad_occurrence):
    """Recover valid neighbors without discarding later header evidence."""
    values = [b"first@example.com", b"later@example.com"]
    values[bad_occurrence] = b"a\xff@example.com, valid@example.com"
    raw = (
        _HEADERS.replace(b"To: bob@example.com\r\n", b"")
        + b"".join(b"To: " + value + b"\r\n" for value in values)
        + b"\r\nbody"
    )
    parsed, reference = _parse_pair(tmp_path, raw)
    expected_to = "first@example.com"
    if bad_occurrence == 0:
        expected_to = "valid@example.com"

    assert parsed.to == reference.to == [("", expected_to)]
    assert parsed.from_ == [("", "alice@example.com")]
    assert parsed.has_defects is True
    assert parsed.address_header_defects == [
        {
            "reason": "invalid-utf8",
            "raw": r"a\udcff@example.com",
            "recovered": False,
            "candidates": [],
            "header": "to",
            "occurrence": bad_occurrence,
        }
    ]
    assert parsed.address_header_defects == reference.address_header_defects
    assert parsed.message is not None
    raw_values = [
        value.encode("ascii", "surrogateescape")
        for name, value in parsed.message.raw_items()
        if name.lower() == "to"
    ]
    assert raw_values == values


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"Alice <alice@example.com>", [("Alice", "alice@example.com")]),
        (
            b"Jos\xc3\xa9 <jos\xc3\xa9@example.com>",
            [("Jos\u00e9", "jos\u00e9@example.com")],
        ),
        (
            b"<@old.example:alice@example.com>",
            [("", "alice@example.com")],
        ),
    ],
)
def test_file_valid_addresses_match_bytes(tmp_path, value, expected):
    """The file boundary preserves accepted syntax and Unicode identities."""
    raw = _HEADERS.replace(b"alice@example.com", value) + b"\r\nbody"
    parsed, reference = _parse_pair(tmp_path, raw)

    assert parsed.from_ == reference.from_ == expected
    assert parsed.has_defects == reference.has_defects is False
    assert parsed.address_header_defects == []
    assert parsed.message is not None
    assert reference.message is not None
    raw_items = list(parsed.message.raw_items())
    assert raw_items == list(reference.message.raw_items())


def test_file_mime_charset_decoding_uses_original_octets(tmp_path):
    """An 8-bit body is decoded with its declared charset, not UTF-8."""
    raw = (
        _HEADERS
        + b"MIME-Version: 1.0\r\n"
        + b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        + b"Content-Transfer-Encoding: 8bit\r\n\r\nCaf\xe9"
    )
    parsed, reference = _parse_pair(tmp_path, raw)

    assert parsed.text_plain == reference.text_plain == ["Caf\u00e9"]
    assert parsed.message is not None
    assert parsed.message.get_payload(decode=True) == b"Caf\xe9"
    assert parsed.has_defects == reference.has_defects is False


def test_file_binary_attachment_preserves_octets_and_line_endings(tmp_path):
    """Loading a file cannot decode or translate an attachment's bytes."""
    payload = b"\x00\x80\xff\r\n\xc3\xa9\n\rEND"
    raw = (
        _HEADERS
        + b"MIME-Version: 1.0\r\n"
        + b"Content-Type: application/octet-stream\r\n"
        + b'Content-Disposition: attachment; filename="sample.bin"\r\n'
        + b"Content-Transfer-Encoding: binary\r\n\r\n"
        + payload
    )
    parsed, reference = _parse_pair(tmp_path, raw)

    assert len(parsed.attachments) == 1
    assert parsed.attachments == reference.attachments
    assert base64.b64decode(parsed.attachments[0]["payload"]) == payload
    assert parsed.message is not None
    assert parsed.message.get_payload(decode=True) == payload


def test_cli_file_reports_invalid_address_octets(tmp_path):
    """The real --file CLI must not print a sender created by byte loss."""
    raw = _HEADERS.replace(b"alice@example.com", b"a\xff@example.com")
    path = tmp_path / "message.eml"
    path.write_bytes(raw + b"\r\nbody")
    result = subprocess.run(
        [sys.executable, "-m", "mailparser", "--file", str(path), "--json"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=True,
        timeout=10,
    )
    output = json.loads(result.stdout.decode("utf-8"))

    assert not output.get("from")
    assert output["to"] == [["", "bob@example.com"]]
    assert output["has_defects"] is True
    assert output["address_header_defects"] == [
        {
            "reason": "invalid-utf8",
            "raw": r"a\udcff@example.com",
            "recovered": False,
            "candidates": [],
            "header": "from",
            "occurrence": 0,
        }
    ]


def test_converted_outlook_file_is_removed_after_success(tmp_path):
    """Converted temporary files are cleaned after lossless loading."""
    raw = _HEADERS.replace(b"alice@example.com", b"a\xff@example.com")
    path = tmp_path / "converted.eml"
    path.write_bytes(raw + b"\r\nbody")

    parsed = mailparser.MailParser.from_file(path, is_outlook=True)

    assert not path.exists()
    assert parsed.from_ == []
    assert parsed.has_defects is True
    assert parsed.address_header_defects[0]["reason"] == "invalid-utf8"


@pytest.mark.parametrize("is_outlook", [False, True])
def test_file_recursion_guard_and_cleanup(tmp_path, is_outlook):
    """Real nested input retains the public recursion and cleanup guards."""
    opening = "Content-Type: multipart/mixed; boundary=B{0}\r\n\r\n--B{0}\r\n"
    parts = b"".join(opening.format(i).encode() for i in range(3000))
    raw = _HEADERS + parts + b"text\r\n"
    path = tmp_path / "nested.eml"
    path.write_bytes(raw)

    with pytest.raises(MailParserRecursionError):
        mailparser.MailParser.from_file(path, is_outlook=is_outlook)

    assert path.exists() is not is_outlook
