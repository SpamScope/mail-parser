"""RFC 6532 mailbox regression and forensic boundaries (issue #177)."""

import json

import pytest

import mailparser
from mailparser.const import ADDRESSES_HEADERS


@pytest.mark.parametrize("as_bytes", [False, True])
@pytest.mark.parametrize("header", sorted(ADDRESSES_HEADERS))
@pytest.mark.parametrize(
    "value,expected",
    [
        ("José <josé@example.com>", [("José", "josé@example.com")]),
        ("user@exämple.com", [("", "user@exämple.com")]),
        ("山田 <yamada@例え.jp>", [("山田", "yamada@例え.jp")]),
        (
            "josé@example.com, bob@example.com",
            [("", "josé@example.com"), ("", "bob@example.com")],
        ),
        ('"josé"@example.com', [("", '"josé"@example.com')]),
        ("用户@例え.jp", [("", "用户@例え.jp")]),
        ("😀@例え.jp", [("", "😀@例え.jp")]),
        ("e\u0301@example.com", [("", "e\u0301@example.com")]),
        ("\u00a0user@example.com", [("", "\u00a0user@example.com")]),
        ("user@example.com\u00a0", [("", "user@example.com\u00a0")]),
        ("J. Doe <@例え.jp:josé@example.com>", [("J. Doe", "josé@example.com")]),
        (
            "チーム: josé@example.com, bob@example.com;",
            [("", "josé@example.com"), ("", "bob@example.com")],
        ),
    ],
)
def test_international_mailboxes_are_not_defects(header, value, expected, as_bytes):
    raw = f"{header}: {value}\r\nSubject: s\r\n\r\nb\r\n"
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if as_bytes
        else mailparser.parse_from_string(raw)
    )
    assert mail.headers[header] == expected
    assert mail.mail[header] == expected
    assert json.loads(mail.mail_json)[header] == [list(pair) for pair in expected]
    assert mail.address_header_defects == []
    assert not mail.has_defects


@pytest.mark.parametrize("as_bytes", [False, True])
def test_unicode_spoof_label_keeps_defect_and_structural_mailbox(as_bytes):
    value = "josé@trusted.example < 用户@例え.jp >"
    raw = f"From: {value}\r\n\r\n"
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if as_bytes
        else mailparser.parse_from_string(raw)
    )
    assert mail.from_ == [("josé@trusted.example", "用户@例え.jp")]
    assert mail.has_defects
    assert mail.address_header_defects == [
        {
            "reason": "invalid-display-name",
            "raw": value,
            "recovered": True,
            "candidates": [
                {"display_name": "josé@trusted.example", "address": "用户@例え.jp"}
            ],
            "header": "from",
            "occurrence": 0,
        }
    ]


def test_ambiguous_unicode_candidates_and_valid_neighbour_survive():
    value = "Label <josé@example.com> <用户@例え.jp>"
    mail = mailparser.parse_from_bytes(f"To: {value}, bob@example.com\r\n\r\n".encode())
    assert mail.to == [("", "bob@example.com")]
    assert mail.has_defects
    defect = mail.address_header_defects[0]
    assert defect["raw"] == value
    assert defect["recovered"] is False
    assert [c["address"] for c in defect["candidates"]] == [
        "josé@example.com",
        "用户@例え.jp",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "josé..x@example.com",
        ".josé@example.com",
        "josé@example..com",
        "josé@example.com@other.example",
        "josé@example.com>",
        "José <josé@example.com",
    ],
)
def test_utf8_does_not_relax_ascii_mailbox_boundaries(value):
    mail = mailparser.parse_from_bytes(f"From: {value}\r\n\r\n".encode())
    assert mail.from_ == []
    assert mail.has_defects
    assert mail.address_header_defects[0]["raw"] == value
    assert mail.address_header_defects[0]["recovered"] is False


@pytest.mark.parametrize(
    "bad", [b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"]
)
@pytest.mark.parametrize("template", [b"%s@b", b'"%s"@b', b"a@[%s]"])
def test_invalid_utf8_cannot_become_a_different_valid_mailbox(bad, template):
    raw = b"To: " + template % bad + b", bob@example.com\r\n\r\n"
    mail = mailparser.parse_from_bytes(raw)
    assert mail.to == [("", "bob@example.com")]
    assert mail.has_defects
    assert mail.address_header_defects[0]["reason"] == "invalid-utf8"
    assert mail.address_header_defects[0]["recovered"] is False
    assert mail.address_header_defects[0]["candidates"] == []
    # Diagnostics must remain serializable as valid UTF-8 JSON.
    mail.mail_json.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        b"\xff: bob@example.com;",
        b"Team (\xff): bob@example.com;",
        b"(\xff), bob@example.com",
        b"Bad\xff <bob@example.com>",
    ],
)
def test_invalid_utf8_in_labels_and_comments_remains_evidence(value):
    mail = mailparser.parse_from_bytes(b"To: " + value + b"\r\n\r\n")
    assert [address for _, address in mail.to] == ["bob@example.com"]
    assert mail.has_defects
    defect = mail.address_header_defects[0]
    assert defect["reason"] == "invalid-utf8"
    assert "\\udcff" in defect["raw"]
    assert defect["header"] == "to"
    assert defect["occurrence"] == 0
    mail.mail_json.encode("utf-8")


@pytest.mark.parametrize("char", ["\x80", "\ud7ff", "\ue000", "\U0010ffff"])
def test_utf8_scalar_range_boundaries(char):
    mail = mailparser.parse_from_bytes(
        f"To: {char}@example.com, user@{char}.example\r\n\r\n".encode()
    )
    assert mail.to == [("", f"{char}@example.com"), ("", f"user@{char}.example")]
    assert not mail.has_defects


@pytest.mark.parametrize(
    "label",
    [
        '"Support <josé@trusted.example>"',
        "Support (josé@trusted.example <decoy@例え.jp>)",
    ],
)
def test_international_display_evidence_is_not_promoted(label):
    value = f"{label} <用户@例え.jp>, bad@label < réel@example.com >"
    mail = mailparser.parse_from_bytes(f"To: {value}\r\n\r\n".encode())
    assert [addr for _, addr in mail.to] == ["用户@例え.jp", "réel@example.com"]
    assert mail.has_defects
    assert mail.address_header_defects[-1]["reason"] == "invalid-display-name"


def test_unicode_text_after_angle_address_is_not_discarded_as_cfws():
    value = "Name <josé@example.com>\u00a0"
    mail = mailparser.parse_from_bytes(f"From: {value}\r\n\r\n".encode())
    assert mail.from_ == []
    assert mail.has_defects
    defect = mail.address_header_defects[0]
    assert defect["raw"] == value
    assert defect["reason"] == "ambiguous-angle-address"
    assert defect["candidates"][0]["address"] == "josé@example.com"
