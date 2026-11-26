"""Subject unfolding preserves raw evidence and other header semantics."""

import json
import subprocess
import sys

import pytest

import mailparser


@pytest.mark.parametrize("route", ["string", "bytes", "file"])
@pytest.mark.parametrize(
    "value, expected",
    [
        ("a\r\n b", "a b"),
        ("a\r\n\tb", "a\tb"),
        ("a \r\n \t b", "a  \t b"),
        ("a\r\n \r\n b", "a  b"),
        (
            "Re: =?UTF-8?Q?R=C3=A9union?= demain\r\n matin",
            "Re: Réunion demain matin",
        ),
        ("=?utf-8?q?one?=\r\n =?utf-8?q?two?=", "onetwo"),
        ("a\n b", "a b"),
        ("a\n\tb", "a\tb"),
        ("a \n \t b", "a  \t b"),
        ("a\n \r\n b", "a  b"),
        ("a\r b", "a\r b"),
        ("=?utf-8?q?a=0D=0A_b?=", "a\r\n b"),
        ("=?utf-8?q?a=0A_b?=", "a\n b"),
    ],
)
def test_subject_unfolding(route, value, expected, tmp_path):
    """Unfold wire CRLF/LF before decoding, preserving other evidence."""
    raw = (
        f"Subject: {value}\r\nComments: a\r\n b\r\nTo: good@example.com\r\n"
        f"\r\nbody"
    )
    if route == "string":
        parsed = mailparser.parse_from_string(raw)
    elif route == "bytes":
        parsed = mailparser.parse_from_bytes(raw.encode())
    else:
        path = tmp_path / "subject.eml"
        path.write_bytes(raw.encode())
        parsed = mailparser.parse_from_file(path)
    assert parsed.subject == expected
    assert parsed.headers["Subject"] == expected
    assert isinstance(parsed.subject_json, str)
    assert json.loads(parsed.subject_json) == expected
    assert json.loads(parsed.mail_json)["subject"] == expected
    assert parsed.mail_partial["subject"] == expected
    assert isinstance(parsed.subject_raw, str)
    assert json.loads(parsed.subject_raw) == [value]
    assert parsed.message is not None
    assert parsed.message.get_all("Subject") == [value]
    assert parsed.comments == "a\r\n b"
    assert parsed.to == [("", "good@example.com")]
    assert parsed.body == "body"
    assert not parsed.has_defects
    assert parsed.header_decoding_defects == []


@pytest.mark.parametrize("newline", ["\r\n", "\n"])
def test_repeated_subjects_keep_occurrences_and_decode_failure(newline):
    """Literal decode failures retain the whole evidence and diagnostics."""
    bad = f"=?no-such-codec?q?test?={newline} evidence"
    parsed = mailparser.parse_from_string(
        f"sUbJeCt: a\r\n b\r\nSubject: {bad}\r\n\r\n"
    )
    assert parsed.subject == ["a b", bad]
    assert isinstance(parsed.subject_raw, str)
    assert json.loads(parsed.subject_raw) == ["a\r\n b", bad]
    assert parsed.has_defects
    assert repr(bad) in parsed.defects[0]["header-decoding"][0]
    assert parsed.header_decoding_defects == [
        {
            "reason": "invalid-encoded-word",
            "raw": bad,
            "header": "subject",
            "occurrence": 1,
            "part": 0,
            "recovered": True,
        }
    ]


@pytest.mark.parametrize("newline", ["\r\n", "\n"])
def test_subject_unfolding_from_cli_stdin(newline):
    """The issue's mixed encoded/literal Subject unfolds through stdin."""
    raw = newline.join(
        [
            "From: a@b.c",
            "To: d@e.f",
            "Subject: Re: =?UTF-8?Q?R=C3=A9union?= demain",
            " matin",
            "Date: Thu, 05 Mar 2026 10:00:00 -0500",
            "",
            "body",
        ]
    )
    result = subprocess.run(
        [sys.executable, "-m", "mailparser", "-k", "-j"],
        input=raw.encode(),
        capture_output=True,
        check=True,
        timeout=10,
    )
    parsed = json.loads(result.stdout)
    assert parsed["subject"] == "Re: Réunion demain matin"
    assert parsed["to"] == [["", "d@e.f"]]
    assert parsed["body"] == "body"
