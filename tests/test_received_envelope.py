"""Forensic envelope recovery without overlapping regular-expression scans."""

import json

import pytest
from work_budget import bounded_text_work

import mailparser
from mailparser import received, utils

DATE = "Mon, 1 Jan 2024 00:00:00 +0000"


def _trace(annotation, embedded):
    """Place an MTA envelope annotation in either supported location."""
    if embedded:
        return f"from a by h ({annotation}); {DATE}"
    return f"from a by h {annotation}; {DATE}"


@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("keyword", ["envelope-from", "envelope-sender"])
@pytest.mark.parametrize(
    "address",
    [
        "sender@example.com",
        '"a<b"@example.com',
        '"a>b"@example.com',
        r'"a\"<>b"@example.com',
        '"two  spaces"@example.com',
        "sender@[IPv6:2001:db8::1]",
        "sender@[literal<>data]",
        "@old.example,@relay.example:sender@example.com",
        " sender@example.com ",
        "sender(comment <nested> (note))@example.com",
        "utente@esempio.italia",
        "δοκιμή@παράδειγμα.δοκιμή",
    ],
)
def test_envelope_preserves_complete_lexical_path(embedded, keyword, address):
    """Keep quoted delimiters, CFWS, obsolete routes and UTF-8 intact."""
    header = _trace(f"{keyword} <{address}>", embedded)
    mail = mailparser.parse_from_bytes(
        f"Received: {header}\r\nSubject: intact\r\n\r\nbody".encode()
    )
    key = keyword.replace("-", "_")
    assert mail.received[0][key] == address.strip(" \t\r\n")
    assert mail.received[0]["by"].startswith("h")
    assert mail.received[0]["date"] == DATE
    assert mail.subject == "intact"
    assert mail.body == "body"
    assert mail.received_header_defects == []
    assert mail.message is not None
    assert [v for k, v in mail.message.raw_items() if k == "Received"] == [
        header.encode().decode("ascii", "surrogateescape")
    ]
    json.loads(mail.mail_json)


@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("keyword", ["envelope-from", "envelope-sender"])
def test_null_envelope_keeps_existing_output(embedded, keyword):
    """The valid SMTP null sender stays absent from extracted values."""
    header = _trace(f"{keyword} <>", embedded)
    mail = mailparser.parse_from_string(f"Received: {header}\r\n\r\n")
    assert keyword.replace("-", "_") not in mail.received[0]
    assert mail.received_header_defects == []


@pytest.mark.parametrize("keyword", ["envelope-from", "envelope-sender"])
@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("<" * 2000, "unclosed-envelope-address"),
        ("<outer<inner@example.com>>", "nested-envelope-address"),
        ('<"unclosed@example.com>', "unclosed-envelope-address"),
    ],
    ids=["many-open-angles", "nested-address", "unclosed-quote"],
)
def test_bad_envelope_retains_evidence_and_neighboring_headers(
    keyword, content, reason
):
    """An ambiguous annotation cannot select a partial sender."""
    bad = _trace(f"{keyword} {content}", True)
    good = f"from neighbor by other; {DATE}"
    raw = (
        f"Received: {bad}\r\nReceived: {good}\r\n"
        "From: alice@example.com\r\nSubject: intact\r\n\r\nbody"
    )
    mail = mailparser.parse_from_string(raw)
    assert keyword.replace("-", "_") not in mail.received[1]
    assert mail.received[1]["date"] == DATE
    assert mail.received[0]["from"] == "neighbor"
    assert mail.from_ == [("", "alice@example.com")]
    assert mail.subject == "intact"
    assert mail.body == "body"
    assert mail.has_defects is True
    assert mail.received_header_defects == [
        {
            "reason": reason,
            "raw": bad,
            "recovered": False,
            "header": "received",
            "occurrence": 0,
        }
    ]
    assert mail.message is not None
    assert mail.message.get_all("Received") == [bad, good]
    for output in (mail.mail_json, mail.mail_partial_json):
        assert json.loads(output)["received_header_defects"] == (
            mail.received_header_defects
        )


def test_complete_annotation_after_bad_path_remains_recoverable():
    """A closed bad path cannot hide a later independent annotation."""
    bad = "envelope-from <outer<bad@example.com>> "
    header = _trace(
        bad + "envelope-from <good@example.com>",
        True,
    )
    mail = mailparser.parse_from_string(f"Received: {header}\r\n\r\n")
    assert mail.received[0]["envelope_from"] == "good@example.com"
    diagnostic = mail.received_header_defects[0]
    assert diagnostic["reason"] == "nested-envelope-address"
    assert diagnostic["recovered"] is True
    assert diagnostic["raw"] == header


@pytest.mark.parametrize("embedded", [False, True])
def test_reported_payload_has_bounded_scanning_and_explicit_evidence(embedded):
    """Exercise both reported call sites with deterministic Python work."""
    annotation = (
        "envelope-from <x " * 4000
        if embedded
        else "envelope-from x (" + "<" * 40000 + ")"
    )
    header = _trace(annotation, embedded)
    raw = f"Received: {header}\r\n\r\nbody"
    names = ("extract_envelope_address",)
    with bounded_text_work(received, ("_envelope_path_end",), len(header)):
        with bounded_text_work(utils, names, len(header)):
            mail = mailparser.parse_from_string(raw)
    assert "envelope_from" not in mail.received[0]
    assert mail.received[0]["date"] == DATE
    assert mail.received_header_defects[0]["raw"] == header
    assert mail.body == "body"


@pytest.mark.parametrize("clause", ["from", "by", "with"])
@pytest.mark.parametrize("keyword", ["envelope-from", "envelope-sender"])
def test_all_embedded_locations_preserve_escaped_comments(clause, keyword):
    """Quoted pairs and nested comment delimiters belong to the path."""
    address = r"user(note\) with <data> (nested))@example.com"
    header = f"{clause} host ({keyword.upper()} <{address}>); {DATE}"
    assert utils.parse_received(header)[keyword.replace("-", "_")] == address


@pytest.mark.parametrize("factory", ["string", "bytes", "file"])
def test_folded_payload_through_public_factories(factory, tmp_path):
    """Legal wire folding does not hide the attack or lose raw evidence."""
    bad = "from a envelope-from x (" + ("<" * 900 + "\r\n\t") * 24 + ")"
    header = f"{bad}; {DATE}"
    raw = f"Received: {header}\r\nSubject: intact\r\n\r\nbody"
    if factory == "file":
        path = tmp_path / "folded.eml"
        path.write_bytes(raw.encode())
        mail = mailparser.parse_from_file(str(path))
    elif factory == "bytes":
        mail = mailparser.parse_from_bytes(raw.encode())
    else:
        mail = mailparser.parse_from_string(raw)
    assert "envelope_from" not in mail.received[0]
    assert mail.received_header_defects == [
        {
            "reason": "unclosed-envelope-address",
            "raw": header,
            "recovered": False,
            "header": "received",
            "occurrence": 0,
        }
    ]
    assert mail.subject == "intact"
    assert mail.body == "body"


def test_many_bad_clauses_do_not_duplicate_raw_evidence():
    """Repeated malformed annotations produce bounded diagnostic output."""
    header = "from a by h " + "envelope-from (<<bad>>) " * 2000 + f"; {DATE}"
    mail = mailparser.parse_from_string(f"Received: {header}\r\n\r\n")
    assert len(mail.received_header_defects) == 1
    diagnostic = mail.received_header_defects[0]
    assert diagnostic["reason"] == "nested-envelope-address"
    assert diagnostic["raw"] == header
    assert len(mail.mail_json) < 8 * len(header)


def test_both_envelope_annotations_remain_independent():
    """A broken sender annotation cannot hide a separate complete value."""
    bad = "envelope-from <outer<bad@example.com>> "
    header = _trace(bad + 'envelope-sender <"a>b"@example.com>', True)
    mail = mailparser.parse_from_string(f"Received: {header}\r\n\r\n")
    assert "envelope_from" not in mail.received[0]
    assert mail.received[0]["envelope_sender"] == '"a>b"@example.com'
    assert mail.received_header_defects[0]["raw"] == header


@pytest.mark.parametrize("keyword", ["envelope-from", "envelope-sender"])
@pytest.mark.parametrize("closed", [False, True])
def test_nested_path_only_recovers_after_outer_close(keyword, closed):
    """A marker inside a malformed outer path is never independent."""
    annotation = (
        f"{keyword} <outer<junk> {keyword} <false@example.com>"
        + (">" if closed else "")
        + f" {keyword} <real@example.com>"
    )
    header = _trace(annotation, True)
    neighbor = f"from neighbor by other; {DATE}"
    mail = mailparser.parse_from_string(
        f"Received: {header}\r\nReceived: {neighbor}\r\nSubject: intact\r\n\r\nbody"
    )
    key = keyword.replace("-", "_")
    if closed:
        assert mail.received[1][key] == "real@example.com"
    else:
        assert key not in mail.received[1]
    assert mail.received[0]["from"] == "neighbor"
    assert mail.subject == "intact"
    assert mail.body == "body"
    assert mail.has_defects is True
    assert mail.received_header_defects == [
        {
            "reason": (
                "nested-envelope-address" if closed else "unclosed-envelope-address"
            ),
            "raw": header,
            "recovered": closed,
            "header": "received",
            "occurrence": 0,
        }
    ]
    assert mail.message is not None
    assert mail.message.get_all("Received") == [header, neighbor]


@pytest.mark.parametrize("factory", ["string", "bytes"])
@pytest.mark.parametrize("marker", ["envelope-ſender", "ENVELOPE-ſENDER"])
def test_unicode_marker_is_literal_evidence(marker, factory):
    """Unicode case equivalents cannot create ASCII envelope markers."""
    header = _trace(f"{marker} <sender@example.com>", True)
    raw = f"Received: {header}\r\nSubject: intact\r\n\r\nbody"
    mail = (
        mailparser.parse_from_string(raw)
        if factory == "string"
        else mailparser.parse_from_bytes(raw.encode())
    )
    assert "envelope_sender" not in mail.received[0]
    assert mail.received_header_defects == []
    assert mail.subject == "intact"
    assert mail.body == "body"
    assert mail.message is not None
    assert [v for k, v in mail.message.raw_items() if k == "Received"] == [
        header
        if factory == "string"
        else header.encode().decode("ascii", "surrogateescape")
    ]


@pytest.mark.parametrize("marker", ["ENVELOPE-SENDER", "EnVeLoPe-FrOm"])
def test_ascii_marker_case_preserves_utf8_address(marker):
    """ASCII case folding changes marker matching only, never the path."""
    address = "δοκιμή@παράδειγμα.δοκιμή"
    header = _trace(f"{marker} <{address}>", True)
    mail = mailparser.parse_from_bytes(f"Received: {header}\r\n\r\n".encode())
    assert mail.received[0][marker.lower().replace("-", "_")] == address
    assert mail.received_header_defects == []
