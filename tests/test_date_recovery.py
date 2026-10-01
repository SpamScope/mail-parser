"""Semantic date validation and occurrence-aware forensic recovery."""

import datetime
import io
import json

import pytest
from work_budget import bounded_text_work

import mailparser
from mailparser import dates
from mailparser.utils import convert_mail_date

VALID = "Thu, 01 Oct 2026 12:00:00 +0000"
EXPECTED = "2026-10-01T12:00:00+00:00"


def _mail(value, extra=""):
    """Parse a Date field alongside independently valid content."""
    return mailparser.parse_from_bytes(
        (
            f"Date: {value}\r\nFrom: alice@sender.example\r\n"
            "To: bob@recipient.example\r\nSubject: intact\r\n" + extra + "\r\nbody"
        ).encode("utf-8", "surrogateescape")
    )


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("Thu, 31 Feb 2026 12:00:00 +0000", "invalid-calendar-date"),
        ("Thu, 29 Feb 2026 12:00:00 +0000", "invalid-calendar-date"),
        ("01 Jan 1899 12:00:00 +0000", "invalid-calendar-date"),
        ("Thu, 01 Oct 2026 24:00:00 +0000", "invalid-time"),
        ("Thu, 01 Oct 2026 12:60:00 +0000", "invalid-time"),
        ("Thu, 01 Oct 2026 12:00:61 +0000", "invalid-time"),
        ("Thu, 01 Oct 2026 12:00:00 +0060", "invalid-zone"),
        ("Thu, 01 Oct 2026 12:00:00 -0060", "invalid-zone"),
        ("Thu, 01 Oct 2026 12:00:00 +99999", "invalid-zone"),
        ("", "invalid-date-syntax"),
        ("unparseable", "invalid-date-syntax"),
        ("Thu, 01 Oct 2026 12:00:00 +0000 (bad", "invalid-date-syntax"),
    ],
)
def test_invalid_date_is_not_normalized(value, reason):
    """Invalid components cannot manufacture a plausible timestamp."""
    mail = _mail(value)
    assert mail.date is None
    assert mail.timezone == 0
    assert mail.has_defects is True
    assert mail.date_header_defects == [
        {
            "reason": reason,
            "raw": value,
            "recovered": False,
            "value": None,
            "header": "date",
            "occurrence": 0,
        }
    ]
    assert "DateHeaderDefect" in mail.defects_categories
    assert mail.subject == "intact"
    assert mail.to == [("", "bob@recipient.example")]
    assert mail.body == "body"
    for output in (mail.mail_json, mail.mail_partial_json):
        assert json.loads(output)["date_header_defects"] == mail.date_header_defects
    assert mail.message is not None
    assert mail.message.get_all("Date") == [value]


def test_weekday_mismatch_retains_numeric_date_and_reports_defect():
    """A redundant incorrect weekday does not erase a recoverable date."""
    value = "Wed, 01 Oct 2026 12:00:00 +0000"
    mail = _mail(value)
    assert mail.date is not None
    assert mail.date.isoformat() == EXPECTED
    assert mail.date_header_defects == [
        {
            "reason": "weekday-mismatch",
            "raw": value,
            "recovered": True,
            "value": EXPECTED,
            "header": "date",
            "occurrence": 0,
        }
    ]
    assert mail.has_defects is True


@pytest.mark.parametrize(
    ("value", "expected", "zone"),
    [
        (VALID, EXPECTED, "+0.0"),
        ("01 Oct 2026 12:00 +0000", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 26 12:00 GMT", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 126 12:00:00GMT", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 2026 12:00:00 -0000", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 2026 12:00:00 A", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 2026 12:00:00 XYZ", EXPECTED, "+0.0"),
        ("Thu, 01 Oct 2026 12:00:00 EST", "2026-10-01T17:00:00+00:00", "-5.0"),
        ("Thu, 01 Oct 2026 12:00:00 +9959", "2026-09-27T08:01:00+00:00", "+100.0"),
        ("Sat, 31 Dec 2016 23:59:60 +0000", "2017-01-01T00:00:00+00:00", "+0.0"),
        ("Thu, 29 Feb 2024 12:00:00 +0000", "2024-02-29T12:00:00+00:00", "+0.0"),
        (
            "(a (b)) Thu (day), 01 (d) Oct (m) 2026 12 (h): 00 (n): 00 GMT",
            EXPECTED,
            "+0.0",
        ),
        (r"Thu, 01 Oct 2026 12:00:00 GMT (escaped\) comment)", EXPECTED, "+0.0"),
        ("Thu,\r\n\t01 Oct 2026 12:00:00 GMT", EXPECTED, "+0.0"),
    ],
)
def test_valid_and_obsolete_date_forms(value, expected, zone):
    """Valid old syntax, leap seconds and unknown zones are not defects."""
    mail = _mail(value)
    assert mail.date is not None
    assert mail.date.isoformat() == expected
    assert mail.timezone == zone
    assert mail.has_defects is False
    assert mail.date_header_defects == []
    converted, timezone = convert_mail_date(value)
    assert converted.isoformat() == expected
    assert timezone == zone


def test_date_occurrences_are_checked_without_changing_first_value():
    """Date and Resent-Date diagnostics retain each wire occurrence."""
    mismatch = "Wed, 01 Oct 2026 12:00:00 +0000"
    bad = "Thu, 31 Feb 2026 12:00:00 +0000"
    mail = _mail(
        VALID, f"Date: {bad}\r\nResent-Date: {VALID}\r\nResent-Date: {mismatch}\r\n"
    )
    assert mail.date is not None
    assert mail.date.isoformat() == EXPECTED
    observed = [
        (d["header"], d["occurrence"], d["raw"]) for d in mail.date_header_defects
    ]
    assert observed == [("date", 1, bad), ("resent-date", 1, mismatch)]
    before = list(mail.defects)
    mail.date
    mail.timezone
    mail.parse()
    assert mail.defects == before
    assert len(mail.date_header_defects) == 2


def test_received_date_defects_are_separate_from_lexical_defects():
    """Bad timestamps keep trace clauses and never create false delays."""
    newest = "from relay.example by mx.example; " + VALID
    oldest = "from sender.example by relay.example; Thu, 31 Feb 2026 12:00:00 +0000"
    mail = _mail(VALID, f"Received: {newest}\r\nReceived: {oldest}\r\n")
    assert mail.received[0]["date_utc"] is None
    assert mail.received[1]["date_utc"] == EXPECTED
    assert mail.received[1]["delay"] == 0
    assert mail.received_header_defects == []
    assert mail.date_header_defects == [
        {
            "reason": "invalid-calendar-date",
            "raw": oldest,
            "recovered": False,
            "value": None,
            "header": "received",
            "occurrence": 1,
        }
    ]


def test_empty_received_date_is_diagnosed():
    """A present separator with no date differs from obsolete no-date form."""
    mail = _mail(VALID, "Received: from sender.example by mx.example;\r\n")
    assert mail.received[0]["date_utc"] is None
    assert mail.date_header_defects[0]["reason"] == "invalid-date-syntax"


def test_date_diagnostics_cannot_be_shadowed_by_wire_header():
    """Caller metadata and attacker-named wire fields stay separate."""
    mail = _mail("bad", "date_header_defects: spoofed\r\n")
    assert isinstance(mail.mail["date_header_defects"], list)
    assert mail.headers["date_header_defects"] == "spoofed"


def test_absent_date_preserves_api_defaults():
    """Missing input to the accessor remains a neutral no-result."""
    mail = mailparser.parse_from_string("Subject: no date\r\n\r\nbody")
    assert mail.date is None
    assert mail.timezone == 0
    assert mail.date_header_defects == []


@pytest.mark.parametrize("size", [20, 10000])
def test_extreme_date_components_are_bounded(size):
    """Large years and nested comments neither overflow nor recurse."""
    huge = "01 Oct " + "9" * size + " 12:00:00 +0000"
    with bounded_text_work(dates, ("_date_tokens",), len(huge)):
        mail = _mail(huge)
    assert mail.date is None
    assert mail.date_header_defects[0]["reason"] == "date-out-of-range"
    nested = "(" * size + "note" + ")" * size
    with bounded_text_work(dates, ("_date_tokens",), len(nested + VALID)):
        parsed = _mail(nested + VALID)
    assert parsed.date is not None
    assert parsed.date.isoformat() == EXPECTED


def test_invalid_date_octets_remain_in_diagnostics():
    """Malformed bytes cannot disappear while constructing a timestamp."""
    value = "Thu, 01 Oct 2026 12:00:00 +0000\udcff"
    mail = _mail(value)
    assert mail.date is None
    assert (
        mail.date_header_defects[0]["raw"] == r"Thu, 01 Oct 2026 12:00:00 +0000\udcff"
    )
    assert mail.message is not None
    original = dict(mail.message.raw_items())["Date"]
    assert (
        original.encode("utf-8", "surrogateescape")
        == b"Thu, 01 Oct 2026 12:00:00 +0000\xff"
    )


def test_all_input_factories_share_date_validation(tmp_path):
    """Bytes, strings and file factories produce the same evidence."""
    raw = b"Date: Thu, 31 Feb 2026 12:00:00 +0000\r\n\r\nbody"
    path = tmp_path / "date.eml"
    path.write_bytes(raw)
    mails = [
        mailparser.parse_from_bytes(raw),
        mailparser.parse_from_string(raw.decode()),
        mailparser.parse_from_file(str(path)),
        mailparser.parse_from_file_obj(io.StringIO(raw.decode())),
    ]
    assert all(mail.date is None for mail in mails)
    assert all(
        mail.date_header_defects == mails[0].date_header_defects for mail in mails
    )


def test_converter_raises_on_unrecoverable_date():
    """The legacy tuple converter keeps its controlled-error contract."""
    with pytest.raises(ValueError):
        convert_mail_date("Thu, 31 Feb 2026 12:00:00 +0000")
    date, zone = convert_mail_date("Wed, 01 Oct 2026 12:00:00 +0000")
    assert date == datetime.datetime(2026, 10, 1, 12, tzinfo=datetime.timezone.utc)
    assert zone == "+0.0"


def test_date_diagnostic_json_is_utf8_encodable():
    """Raw malformed octets use the existing escaped-evidence convention."""
    mail = _mail("Thu, 01 Oct 2026 12:00:00 +0000\udcff")
    output = json.loads(mail.mail_json.encode("utf-8"))
    assert (
        output["date_header_defects"][0]["raw"]
        == r"Thu, 01 Oct 2026 12:00:00 +0000\udcff"
    )


def test_reserved_military_zone_j_is_not_accepted():
    """The single letter J is excluded from RFC 5322 obs-zone."""
    mail = _mail("Thu, 01 Oct 2026 12:00:00 J")
    assert mail.date is None
    assert mail.date_header_defects[0]["reason"] == "invalid-zone"


def test_received_weekday_mismatch_recovers_timestamp():
    """Received dates retain a safe UTC value with explicit evidence."""
    received = "from sender.example by mx.example; Wed, 01 Oct 2026 12:00:00 +0000"
    mail = _mail(VALID, "Received: " + received + "\r\n")
    assert mail.received[0]["date_utc"] == EXPECTED
    assert mail.received_header_defects == []
    assert mail.date_header_defects == [
        {
            "reason": "weekday-mismatch",
            "raw": received,
            "recovered": True,
            "value": EXPECTED,
            "header": "received",
            "occurrence": 0,
        }
    ]


@pytest.mark.parametrize(
    ("year", "expected"), [("49", 2049), ("50", 1950), ("999", 2899)]
)
def test_obsolete_year_pivot_is_rfc_defined(year, expected):
    """Two and three digit years use RFC 5322 section 4.3 mappings."""
    mail = _mail(f"01 Jan {year} 12:00GMT")
    assert mail.date is not None
    assert mail.date.year == expected
    assert mail.has_defects is False


@pytest.mark.parametrize("comment", [b"bad\xff", b"Jos\xc3\xa9"])
def test_date_comment_octets_are_checked_after_recovery(comment):
    """Removing a comment must not erase evidence of malformed UTF-8."""
    raw = b"Thu, 1 Oct 2026 12:00:00 +0000 (" + comment + b")"
    mail = mailparser.parse_from_bytes(b"Date: " + raw + b"\r\n\r\n")
    assert mail.date is not None
    assert mail.date.isoformat() == "2026-10-01T12:00:00+00:00"
    if comment == b"bad\xff":
        assert mail.has_defects is True
        assert mail.date_header_defects[0]["reason"] == "invalid-utf8"
        assert mail.date_header_defects[0]["recovered"] is True
        assert r"\udcff" in mail.date_header_defects[0]["raw"]
    else:
        assert mail.date_header_defects == []
    assert mail.mail_json.encode("utf-8")
    assert mail.message is not None
    assert next(mail.message.raw_items())[1].encode("utf-8", "surrogateescape") == raw
