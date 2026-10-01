"""Received lexical boundaries and forensic attribution regressions."""

import json

import pytest
from work_budget import bounded_text_work

import mailparser
from mailparser import utils
from mailparser.utils import get_from_clause, parse_received

DATE = "Thu, 01 Oct 2026 12:00:00 +0000"


def _mail(*received, extra=""):
    """Parse explicit wire headers through the public bytes factory."""
    raw = (
        f"Date: {DATE}\r\nFrom: alice@sender.example\r\n"
        "To: bob@recipient.example\r\nSubject: intact\r\n"
        + "".join(f"Received: {value}\r\n" for value in received)
        + extra
        + "\r\nbody"
    )
    return mailparser.parse_from_bytes(raw.encode())


@pytest.mark.parametrize(
    "comment",
    [
        "",
        " (note; relay)",
        " (note by relay)",
        " (outer (inner; by relay))",
        r" (note\); by relay)",
        ' (quoted-looking " by relay; still comment)',
    ],
)
def test_comment_delimiters_do_not_split_received(comment):
    """Comments retain their contents and never select stamp delimiters."""
    origin = "sender.example" + comment
    header = f"from {origin} by mx.example with ESMTP; {DATE}"
    mail = _mail(header)
    parsed = mail.received[0]
    assert parsed["from"] == origin
    assert parsed["by"] == "mx.example"
    assert parsed["date"] == DATE
    assert parsed["date_utc"] == "2026-10-01T12:00:00+00:00"
    assert get_from_clause(header) == origin
    assert mail.message is not None
    assert mail.message.get_all("Received") == [header]
    assert mail.has_defects is False


@pytest.mark.parametrize(
    "recipient",
    [
        '<"a; by b"@recipient.example>',
        '<"a\\"; by b"@recipient.example>',
        '<"two  spaces; from here"@recipient.example>',
        "<user@[by literal; data]>",
    ],
)
def test_recipient_is_one_lexical_value(recipient):
    """Quotes, escapes and domain literals cannot forge clauses or dates."""
    header = f"from sender.example by mx.example with ESMTP for {recipient}; {DATE}"
    mail = _mail(header)
    assert mail.received[0]["for"] == recipient
    assert mail.received[0]["date"] == DATE
    assert mail.received[0]["by"] == "mx.example"
    assert get_from_clause(header) == "sender.example"


@pytest.mark.parametrize(
    ("tail", "reason"),
    [
        ("(unclosed; by mx.example", "unclosed-comment"),
        ('"unclosed; by mx.example', "unclosed-quoted-string"),
        ("[unclosed; by mx.example", "unclosed-domain-literal"),
        ("<unclosed; by mx.example", "unclosed-angle-address"),
    ],
)
def test_unbalanced_header_retains_raw_and_fails_closed(tail, reason):
    """Ambiguous syntax stays evidence and cannot resume a forged chain."""
    bad = f"from attacker.example {tail}; {DATE}"
    forged = f"from forged.example ([8.8.8.8]) by mx.example; {DATE}"
    mail = _mail(bad, forged)
    assert mail.received[1]["raw"] == bad
    assert mail.received[0]["from"] == "forged.example ([8.8.8.8])"
    assert mail.received_header_defects == [
        {
            "reason": reason,
            "raw": bad,
            "recovered": False,
            "header": "received",
            "occurrence": 0,
        }
    ]
    assert mail.has_defects is True
    assert "ReceivedHeaderDefect" in mail.defects_categories
    assert get_from_clause(bad) == ""
    assert mail.get_server_ipaddress("mx.example") is None
    assert mail.subject == "intact"
    assert mail.to == [("", "bob@recipient.example")]
    assert mail.body == "body"
    assert mail.message is not None
    assert mail.message.get_all("Received") == [bad, forged]
    for output in (mail.mail_json, mail.mail_partial_json):
        assert json.loads(output)["received_header_defects"] == (
            mail.received_header_defects
        )
    before = list(mail.defects)
    mail.parse()
    assert mail.defects == before


def test_folded_bad_header_preserves_original_evidence():
    """Raw fallback keeps wire folding instead of replacing its content."""
    bad = f"from sender.example (bad\r\n\tby mx.example; {DATE}"
    mail = _mail(bad)
    assert mail.received[0]["raw"] == bad
    assert mail.received_header_defects[0]["raw"] == bad


def test_wire_header_cannot_shadow_received_diagnostics():
    """Computed diagnostics and a literal header remain distinguishable."""
    bad = f"from sender.example (bad; by mx.example; {DATE}"
    mail = _mail(bad, extra="received_header_defects: spoofed\r\n")
    assert isinstance(mail.mail["received_header_defects"], list)
    assert mail.headers["received_header_defects"] == "spoofed"


@pytest.mark.parametrize(
    "origin",
    [
        "[8.8.8.8] (source [1.2.3.4]; via note)",
        "source.example ([1.2.3.4]:1 helo=[8.8.8.8]; by note)",
        "[1.2.3.4] (account a@b.example HELO 8.8.8.8; by note)",
    ],
)
def test_comment_aware_attribution_excludes_helo_addresses(origin):
    """A recovered comment must preserve the existing HELO exclusion."""
    header = f"from {origin} by mx.example; {DATE}"
    mail = _mail(header)
    assert mail.get_server_ipaddress("mx.example") == "1.2.3.4"


def test_missing_sender_ip_stops_at_authoritative_hop():
    """An IP in a quoted recipient cannot fall through to an older hop."""
    first = (
        "from sender.example (note; by relay) by mx.example "
        f'for <"[8.8.8.8] by q"@recipient.example>; {DATE}'
    )
    older = f"from forged.example ([9.9.9.9]) by mx.example; {DATE}"
    assert _mail(first, older).get_server_ipaddress("mx.example") is None


def test_received_date_comment_semicolon_is_not_reinterpreted():
    """A comment after the stamp separator never replaces the date."""
    date = DATE + " (note; preserved)"
    parsed = _mail(f"from sender.example by mx.example; {date}").received[0]
    assert parsed["date"] == date
    assert parsed["date_utc"] == "2026-10-01T12:00:00+00:00"


def test_deep_comments_scan_without_recursion_or_backtracking():
    """Attacker-chosen comment depth and spacing stay bounded."""
    origin = "sender.example " + "(" * 20000 + "; by " + ")" * 20000
    header = f"from {origin} by mx.example; {DATE}"
    with bounded_text_work(utils, ("split_received",), len(header)):
        assert parse_received(header)["from"] == origin
        assert get_from_clause(header) == origin


@pytest.mark.parametrize(
    "helo",
    [
        'helo="evil by q [8.8.8.8]"',
        "helo=evil by q [8.8.8.8]",
        r"helo=evil\) by q [8.8.8.8]",
        "HELO evil (by q [8.8.8.8])",
    ],
)
def test_helo_text_cannot_inject_ip_after_comment_keyword(helo):
    """Everything after a HELO marker in that comment is sender text."""
    header = f"from sender.example ([1.2.3.4] {helo}) by mx.example; {DATE}"
    assert _mail(header).get_server_ipaddress("mx.example") == "1.2.3.4"


def test_legacy_extra_separator_recovers_with_evidence():
    """A known MTA separator before FOR is recovered without losing it."""
    header = (
        "from sender.example by mx.example with ESMTP id token;\r\n"
        f'\tfor <"a; by b"@recipient.example>; {DATE}'
    )
    mail = _mail(header)
    assert mail.received[0]["date"] == DATE
    assert mail.received[0]["for"] == '<"a; by b"@recipient.example>'
    assert mail.received[0]["date_utc"] == "2026-10-01T12:00:00+00:00"
    assert mail.received_header_defects == [
        {
            "reason": "misplaced-date-separator",
            "raw": header,
            "recovered": True,
            "header": "received",
            "occurrence": 0,
        }
    ]
    assert mail.has_defects is True


def test_invalid_received_octet_does_not_crash_or_disappear():
    """Compatibility Header objects retain their octets as raw evidence."""
    raw = b"from sender\xff.example (unclosed by mx.example"
    mail = mailparser.parse_from_bytes(b"Received: " + raw + b"\r\n\r\n")
    evidence = r"from sender\udcff.example (unclosed by mx.example"
    assert mail.received[0]["raw"] == evidence
    assert mail.received_header_defects[0]["raw"] == evidence
    assert mail.message is not None
    assert next(mail.message.raw_items())[1].encode("utf-8", "surrogateescape") == raw


def test_utf8_received_comment_does_not_crash():
    """Raw-items access accepts a UTF-8 Header without losing its bytes."""
    header = f"from sender.example (José; by relay) by mx.example; {DATE}"
    mail = _mail(header)
    assert mail.received[0]["by"] == "mx.example"
    assert mail.received[0]["date"] == DATE
    assert mail.received[0]["from"].encode("utf-8", "surrogateescape") == (
        "sender.example (José; by relay)".encode()
    )
    assert mail.has_defects is False


def test_opaque_obsolete_received_keeps_raw_without_false_defect():
    """Unknown legacy trace tokens are not proof of malformed syntax."""
    header = "(legacy trace)"
    mail = _mail(header)
    assert mail.received[0]["raw"] == header
    assert mail.has_defects is False


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("from source.example ) by mx.example", "unexpected-comment-close"),
        ("from source.example <<a@example.com>>", "nested-angle-address"),
        (f"from source.example; {DATE}; ignored", "ambiguous-date-separators"),
    ],
)
def test_ambiguous_trace_falls_back_with_reason(value, reason):
    """Malformed separators do not silently select an alternative trace."""
    mail = _mail(value)
    assert mail.received[0]["raw"] == value
    assert mail.received_header_defects[0]["reason"] == reason
    assert mail.received_header_defects[0]["recovered"] is False
    assert get_from_clause(value) == ""


def test_group_spans_ignore_quoted_and_escaped_delimiters():
    """Only structural comments/literals are IP attribution locations."""
    from mailparser.utils import group_spans

    assert group_spans('"fake [8.8.8.8]" (real [1.2.3.4])') == [(18, 32)]
    text = r"source (real [1.2.3.4] escaped\) fake [8.8.8.8])"
    assert group_spans(text) == [(8, len(text) - 1)]


def test_many_ip_groups_have_bounded_attribution_work(monkeypatch):
    """Attacker-chosen groups cannot cause a full rescan for every IP."""
    import mailparser.core as core

    accesses = 0
    original = core.group_spans

    class CountedSpans(list):
        """Count actual span visits independently of machine speed."""

        def __iter__(self):
            nonlocal accesses
            for item in super().__iter__():
                accesses += 1
                yield item

        def __getitem__(self, index):
            nonlocal accesses
            accesses += 1
            return super().__getitem__(index)

    monkeypatch.setattr(
        core, "group_spans", lambda value: CountedSpans(original(value))
    )
    count = 256
    header = "from sender " + "(9.9.9.9) " * count + f"by mx.example; {DATE}"
    mail = _mail(header)
    assert mail.get_server_ipaddress("mx.example") == "9.9.9.9"
    assert accesses < 20 * count


@pytest.mark.parametrize("malformed", [False, True])
def test_invalid_received_evidence_is_utf8_serializable(malformed):
    """Invalid trace bytes survive in evidence without breaking JSON sinks."""
    raw = b"from sender\xff.example " + (
        b"(unclosed by mx.example"
        if malformed
        else b"([9.9.9.9]) by mx.example; " + DATE.encode()
    )
    mail = mailparser.parse_from_bytes(b"Received: " + raw + b"\r\n\r\n")
    rendered = mail.mail_json.encode("utf-8")
    assert b"\\\\udcff" in rendered
    assert mail.has_defects is True
    assert mail.message is not None
    assert next(mail.message.raw_items())[1].encode("utf-8", "surrogateescape") == raw


@pytest.mark.parametrize(
    "argument",
    ['"x by y" [8.8.8.8]', "host [8.8.8.8]", "x (nested [8.8.8.8])", r"x\) [8.8.8.8]"],
)
@pytest.mark.parametrize("real_ip", ["(1.2.3.4) ", ""])
def test_comment_initial_helo_cannot_supply_sender_ip(argument, real_ip):
    """A comment-initial HELO argument cannot override the connection IP."""
    raw = (
        f"Received: from source {real_ip}(HELO {argument}) by mx.example; {DATE}\r\n"
        f"Received: from forged ([8.8.4.4]) by mx.example; {DATE}\r\n\r\n"
    )
    mail = mailparser.parse_from_string(raw)
    assert mail.get_server_ipaddress("mx.example") == ("1.2.3.4" if real_ip else None)


@pytest.mark.parametrize(
    "comment",
    ["( helo [45.33.32.156])", "(\thelo [45.33.32.156])", "((helo [45.33.32.156]))"],
)
def test_literal_helo_hostname_after_comment_fws(comment):
    """Formatting or nesting cannot promote the sender's first-token IP."""
    header = f"from 8.8.8.8 {comment} by mx.example; {DATE}"
    assert _mail(header).get_server_ipaddress("mx.example") == "45.33.32.156"
