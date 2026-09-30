"""RFC 5322 boundaries and forensic recovery regressions for issue #175."""

import json
import time
from itertools import product

import pytest

import mailparser
from mailparser.const import ADDRESSES_HEADERS
from mailparser.utils import get_addresses


@pytest.mark.parametrize("header", sorted(ADDRESSES_HEADERS))
@pytest.mark.parametrize("padding", [" ", "\t", "\r\n\t"])
def test_issue175_public_outputs(header, padding):
    value = f"billing@trusted.example <{padding}billing@vendor.example >"
    mail = mailparser.parse_from_bytes(
        f"{header}: {value}\r\nSubject: t\r\n\r\nbody\r\n".encode()
    )
    expected = [("billing@trusted.example", "billing@vendor.example")]
    assert mail.headers[header] == expected
    assert mail.mail[header] == expected
    assert json.loads(mail.mail_json)[header] == [list(expected[0])]
    assert mail.has_defects
    diagnostics = mail.address_header_defects
    assert diagnostics[0]["header"] == header
    assert diagnostics[0]["recovered"] is True
    assert "billing@trusted.example" in diagnostics[0]["raw"]
    # Property reads must not append diagnostics or change cached outputs.
    before = json.dumps(diagnostics)
    mail.headers
    mail.mail_partial
    assert json.dumps(mail.address_header_defects) == before
    assert json.loads(getattr(mail, header.replace("-", "_") + "_raw")) == [value]


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            '"billing@trusted.example" < billing@vendor.example >',
            [("billing@trusted.example", "billing@vendor.example")],
        ),
        (
            'bad@name <"sender desk"@vendor.example>',
            [("bad@name", '"sender desk"@vendor.example')],
        ),
        (
            "bad@name (cmt <decoy@example.com>) <real@example.com>",
            [("bad@name", "real@example.com")],
        ),
        ("bad@name (a,b) < real@example.com >", [("bad@name", "real@example.com")]),
        (
            '"Support <decoy@example.com>" <real@example.com>, '
            "bad@name < next@example.com >",
            [
                ("Support <decoy@example.com>", "real@example.com"),
                ("bad@name", "next@example.com"),
            ],
        ),
        (
            '"A\\", <decoy@example.com>" <real@example.com>, '
            "bad@name < next@example.com >",
            [
                ('A", <decoy@example.com>', "real@example.com"),
                ("bad@name", "next@example.com"),
            ],
        ),
        (
            "bad@name < (note) real@example.com (tail) >",
            [("bad@name", "real@example.com")],
        ),
        ("bad@name <a@[IPv6:2001:db8::1]>", [("bad@name", "a@[IPv6:2001:db8::1]")]),
        (
            'Group: "First, Person" <one@example.com>, bad@name < two@example.com >;',
            [("First, Person", "one@example.com"), ("bad@name", "two@example.com")],
        ),
        (
            "Route <@old.example,@relay.example:user@example.com>",
            [("Route", "user@example.com")],
        ),
    ],
)
def test_structural_mailbox_precedence(value, expected):
    assert get_addresses(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "bad@name <one@example.com> <two@example.com>",
        "bad@name <one@example.com",
        "bad@name <<one@example.com>>",
        "bad@name <one@example.com> trailing@example.com",
        '"unterminated <one@example.com>',
        "bad@name (unterminated <one@example.com>",
        'bad@name <one@example.com>, "unterminated <two@example.com>',
    ],
)
def test_ambiguous_items_are_reported_without_promoting_labels(value):
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert all(addr != "bad@name" for _, addr in mail.from_)
    assert mail.address_header_defects
    assert any(not defect["recovered"] for defect in mail.address_header_defects)
    assert mail.has_defects
    assert json.loads(getattr(mail, "from_raw")) == [value]


def test_multiple_candidates_are_visible_but_not_selected():
    value = "bad@name <one@example.com> <two@example.com>"
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.from_ == []
    assert [c["address"] for c in mail.address_header_defects[0]["candidates"]] == [
        "one@example.com",
        "two@example.com",
    ]


def test_diagnostics_cannot_be_shadowed_by_a_wire_header():
    mail = mailparser.parse_from_string(
        "Address_header_defects: forged\r\nFrom: bad@name < real@example.com >\r\n\r\n"
    )
    assert isinstance(mail.mail["address_header_defects"], list)
    assert mail.headers["Address_header_defects"] == "forged"
    assert mail.message is not None
    assert mail.message.get_all("Address_header_defects") == ["forged"]
    count = len(mail.address_header_defects)
    mail.parse()
    assert len(mail.address_header_defects) == count


def test_valid_quoted_name_and_cfws_do_not_get_noncompliance_defects():
    mail = mailparser.parse_from_string(
        'From: "billing@trusted.example" < billing@vendor.example >\r\n\r\n'
    )
    assert not mail.has_defects
    assert mail.address_header_defects == []


DISPLAYS = [
    "",
    "Bob",
    "Bob Smith",
    '"Bob, Smith"',
    "billing@trusted.example",
    '"billing@trusted.example"',
    '"Support <billing@trusted.example>"',
    "(cmt) Bob",
    "Bob (a,b)",
]
ADDRESSES = [
    "<sender@vendor.example>",
    "< sender@vendor.example >",
    "<sender@vendor.example >",
    "< sender@vendor.example>",
    "sender@vendor.example",
    "sender@vendor.example>",
    "<sender@vendor.example",
    '<"sender desk"@vendor.example>',
    "<sender@vendor.example> (a,b)",
    "<sender@vendor.example>(x)",
    "sender@vendor.example (a,b)",
    ">sender@vendor.example",
]
TAILS = [
    "",
    ", other@elsewhere.example",
    ", <other@elsewhere.example>",
    ", Other <other@elsewhere.example> (c,d)",
]


@pytest.mark.parametrize(
    "display,address,tail", list(product(DISPLAYS, ADDRESSES, TAILS))
)
def test_issue175_matrix(display, address, tail):
    value = (display + " " + address).strip() + tail
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    actual = [addr for _, addr in mail.from_]
    # Complete angle-addrs have a determinate mailbox, regardless of label.
    if address.startswith("<") and ">" in address:
        expected = (
            '"sender desk"@vendor.example'
            if '"sender desk"' in address
            else "sender@vendor.example"
        )
        assert actual == [expected] + (["other@elsewhere.example"] if tail else [])
    else:
        # Malformed/ambiguous shapes have no historical-output oracle.
        # They must retain evidence and never promote an address in a label.
        assert "billing@trusted.example" not in actual
        assert json.loads(getattr(mail, "from_raw")) == [value]
        if not actual:
            assert mail.address_header_defects


@pytest.mark.parametrize(
    "value",
    [
        "bad@name <real@example.com>" + " " * 40000,
        "<" * 40000,
        "bad@name " + "(" * 4000 + "comment" + ")" * 4000 + " <real@example.com>",
        "x" * 40000,
    ],
)
def test_hostile_address_input_finishes(value):
    start = time.perf_counter()
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert time.perf_counter() - start < 2
    assert isinstance(mail.from_, list)


@pytest.mark.parametrize(
    "value",
    [
        "Name < local (comment) @ example.com >",
        "Name < local . part @ example . com >",
    ],
)
def test_cfws_is_not_part_of_mailbox_identity(value):
    expected = "local.part@example.com" if ". part" in value else "local@example.com"
    result = get_addresses(value)
    assert len(result) == 1
    assert result[0][1] == expected


def test_malformed_group_boundary_does_not_drop_an_existing_mailbox():
    mail = mailparser.parse_from_string(
        "From: Name <one@example.com>: two@example.com;\r\n\r\n"
    )
    assert mail.from_ == []
    assert mail.has_defects
    assert "one@example.com" in mail.address_header_defects[0]["raw"]


def test_repeated_headers_are_all_inspected_without_changing_first_value():
    mail = mailparser.parse_from_string(
        "From: first@example.com\r\nFrom: bad@name < real@example.com >\r\n\r\n"
    )
    assert mail.from_ == [("", "first@example.com")]
    assert mail.address_header_defects[0]["occurrence"] == 1
    assert len(json.loads(getattr(mail, "from_raw"))) == 2


@pytest.mark.parametrize(
    "value",
    [
        "word " * 16000 + "user@example.com",
        "<one@example.com> " * 16000,
    ],
)
def test_malformed_words_and_many_angles_do_not_trigger_quadratic_work(value):
    start = time.perf_counter()
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.from_ == []
    assert mail.has_defects
    assert time.perf_counter() - start < 2


@pytest.mark.parametrize(
    "value",
    [
        "Route <@old.example: user@example.com>",
        "Route <@old.example,@[IPv6:2001:db8::1]:user@example.com>",
        "Route <,@old.example,,@relay.example: user@example.com>",
    ],
)
def test_obsolete_source_routes_preserve_final_mailbox(value):
    assert get_addresses(value) == [("Route", "user@example.com")]


@pytest.mark.parametrize(
    "value",
    [
        "bad@label: user@example.com;",
        "Name <@route.example>",
        "Name <@route.example,not-a-route:user@example.com>",
        "Name <@route.example,@bad@domain:user@example.com>",
        "Name <not-a-mailbox>",
        "Name <@route.example: user@example.com> stray",
        "Group: first@example.com, second@example.com",
    ],
)
def test_malformed_route_and_group_evidence(value):
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.has_defects
    assert mail.address_header_defects
    assert json.loads(getattr(mail, "from_raw")) == [value]
