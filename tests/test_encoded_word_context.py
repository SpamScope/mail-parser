"""RFC 2047 display words retain their RFC 5322 lexical context."""

import json

import pytest
from work_budget import bounded_address_work, bounded_encoded_word_work

import mailparser
from mailparser.utils import get_addresses


@pytest.mark.parametrize(
    "name, expected",
    [
        ('"=?utf-8?Q?Jos=C3=A9?="', "=?utf-8?Q?Jos=C3=A9?="),
        ("=?utf-8?Q?Jos=C3=A9?=", "José"),
        ('"Alice Example"', "Alice Example"),
        (
            '"=?utf-8?Q?Jos=C3=A9?=" =?utf-8?Q?Andr=C3=A9?=',
            "=?utf-8?Q?Jos=C3=A9?= André",
        ),
        (
            "=?utf-8?Q?Jos=C3=A9?=\r\n\t=?utf-8?Q?_Andr=C3=A9?=",
            "José André",
        ),
        ("=?utf-8?Q?A=2CB=3Cfake=40example.com=3E?=", "A,B<fake@example.com>"),
        ("=?utf-8?Q?=3D=3Futf-8=3FQ=3FAlice=3F=3D?=", "=?utf-8?Q?Alice?="),
        ('"A\\" =?utf-8?Q?Jos=C3=A9?="', 'A" =?utf-8?Q?Jos=C3=A9?='),
        ("=?no-such-charset?Q?=FF?=", "=?no-such-charset?Q?=FF?="),
        ("=?utf-8?Q?=FF?=", "=?utf-8?Q?=FF?="),
        ("José", "José"),
    ],
)
@pytest.mark.parametrize("factory", ["string", "bytes"])
def test_display_words_preserve_quote_context(name, expected, factory):
    """Decode eligible words once without changing mailbox boundaries."""
    value = f"{name} <alice@example.com>, Bob <bob@example.com>"
    raw = f"From: {value}\r\nTo: neighbor@example.com\r\n\r\n"
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if factory == "bytes"
        else mailparser.parse_from_string(raw)
    )
    assert mail.from_ == [(expected, "alice@example.com"), ("Bob", "bob@example.com")]
    assert mail.to == [("", "neighbor@example.com")]
    decoded_json = mail.from_json
    assert isinstance(decoded_json, str)
    assert json.loads(decoded_json) == [list(x) for x in mail.from_]
    if value.isascii() or factory == "string":
        raw_json = mail.from_raw
        assert isinstance(raw_json, str)
        assert json.loads(raw_json) == [value]
    assert mail.address_header_defects == []


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Alice (=?utf-8?Q?Andr=C3=A9?=) <alice@example.com>", "Alice (André)"),
        ("alice@example.com (=?utf-8?Q?Andr=C3=A9?=)", "André"),
        ("Alice (=?utf-8?Q?A=28B=29=5CC?=) <alice@example.com>", "Alice (A(B)\\C)"),
    ],
)
def test_comment_words_keep_special_characters_as_data(value, expected):
    """Decoded parentheses and escapes cannot change comment boundaries."""
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.from_ == [(expected, "alice@example.com")]
    assert not mail.has_defects


def test_get_addresses_retains_undecoded_name_contract():
    """The helper's default still returns literal encoded display words."""
    value = "=?utf-8?Q?Jos=C3=A9?= <alice@example.com>"
    assert get_addresses(value) == [("=?utf-8?Q?Jos=C3=A9?=", "alice@example.com")]


def test_recovery_keeps_raw_name_evidence_and_a_valid_neighbor():
    """Malformed display syntax remains diagnosed after rendering."""
    value = (
        'bad@label "=?utf-8?Q?Jos=C3=A9?=" <alice@example.com>, Bob <bob@example.com>'
    )
    mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.from_ == [
        ("bad@label =?utf-8?Q?Jos=C3=A9?=", "alice@example.com"),
        ("Bob", "bob@example.com"),
    ]
    assert mail.has_defects
    assert mail.address_header_defects[0]["reason"] == "invalid-display-name"
    assert mail.address_header_defects[0]["raw"] == value.split(", ")[0]
    assert mail.address_header_defects[0]["recovered"] is True


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            '"José =?utf-8?Q?Alice?=" <alice@example.com>',
            [("José =?utf-8?Q?Alice?=", "alice@example.com")],
        ),
        (
            'Name <"=?utf-8?Q?Alice?="@example.com>',
            [("Name", '"=?utf-8?Q?Alice?="@example.com')],
        ),
        (
            "=?utf-8?Q?A=22B=5CC?= <alice@example.com>",
            [('A"B\\C', "alice@example.com")],
        ),
        (
            "=?utf-8?Q?A=0D=0AB?= <alice@example.com>",
            [("=?utf-8?Q?A=0D=0AB?=", "alice@example.com")],
        ),
        (
            "=?utf-8?Q?Alice?=suffix <alice@example.com>",
            [("=?utf-8?Q?Alice?=suffix", "alice@example.com")],
        ),
    ],
)
def test_rendering_cannot_reinterpret_address_or_escaped_text(value, expected):
    """Unicode adaptation and decoded specials preserve lexical identity."""
    mail = mailparser.parse_from_bytes(f"From: {value}\r\n\r\n".encode())
    assert mail.from_ == expected


def test_encoded_names_do_not_hide_invalid_utf8_evidence():
    """Keep invalid-octet diagnostics and the neighboring valid mailbox."""
    value = (
        b'"=?utf-8?Q?Alice?=" <a\xff@example.com>, =?utf-8?Q?Bob?= <bob@example.com>'
    )
    mail = mailparser.parse_from_bytes(b"From: " + value + b"\r\n\r\n")
    assert mail.from_ == [("Bob", "bob@example.com")]
    defect = mail.address_header_defects[0]
    assert defect["reason"] == "invalid-utf8"
    assert "\\udcff" in defect["raw"]
    assert defect["recovered"] is False
    assert defect["header"] == "from"
    assert defect["occurrence"] == 0
    assert defect["candidates"] == []


def test_many_display_words_remain_bounded():
    """A long encoded phrase has linear-sized output and one mailbox."""
    count = 8000
    value = "=?utf-8?Q?A?= " * count + "<alice@example.com>"
    with bounded_address_work(len(value)):
        with bounded_encoded_word_work(count, len(value)):
            mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert mail.from_ == [("A" * count, "alice@example.com")]


@pytest.mark.parametrize("context", ["phrase", "comment"])
def test_overlong_encoded_word_is_recovered_and_reported(context):
    """Recover the existing corpus name despite its 76-character word."""
    word = (
        "=?UTF-8?B?0YHQu9GD0LbQsdCwINCk0J3QoSDQlNCw0L3QuNC40Lsg0KHRg9Cy0L7RgNC+0LI=?="
    )
    expected = "служба ФНС Даниил Суворов"
    assert len(word) == 76
    if context == "phrase":
        value = f"{word} <alice@example.com>"
    else:
        value = f"alice@example.com ({word})"
    mail = mailparser.parse_from_bytes(
        f"From: {value}, Bob <bob@example.com>\r\n\r\n".encode()
    )
    assert mail.from_ == [(expected, "alice@example.com"), ("Bob", "bob@example.com")]
    assert mail.has_defects
    assert mail.address_header_defects == [
        {
            "reason": "overlong-encoded-word",
            "raw": value,
            "recovered": True,
            "candidates": [
                {
                    "display_name": expected if context == "phrase" else "",
                    "address": "alice@example.com",
                }
            ],
            "header": "from",
            "occurrence": 0,
        }
    ]


def test_overlong_quoted_encoded_looking_text_remains_literal():
    """RFC 2047's length limit does not apply to quoted literal text."""
    word = "=?utf-8?Q?" + "A" * 100 + "?="
    mail = mailparser.parse_from_string(f'From: "{word}" <alice@example.com>\r\n\r\n')
    assert mail.from_ == [(word, "alice@example.com")]
    assert not mail.has_defects


@pytest.mark.parametrize("terminated", [True, False])
def test_long_encoded_tokens_and_failed_matches_remain_bounded(terminated):
    """Matching a long invalid token must not repeatedly scan its suffix."""
    count = 4000
    word = "=?utf-8?Q?" + "A" * 100 + ("?=" if terminated else "")
    value = (word + " ") * count + "<alice@example.com>"
    with bounded_address_work(len(value)):
        with bounded_encoded_word_work(count, len(value)):
            mail = mailparser.parse_from_string(f"From: {value}\r\n\r\n")
    assert len(mail.from_) == 1
    assert mail.from_[0][1] == "alice@example.com"
    if terminated:
        assert mail.from_[0][0] == "A" * (100 * count)
        assert mail.address_header_defects[0]["reason"] == "overlong-encoded-word"
    else:
        assert mail.from_[0][0] == " ".join([word] * count)


@pytest.mark.parametrize("charset", ["unicode_escape", "raw_unicode_escape"])
@pytest.mark.parametrize("comment", [False, True])
def test_encoded_word_surrogate_is_evidence_not_output(charset, comment):
    """Codec-produced surrogates cannot crash JSON or hide the mailbox."""
    word = f"=?{charset}?b?XHVkODAw?="
    field = f"a@example.com ({word})" if comment else f"{word} <a@example.com>"
    parsed = mailparser.parse_from_string(f"From: {field}\r\n\r\n")
    assert parsed.mail_json.encode("utf-8")
    assert parsed.from_ == [(word, "a@example.com")]
    assert parsed.address_header_defects[0]["reason"] == "invalid-encoded-word"
    assert parsed.address_header_defects[0]["recovered"] is True
    assert parsed.address_header_defects[0]["raw"] == field
