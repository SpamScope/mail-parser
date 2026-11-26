"""RFC 2231 parameters the email package cannot use do not stop a parse.

The standard library reads parameters on its own while it parses and
flattens a message, and raises outside the ``MailParser*`` hierarchy on
four kinds of value: a charset that refuses the octets, sections it
cannot sort, a section number ``int()`` refuses, and a ``(charset,
language, value)`` tuple where it expects a codec name.  Which of them
raise, and how repeated sections are ordered, depends on the Python
version; what mail-parser returns and reports does not, except where a
test says so.
"""

import base64
import email
import email.errors
import email.message
import email.utils
import io
from email.message import Message

import pytest

import mailparser
from mailparser import utils
from mailparser.exceptions import MailParserRecursionError
from mailparser.utils import (
    RecoveringMessage,
    mime_boundary,
    mime_charset,
    mime_filename,
)

_FACTORIES = pytest.mark.parametrize("factory", ["bytes", "string", "file"])
_CHILDREN = (
    b"--abc\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
    b"--abc\r\nContent-Type: application/octet-stream\r\n"
    b'Content-Disposition: attachment; filename="a.bin"\r\n\r\ndata\r\n'
    b"--abc--\r\n"
)


def _int_converts_any_number():
    """Tell whether this Python lacks the limit on the digits of an int."""
    try:
        int(_LONG_NUMBER)
    except ValueError:
        return False
    return True


# More digits than the default limit of ``int()``, where it has one.
_LONG_NUMBER = "9" * 5000
_CONVERTS_ANY_NUMBER = _int_converts_any_number()


def _email_package_keeps_the_order_of_equal_sections():
    """Tell whether this Python has the fix of 3.13.18, 3.14.10, 3.15.2."""
    probe = Message()
    probe["Content-Type"] = "t/p; n*=b; n*=a"
    return probe.get_param("n") == (None, None, "ba")


_FIXED_EMAIL_PACKAGE = _email_package_keeps_the_order_of_equal_sections()


def _parse(raw, factory, tmp_path):
    if factory == "file":
        path = tmp_path / "message.eml"
        path.write_bytes(raw)
        return mailparser.parse_from_file(path)
    if factory == "string":
        return mailparser.parse_from_string(
            raw.decode("utf-8", "surrogateescape")
        )
    return mailparser.parse_from_bytes(raw)


def _mime_details(mail):
    return [
        detail
        for defect in mail.defects
        for detail in defect.get("mime-headers", [])
    ]


def _continuation_details(part, header, value):
    """The diagnostic of a malformed parameter list, on every Python."""
    return [
        f"MimeHeaderDefect: part {part}, {header}[0]: "
        f"invalid-parameter-continuation; raw={value!r}"
    ]


@_FACTORIES
@pytest.mark.parametrize(
    "parameter, raw_value",
    [
        pytest.param(
            "boundary*=undefined''abc",
            ("undefined", "", "abc"),
            id="undefined",
        ),
        pytest.param("boundary*=idna''abc", ("idna", "", "abc"), id="idna"),
        pytest.param(
            "boundary*0*=undefined'en'a; boundary*1=bc",
            ("undefined", "en", "abc"),
            id="continued",
        ),
        pytest.param(
            "boundary*=a%00b'en'abc",
            ("a\x00b", "en", "abc"),
            id="nul in charset",
        ),
    ],
)
def test_undecodable_boundary_is_read_as_latin_1(
    parameter, raw_value, factory, tmp_path
):
    """The parts are split on the octets of the value, read as Latin-1."""
    raw = (
        f"Content-Type: multipart/mixed; {parameter}\r\n\r\n".encode()
        + _CHILDREN
    )
    mail = _parse(raw, factory, tmp_path)
    root, text, attachment = mail.mime_tree

    assert mail.text_plain == ["hi"]
    assert [a["filename"] for a in mail.attachments] == ["a.bin"]
    assert base64.b64decode(mail.attachments[0]["payload"]) == b"data"
    assert mail.message is not None
    assert root["boundary"] == mail.message.get_boundary() == "abc"
    assert mail.has_defects is True
    assert mail.defects_categories == {"MimeHeaderDefect"}
    assert root["defects"] == ["MimeHeaderDefect"]
    assert text["defects"] == attachment["defects"] == []
    assert _mime_details(mail) == [
        f"MimeHeaderDefect: part 0, invalid-boundary-parameter: "
        f"raw={raw_value!r}"
    ]
    mail.mail_json.encode("utf-8")
    mail.mime_tree_json.encode("utf-8")


@_FACTORIES
def test_undecodable_boundary_is_percent_decoded(factory, tmp_path):
    """As the email package reads a value whose charset it does not know."""
    raw = (
        b"Content-Type: multipart/mixed; boundary*=undefined''%41%42\r\n\r\n"
        b"--AB\r\nContent-Type: text/plain\r\n\r\nhi\r\n--AB--\r\n"
    )
    mail = _parse(raw, factory, tmp_path)

    assert mail.text_plain == ["hi"]
    assert mail.mime_tree[0]["boundary"] == "AB"
    assert _mime_details(mail) == [
        "MimeHeaderDefect: part 0, invalid-boundary-parameter: "
        "raw=('undefined', '', 'AB')"
    ]


@pytest.mark.parametrize("as_bytes", [False, True], ids=["string", "bytes"])
@pytest.mark.parametrize(
    "parameter, always_diagnosed",
    [
        ("boundary*=undefined''abc", True),
        ("boundary*=idna''q", True),
        # Python 3.13 decodes this one, to an empty boundary.
        ("boundary*=punycode'en'%FF", False),
        ("boundary*1*=undefined'en'%FF", True),
    ],
)
def test_one_header_line_cannot_stop_the_parse(
    parameter, always_diagnosed, as_bytes
):
    """Each reported one-line message parses, without a boundary to find."""
    raw = f"Content-Type: multipart/mixed; {parameter}\r\n\r\n"
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if as_bytes
        else mailparser.parse_from_string(raw)
    )
    (root,) = mail.mime_tree

    assert isinstance(mail.message, Message)
    assert root["content_type"] == "multipart/mixed"
    assert mail.has_defects is True
    assert "StartBoundaryNotFoundDefect" in root["defects"]
    if always_diagnosed:
        assert "MimeHeaderDefect" in root["defects"]
        assert "invalid-boundary-parameter: raw=" in _mime_details(mail)[0]
    mail.mail_json.encode("utf-8")


@_FACTORIES
def test_unsortable_name_sections_are_joined(factory, tmp_path):
    """``name*`` next to ``name*1`` is section 0, and always reported."""
    value = "text/plain; name*=x; name*1=y"
    mail = _parse(
        f"Content-Type: {value}\r\n\r\nhi\r\n".encode(), factory, tmp_path
    )
    (root,) = mail.mime_tree

    assert [a["filename"] for a in mail.attachments] == ["xy"]
    assert base64.b64decode(mail.attachments[0]["payload"]) == b"hi\r\n"
    assert root["filename"] == "xy"
    assert _mime_details(mail) == _continuation_details(
        0, "content-type", value
    )
    assert mail.has_defects is True
    assert root["defects"] == ["MimeHeaderDefect"]


@_FACTORIES
@pytest.mark.parametrize(
    "value, filename",
    [
        pytest.param(
            "attachment; filename*0=report; filename*=utf-8''evil.exe; "
            "filename*1=.pdf",
            "report.pdf",
            id="section 0 wins",
        ),
        pytest.param(
            "attachment; filename*=invoice; filename*=.exe; filename*1=.pdf",
            "invoice.exe.pdf",
            id="equal numbers keep the order of the header",
        ),
        pytest.param(
            "attachment; filename*1*=%2Epdf; filename*=utf-8''caf%C3%A9",
            "café.pdf",
            id="charset of the unnumbered section",
        ),
        pytest.param(
            "attachment; filename*0=b.exe; filename*0=a",
            "b.exea",
            id="repeated number",
        ),
        pytest.param(
            "attachment; filename*=utf-8''b; filename*=utf-8''a",
            "butf-8''a",
            id="two sections without a number",
        ),
    ],
)
def test_dropped_or_reordered_section_is_reported(
    value, filename, factory, tmp_path
):
    """The name is the same on every Python, and so is the evidence.

    A fixed email package reads these lists without a word, and an older
    one orders repeated sections by their text: the section that is
    dropped or moved would vanish from a parse with no defect.
    """
    raw = f"Content-Disposition: {value}\r\n\r\nhi\r\n".encode()
    mail = _parse(raw, factory, tmp_path)

    assert [a["filename"] for a in mail.attachments] == [filename]
    assert mail.has_defects is True
    assert mail.mime_tree[0]["defects"] == ["MimeHeaderDefect"]
    assert _mime_details(mail) == _continuation_details(
        0, "content-disposition", value
    )


@_FACTORIES
def test_repeated_charset_section_names_no_charset(factory, tmp_path):
    """Older releases read ``autf-8`` here, by sorting the two values."""
    value = "text/plain; charset*=utf-8''%E2%82; charset*=a"
    raw = f"Content-Type: {value}\r\n\r\n".encode() + "café".encode()
    mail = _parse(raw, factory, tmp_path)

    assert mail.mime_tree[0]["charset"] is None
    assert mail.text_plain == ["café"]
    assert mail.mime_tree[0]["defects"] == ["MimeHeaderDefect"]
    assert _mime_details(mail) == _continuation_details(
        0, "content-type", value
    )


@_FACTORIES
def test_parameter_given_twice_is_no_repeated_section(factory, tmp_path):
    """Only RFC 2231 sections are numbered: the first plain value wins."""
    raw = b"Content-Type: text/plain; name=a.txt; name=b.txt\r\n\r\nhi\r\n"
    mail = _parse(raw, factory, tmp_path)

    assert [a["filename"] for a in mail.attachments] == ["a.txt"]
    assert mail.has_defects is False


@_FACTORIES
def test_unsortable_sections_of_a_disposition(factory, tmp_path):
    """The body of the part is kept; ``name`` is no disposition filename."""
    value = "inline; name*=; name*1*="
    mail = _parse(
        f"Content-Disposition: {value}\r\n\r\nhi\r\n".encode(),
        factory,
        tmp_path,
    )

    assert mail.text_plain == ["hi\r\n"]
    assert mail.attachments == []
    assert _mime_details(mail) == _continuation_details(
        0, "content-disposition", value
    )
    assert mail.has_defects is True


@_FACTORIES
def test_unsortable_boundary_sections_still_split_the_parts(factory, tmp_path):
    """The email package reads this boundary itself, while it parses."""
    value = "multipart/mixed; boundary*=ab; boundary*1=c"
    mail = _parse(
        f"Content-Type: {value}\r\n\r\n".encode() + _CHILDREN,
        factory,
        tmp_path,
    )
    root, text, attachment = mail.mime_tree

    assert mail.text_plain == ["hi"]
    assert [a["filename"] for a in mail.attachments] == ["a.bin"]
    assert root["boundary"] == "abc"
    assert text["defects"] == attachment["defects"] == []
    assert _mime_details(mail) == _continuation_details(
        0, "content-type", value
    )


@_FACTORIES
@pytest.mark.parametrize(
    "broken", ["", "; x*=a; x*1=b"], ids=["alone", "next"]
)
def test_neighbours_of_unsortable_sections_are_intact(
    broken, factory, tmp_path
):
    """A parameter reads the same with and without the broken one."""
    raw = (
        f"Content-Type: multipart/mixed; boundary=abc{broken}\r\n\r\n"
        f"--abc\r\nContent-Type: text/plain; charset=iso-8859-1{broken}\r\n"
        f"\r\n"
    ).encode() + (
        b"caf\xe9\r\n--abc\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment;"
        b" filename*0*=utf-8''caf%C3%A9; filename*1=.bin"
        + broken.encode()
        + b"\r\n\r\ndata\r\n--abc--\r\n"
    )
    mail = _parse(raw, factory, tmp_path)
    root, text, attachment = mail.mime_tree

    assert root["boundary"] == "abc"
    assert mail.text_plain == ["café"]
    assert text["charset"] == "iso-8859-1"
    assert [a["filename"] for a in mail.attachments] == ["café.bin"]
    assert attachment["filename"] == "café.bin"
    assert base64.b64decode(mail.attachments[0]["payload"]) == b"data"
    expected = ["MimeHeaderDefect"] if broken else []
    assert (
        root["defects"] == text["defects"] == attachment["defects"] == expected
    )


@_FACTORIES
def test_nested_part_carries_its_own_defect(factory, tmp_path):
    """Only the part with the broken parameter is flagged."""
    name = "text/plain; name*=x; name*1=y"
    raw = (
        "Content-Type: multipart/mixed; boundary=outer\r\n\r\n"
        "--outer\r\nContent-Type: text/plain\r\n\r\nfirst\r\n"
        "--outer\r\nContent-Type: multipart/mixed; "
        "boundary*=undefined''inner\r\n\r\n"
        f"--inner\r\nContent-Type: {name}\r\n\r\nnested\r\n"
        "--inner--\r\n"
        "--outer\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename*=utf-8''caf%C3%A9.bin\r\n"
        "\r\n"
        "last\r\n--outer--\r\n"
    ).encode()
    mail = _parse(raw, factory, tmp_path)
    tree = mail.mime_tree
    continuation = _continuation_details(3, "content-type", name)

    assert [(node["parent"], node["content_type"]) for node in tree] == [
        (None, "multipart/mixed"),
        (0, "text/plain"),
        (0, "multipart/mixed"),
        (2, "text/plain"),
        (0, "application/octet-stream"),
    ]
    assert tree[2]["boundary"] == "inner"
    assert tree[3]["filename"] == "xy"
    assert [node["defects"] for node in tree] == [
        [],
        [],
        ["MimeHeaderDefect"],
        ["MimeHeaderDefect"],
        [],
    ]
    assert _mime_details(mail) == [
        "MimeHeaderDefect: part 2, invalid-boundary-parameter: "
        "raw=('undefined', '', 'inner')",
        *continuation,
    ]
    assert mail.text_plain == ["first"]
    assert [a["filename"] for a in mail.attachments] == ["xy", "café.bin"]
    assert [base64.b64decode(a["payload"]) for a in mail.attachments] == [
        b"nested",
        b"last",
    ]


@_FACTORIES
@pytest.mark.parametrize(
    "header, filename",
    [
        pytest.param(
            "Content-Disposition: attachment; filename*=utf-8''caf%C3%A9.txt",
            "café.txt",
            id="extended",
        ),
        pytest.param(
            'Content-Disposition: attachment; filename*0="a"; '
            'filename*1="b.txt"',
            "ab.txt",
            id="continued",
        ),
        pytest.param(
            "Content-Disposition: attachment; filename*1=b.txt; filename*0=a",
            "ab.txt",
            id="continued out of order",
        ),
        pytest.param(
            "Content-Disposition: attachment;"
            " filename*0*=iso-8859-1'en'%E9; filename*1*=%E8; filename*2=.txt",
            "éè.txt",
            id="mixed",
        ),
        pytest.param(
            "Content-Type: text/plain; name*=us-ascii'en'report.pdf",
            "report.pdf",
            id="extended name",
        ),
    ],
)
def test_conforming_filename_parameters_decode(
    header, filename, factory, tmp_path
):
    """RFC 2231 sections 3, 4 and 4.1: nothing is recovered or reported."""
    mail = _parse(f"{header}\r\n\r\nhi\r\n".encode(), factory, tmp_path)

    assert [a["filename"] for a in mail.attachments] == [filename]
    assert mail.mime_tree[0]["filename"] == filename
    assert mail.has_defects is False


@_FACTORIES
@pytest.mark.parametrize(
    "parameter", ["boundary*0=ab; boundary*1=c", "boundary*=us-ascii''abc"]
)
def test_conforming_boundary_parameters_decode(parameter, factory, tmp_path):
    """A boundary the email package decodes is not diagnosed."""
    raw = (
        f"Content-Type: multipart/mixed; {parameter}\r\n\r\n".encode()
        + _CHILDREN
    )
    mail = _parse(raw, factory, tmp_path)

    assert mail.mime_tree[0]["boundary"] == "abc"
    assert mail.text_plain == ["hi"]
    assert [a["filename"] for a in mail.attachments] == ["a.bin"]
    assert mail.has_defects is False


@_FACTORIES
def test_conforming_charset_parameter_decodes(factory, tmp_path):
    """An RFC 2231 charset selects the codec of the body."""
    raw = (
        b"Content-Type: text/plain; charset*=us-ascii'en'iso-8859-1\r\n\r\n"
        b"caf\xe9"
    )
    mail = _parse(raw, factory, tmp_path)

    assert mail.text_plain == ["café"]
    assert mail.mime_tree[0]["charset"] == "iso-8859-1"
    assert mail.has_defects is False


@_FACTORIES
def test_boundary_of_a_part_that_is_not_multipart_is_not_read(
    factory, tmp_path
):
    """Nothing decodes this parameter, so nothing can report it."""
    raw = b"Content-Type: text/plain; boundary*=idna''A%80\r\n\r\nhi\r\n"
    mail = _parse(raw, factory, tmp_path)

    assert mail.text_plain == ["hi\r\n"]
    assert mail.mime_tree[0]["boundary"] is None
    assert mail.has_defects is False


@_FACTORIES
@pytest.mark.parametrize(
    "parameters, filename, charset",
    [
        pytest.param(
            "name*1*=x-unknown'en'q; charset*0*=idna'en'%FF",
            "q",
            None,
            id="undecodable charset",
        ),
        pytest.param(
            "name=a.html; charset*=us-ascii'en'utf-8",
            "a.html",
            "utf-8",
            id="conforming charset",
        ),
        pytest.param(
            "name=a.html; charset*=''x-unknown",
            "a.html",
            "x-unknown",
            id="unknown charset",
        ),
    ],
)
def test_rfc2231_charset_does_not_stop_reading_a_payload(
    parameters, filename, charset, factory, tmp_path
):
    """Up to Python 3.11 ``get_payload()`` decodes with the tuple.

    These octets are not base64: every Python shows them replaced.
    """
    raw = (
        b"Content-Transfer-Encoding: base64\r\n"
        b"Content-Type: text/html; "
        + parameters.encode()
        + b"\r\n\r\n\xff\xfe\r\n"
    )
    mail = _parse(raw, factory, tmp_path)
    (attachment,) = mail.attachments

    assert attachment["filename"] == filename
    assert attachment["binary"] is True
    assert attachment["content_transfer_encoding"] == "base64"
    assert attachment["payload"] == "\ufffd\ufffd\r\n"
    assert mail.mime_tree[0]["charset"] == charset
    assert mail.has_defects is False
    assert mail.message is not None
    assert b"\xff\xfe" in mail.message.as_bytes()
    mail.mail_json.encode("utf-8")


def _container(child_type, body):
    """An attached multipart: its child is flattened into the payload."""
    return (
        b"Content-Type: multipart/mixed; boundary=q\r\n"
        b"Content-Disposition: attachment; filename=c.bin\r\n\r\n"
        b"--q\r\nContent-Type: "
        + child_type
        + b"\r\n\r\n"
        + body
        + b"\r\n--q--\r\n"
    )


@pytest.mark.parametrize("factory", ["bytes", "file"])
@pytest.mark.parametrize(
    "extended, plain, body, text",
    [
        pytest.param(
            b"text/plain; charset*=us-ascii'en'iso-8859-1",
            b"text/plain; charset=iso-8859-1",
            b"caf\xe9",
            "caf=E9",
            id="iso-8859-1",
        ),
        pytest.param(
            b"text/plain; charset*0=iso-; charset*1=8859-1",
            b"text/plain; charset=iso-8859-1",
            b"caf\xe9",
            "caf=E9",
            id="continued",
        ),
        pytest.param(
            b"text/plain; charset*=utf-8''utf-8",
            b"text/plain; charset=utf-8",
            b"caf\xc3\xa9",
            "Y2Fmw6k=\n",
            id="utf-8",
        ),
    ],
)
def test_rfc2231_charset_flattens_as_the_plain_charset(
    extended, plain, body, text, factory, tmp_path
):
    """The generator hands ``set_payload()`` the tuple of the parameter.

    A decodable charset gives one payload, whichever way it is written,
    and that payload is text.
    """
    mail = _parse(_container(extended, body), factory, tmp_path)
    reference = _parse(_container(plain, body), factory, tmp_path)
    (attachment,) = mail.attachments

    assert attachment["payload"] == reference.attachments[0]["payload"]
    assert attachment["payload"].endswith(f"\n\n{text}")
    assert attachment["filename"] == "c.bin"
    assert mail.mime_tree[1]["charset"] == reference.mime_tree[1]["charset"]
    assert mail.has_defects is False
    mail.mail_json.encode("utf-8")


def test_wrong_use_of_get_payload_still_raises():
    """Only the charset tuple of old Python releases is recovered."""
    message = RecoveringMessage()
    message.set_payload("text")

    with pytest.raises(TypeError):
        message.get_payload(0)


@pytest.mark.parametrize("factory", ["bytes", "file"])
@pytest.mark.parametrize(
    "charset",
    [
        "charset*=us-ascii''%FF",
        "charset*=iso-8859-1''%E9",
        "charset*0*=''%FF; charset*1=x",
        "charset*=utf-8''%C3%A9",
    ],
)
def test_rfc2231_charset_that_names_no_codec_flattens_as_bytes(
    charset, factory, tmp_path
):
    """No header is made up and no octet is replaced.

    Without a codec the generator would store the text it could not
    decode and write an empty ``Content-Transfer-Encoding``.
    """
    raw = (
        b"Content-Type: message/rfc822\r\n"
        b"Content-Disposition: attachment; filename=m.eml\r\n\r\n"
        b"Content-Type: text/plain; " + charset.encode() + b"\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\ncaf\xe9"
    )
    mail = _parse(raw, factory, tmp_path)
    payload = mail.attachments[0]["payload"]

    assert "Content-Transfer-Encoding: 8bit\n" in payload
    assert "Content-Transfer-Encoding: \n" not in payload
    assert "\ufffd" not in payload
    assert payload.encode("utf-8", "surrogateescape").endswith(b"\n\ncaf\xe9")


def test_rfc2231_charset_of_a_text_string_is_left_as_written():
    """Nothing is re-encoded when the body holds no undecoded octet."""
    child = "Content-Type: text/plain; charset*=us-ascii'en'utf-8"
    raw = _container(child[14:].encode(), "café".encode()).decode()
    mail = mailparser.parse_from_string(raw)

    assert mail.attachments[0]["payload"] == f"{child}\n\ncafé"
    assert mail.has_defects is False


@pytest.mark.parametrize("as_bytes", [False, True], ids=["string", "bytes"])
def test_part_recovered_from_the_epilogue_is_built_safely(as_bytes):
    """A hidden multipart with an undecodable boundary is still recovered."""
    raw = (
        "From: a@b\nContent-Type: multipart/mixed; boundary=A\n\n"
        "--A\nContent-Type: multipart/alternative; boundary=B\n\nx\n--A--\n"
        "--A\nContent-Type: multipart/mixed; boundary*=undefined''C\n\n"
        "--C\nContent-Type: text/plain\n\nhidden\n--C--\n--A--\n"
    )
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if as_bytes
        else mailparser.parse_from_string(raw)
    )
    recovered = mail.mime_tree[-1]

    assert recovered["recovered"] is True
    assert recovered["content_type"] == "multipart/mixed"
    assert recovered["boundary"] == "C"
    assert recovered["defects"] == ["MimeHeaderDefect"]
    assert _mime_details(mail) == [
        "MimeHeaderDefect: part 2, invalid-boundary-parameter: "
        "raw=('undefined', '', 'C')"
    ]


_EPILOGUE = (
    "From: a@b\nContent-Type: multipart/mixed; boundary=A\n\n"
    "--A\nContent-Type: multipart/alternative; boundary=B\n\nx\n--A--\n--A\n"
)


@pytest.mark.parametrize("as_bytes", [False, True], ids=["string", "bytes"])
def test_sub_parts_of_the_epilogue_part_are_reported_on_it(as_bytes):
    """They are no entries of the tree: each is named by its position."""
    name = "text/plain; name*=x; name*1=y"
    disposition = "attachment; filename*0=b.exe; filename*0=a"
    raw = (
        _EPILOGUE + "Content-Type: message/rfc822\n"
        "Content-Disposition: attachment; filename=m.eml\n\n"
        "Subject: inner\n"
        "Content-Type: multipart/mixed; boundary*=undefined''abc\n\n"
        f"--abc\nContent-Type: {name}\n\nhidden\n"
        "--abc\nContent-Type: text/plain\n\nfine\n"
        f"--abc\nContent-Disposition: {disposition}\n\nlast\n"
        "--abc--\n--A--\n"
    )
    mail = (
        mailparser.parse_from_bytes(raw.encode())
        if as_bytes
        else mailparser.parse_from_string(raw)
    )
    *structural, recovered = mail.mime_tree

    assert recovered["recovered"] is True
    assert recovered["content_type"] == "message/rfc822"
    assert recovered["defects"] == ["MimeHeaderDefect"]
    assert all(
        "MimeHeaderDefect" not in node["defects"] for node in structural
    )
    assert _mime_details(mail) == [
        "MimeHeaderDefect: part 2, sub-part 1: invalid-boundary-parameter: "
        "raw=('undefined', '', 'abc')",
        "MimeHeaderDefect: part 2, sub-part 2: content-type[0]: "
        f"invalid-parameter-continuation; raw={name!r}",
        "MimeHeaderDefect: part 2, sub-part 4: content-disposition[0]: "
        f"invalid-parameter-continuation; raw={disposition!r}",
    ]
    assert [a["filename"] for a in mail.attachments] == ["m.eml"]
    assert "hidden" in mail.attachments[0]["payload"]


@pytest.mark.parametrize(
    "filename, details",
    [
        pytest.param(
            b"filename=\xc3\xa9\xff",
            [
                "MimeHeaderDefect: part 2, sub-part 1: "
                "content-disposition[0]: "
                "invalid UTF-8; raw='inline; filename=\\\\xc3\\\\xa9\\\\xff'"
            ],
            id="plain",
        ),
        pytest.param(
            b"filename*=x; filename*1=\xc3\xa9\xff",
            [
                "MimeHeaderDefect: part 2, sub-part 1: "
                "content-disposition[0]: "
                "invalid UTF-8; "
                "raw='inline; filename*=x; filename*1=\\\\xc3\\\\xa9\\\\xff'",
                "MimeHeaderDefect: part 2, sub-part 1: "
                "content-disposition[0]: "
                "invalid-parameter-continuation; "
                "raw='inline; filename*=x; filename*1=é\ufffd'",
            ],
            id="sections",
        ),
    ],
)
def test_sub_part_header_the_email_package_cannot_print(filename, details):
    """A character next to an undecoded octet: ``str()`` of it raises.

    The sub-parts are read from their raw headers, as parts are.
    """
    raw = (
        _EPILOGUE.encode() + b"Content-Type: multipart/mixed; boundary=C\n\n"
        b"--C\nContent-Disposition: inline; "
        + filename
        + b"\n\n--C--\n--A--\n"
    )
    mail = mailparser.parse_from_string(raw.decode("utf-8", "surrogateescape"))

    assert mail.mime_tree[-1]["recovered"] is True
    assert mail.mime_tree[-1]["defects"] == ["MimeHeaderDefect"]
    assert _mime_details(mail) == details
    mail.mail_json.encode("utf-8")


@pytest.mark.parametrize("factory", ["bytes", "string", "file", "file_obj"])
def test_every_part_of_a_parsed_message_recovers_parameters(factory, tmp_path):
    """No entry point may build a part of the plain ``Message`` class."""
    raw = b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n" + _CHILDREN
    if factory == "file_obj":
        mail = mailparser.parse_from_file_obj(io.StringIO(raw.decode()))
    else:
        mail = _parse(raw, factory, tmp_path)
    assert mail.message is not None
    parts = list(mail.message.walk())

    assert len(parts) == 3
    assert all(isinstance(part, RecoveringMessage) for part in parts)
    assert all(isinstance(part, Message) for part in parts)


@pytest.mark.parametrize(
    "value, params",
    [
        (
            "t/p; name*=x; name*1=y",
            [("t/p", ""), ("name", (None, None, "xy"))],
        ),
        # An explicit section 0 wins over the section without a number.
        ("t/p; a*0=p; a*=q; a*1=r", [("t/p", ""), ("a", "pr")]),
        # Equal numbers keep the order of the header.
        (
            "t/p; n*=invoice; n*=.exe; n*1=.pdf",
            [("t/p", ""), ("n", (None, None, "invoice.exe.pdf"))],
        ),
        (
            "t/p; n*2=c; n*=b; n*2=a; n*=a",
            [("t/p", ""), ("n", (None, None, "baca"))],
        ),
        (
            't/p; a*1*=%41; a*=x; b*0="q"; b*1=r',
            [("t/p", ""), ("a", (None, None, "xA")), ("b", "qr")],
        ),
        (
            "t/p; charset=utf-8; name*=utf-8''%E2%82%AC; name*1=.txt",
            [
                ("t/p", ""),
                ("charset", "utf-8"),
                ("name", ("utf-8", "", "â\x82¬.txt")),
            ],
        ),
        # A number given twice, also with a leading zero.
        ("t/p; n*0=b.exe; n*0=a", [("t/p", ""), ("n", "b.exea")]),
        ("t/p; n*1=x; n*01=w; n*0=z", [("t/p", ""), ("n", "zxw")]),
        # More than one section without a number.
        ("t/p; n*=b; n*=a", [("t/p", ""), ("n", (None, None, "ba"))]),
        (
            "t/p; n*=utf-8''b; n*=utf-8''a",
            [("t/p", ""), ("n", ("utf-8", "", "butf-8''a"))],
        ),
    ],
)
def test_malformed_sections(value, params):
    """Read on every Python as 3.13.18, 3.14.10 and 3.15.2 read them."""
    message, plain = RecoveringMessage(), Message()
    message["Content-Type"] = plain["Content-Type"] = value

    assert message.get_params() == params
    assert message.get_param(params[-1][0]) == params[-1][1]
    assert utils._read_params(value)[1] is True
    if _FIXED_EMAIL_PACKAGE:
        assert plain.get_params() == params


@pytest.mark.parametrize(
    "value",
    [
        "text/plain",
        "text/plain; charset=utf-8",
        'multipart/mixed; boundary="a;b"; x',
        "t/p; name*0*=utf-8''caf%C3%A9; name*1=.bin; NAME*2=x",
        # Gaps and leading zeros are read as they are, on each Python.
        "t/p; a*1=x; a*3=y; b*=''q",
        "t/p; a*01=x; a*000=y",
        # A parameter given twice is no RFC 2231 section.
        "t/p; name=b; name=a; NAME=c",
        "t/p; a*x=1; a*1=2; a**=3",
        "t/p; =; ;; a==; *=x; *0=y",
    ],
)
def test_other_parameters_read_as_the_email_package_reads_them(value):
    """The override returns what ``Message`` returns whenever it returns."""
    plain, recovering = Message(), RecoveringMessage()
    plain["Content-Type"] = recovering["Content-Type"] = value

    assert recovering.get_params() == plain.get_params()
    assert recovering.get_params(unquote=False) == plain.get_params(
        unquote=False
    )
    assert recovering.get_boundary() == plain.get_boundary()
    assert recovering.get_filename() == plain.get_filename()
    assert recovering.get_content_charset() == plain.get_content_charset()
    assert recovering.get_param("x", header="x-absent") is None
    assert recovering.get_params(header="x-absent") is None
    assert utils._read_params(value)[1] is False


def test_private_names_of_the_email_package_exist():
    """A Python that renames one must fail here, not bring the crash back."""
    assert callable(email.message._parseparam)  # type: ignore[attr-defined]
    section = email.utils.rfc2231_continuation  # type: ignore[attr-defined]
    assert section.match("name*1*").group("name", "num") == ("name", "1")
    assert section.match("name*").group("name", "num") == ("name", None)
    assert section.match("name*x") is None
    assert callable(Message._get_params_preserve)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "accessor",
    [
        lambda part: part.get_param("name"),
        lambda part: part.get_params(),
        lambda part: part.get_boundary(),
        lambda part: part.get_filename(),
        lambda part: part.get_content_charset(),
    ],
    ids=["get_param", "get_params", "get_boundary", "get_filename", "charset"],
)
def test_every_parameter_accessor_reads_through_the_override(accessor):
    """Neither the plain accessor nor a renamed hook can pass unnoticed."""
    calls = []

    class Spy(RecoveringMessage):
        def _get_params_preserve(self, failobj, header):
            calls.append(header)
            return super()._get_params_preserve(failobj, header)

    spy = Spy()
    spy["Content-Type"] = "multipart/mixed; boundary=abc; name*=x; name*1=y"
    accessor(spy)

    assert calls == ["content-type"]


def test_readers_of_a_header_value_share_one_split(monkeypatch):
    """The split is quadratic in some Python releases.

    The feed parser and ``parse()`` read this value several times and
    split it once; the tree is built after the cache was emptied, and
    splits it once more.
    """
    split = email.message._parseparam  # type: ignore[attr-defined]
    values = []

    def counting(value):
        values.append(str(value))
        return split(value)

    monkeypatch.setattr(email.message, "_parseparam", counting)
    utils._read_params.cache_clear()
    content_type = "multipart/mixed; boundary=abc; name*=x; name*1=y"
    raw = f"Content-Type: {content_type}\r\n\r\n".encode() + _CHILDREN
    mail = mailparser.parse_from_bytes(raw)

    assert values.count(content_type) == 1
    assert len(values) == len(set(values))
    assert mail.mime_tree[0]["filename"] == "xy"
    assert values.count(content_type) == 2


def _cached_values():
    return utils._read_params.cache_info().currsize


def test_no_header_value_is_kept_after_a_parse():
    """The cache is module state: it must not outlive what filled it."""
    raw = b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n" + _CHILDREN
    mail = mailparser.parse_from_string(raw.decode())
    assert _cached_values() == 0

    assert mail.message is not None
    assert mail.message.get_boundary() == "abc"
    assert _cached_values() == 1
    assert len(mail.mime_tree) == 3
    assert _cached_values() == 0

    mailparser.MailParser(email.message_from_bytes(raw))
    assert _cached_values() == 0


def test_no_header_value_is_kept_after_flattening_the_message():
    """The generator reads the charset of a part with an 8-bit body."""
    mail = mailparser.parse_from_bytes(
        b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\ncaf\xe9\r\n"
    )

    assert "caf" in mail.message_as_string
    assert _cached_values() == 0


def test_no_header_value_is_kept_after_a_failed_parse():
    """The feed parser read thousands of boundaries before it gave up."""
    raw = "".join(
        f"Content-Type: multipart/mixed; boundary=B{i}\r\n\r\n--B{i}\r\n"
        for i in range(3000)
    )
    with pytest.raises(MailParserRecursionError):
        mailparser.parse_from_string(raw)

    assert _cached_values() == 0


def test_cached_parameters_cannot_be_changed_by_a_caller():
    """Every reader gets its own list of immutable pairs."""
    message = RecoveringMessage()
    message["Content-Type"] = "text/plain; charset=utf-8; name*=x; name*1=y"
    params = message.get_params(unquote=False)
    assert params is not None
    params.clear()

    assert message.get_params() == [
        ("text/plain", ""),
        ("charset", "utf-8"),
        ("name", (None, None, "xy")),
    ]
    assert isinstance(utils._read_params(message["Content-Type"])[0], tuple)


@_FACTORIES
def test_section_number_too_long_to_convert(factory, tmp_path):
    """``int()`` refuses the number: the other parameters are still read."""
    value = f"text/plain; charset=iso-8859-1; name*{_LONG_NUMBER}=x"
    raw = f"Content-Type: {value}\r\n\r\n".encode() + b"caf\xe9"
    mail = _parse(raw, factory, tmp_path)
    (root,) = mail.mime_tree

    assert root["charset"] == "iso-8859-1"
    if _CONVERTS_ANY_NUMBER:
        # The email package reads it as the only section of ``name``.
        assert [a["filename"] for a in mail.attachments] == ["x"]
        assert mail.has_defects is False
    else:
        assert mail.text_plain == ["café"]
        assert mail.attachments == []
        assert root["defects"] == ["MimeHeaderDefect"]
        assert _mime_details(mail) == [
            "MimeHeaderDefect: part 0, content-type[0]: "
            f"invalid-parameter-continuation; raw={value!r}"
        ]


@_FACTORIES
def test_section_number_too_long_next_to_a_boundary(factory, tmp_path):
    """The email package reads the boundary through the same list."""
    raw = (
        f"Content-Type: multipart/mixed; boundary=abc; x*{_LONG_NUMBER}*=y\r\n"
        f"\r\n"
    ).encode() + _CHILDREN
    mail = _parse(raw, factory, tmp_path)
    root, text, attachment = mail.mime_tree

    assert root["boundary"] == "abc"
    assert mail.text_plain == ["hi"]
    assert [a["filename"] for a in mail.attachments] == ["a.bin"]
    assert text["defects"] == attachment["defects"] == []
    assert mail.has_defects is not _CONVERTS_ANY_NUMBER


def test_parameter_with_a_number_too_long_keeps_its_literal_name():
    """It is no section, and its neighbours are sections as before."""
    name = f"b*{_LONG_NUMBER}"
    message = RecoveringMessage()
    message["Content-Type"] = f't/p; a=1; {name}="z"; c*0=p; c*1=q'

    assert message.get_param("a") == "1"
    assert message.get_param("c") == "pq"
    if not _CONVERTS_ANY_NUMBER:
        assert message.get_params() == [
            ("t/p", ""),
            ("a", "1"),
            ("c", "pq"),
            (name, "z"),
        ]


def test_many_unsortable_parameters_are_all_read():
    """One pass over the list, whatever its length."""
    count = 5000
    message = RecoveringMessage()
    message["Content-Type"] = "t/p" + "".join(
        f"; p{i}*=a; p{i}*1=b" for i in range(count)
    )
    params = message.get_params()

    assert params is not None
    assert len(params) == count + 1
    assert params[1] == ("p0", (None, None, "ab"))
    assert params[-1] == (f"p{count - 1}", (None, None, "ab"))


def test_helpers_read_a_plain_message_without_raising():
    """They do not depend on the class of the part they are given."""
    message = Message()
    message["Subject"] = "not a header with parameters"
    message["Content-Type"] = (
        f"multipart/mixed; boundary*=undefined''abc; name*=x; name*1=y;"
        f" x*{_LONG_NUMBER}=z"
    )
    defects = []

    assert mime_boundary(message, defects=defects) == "abc"
    assert defects == [
        "invalid-boundary-parameter: raw=('undefined', '', 'abc')"
    ]
    assert mime_filename(message) == "xy"
    assert mime_charset(message, "utf-8") == "utf-8"
    assert type(message) is Message


@pytest.mark.parametrize(
    "raw, filename, defects",
    [
        pytest.param(
            b"Content-Type: multipart/mixed; boundary=abc\r\n"
            b"Content-Disposition: attachment; filename*=x; filename*1=y\r\n"
            b"\r\n" + _CHILDREN,
            "xy",
            ["MimeHeaderDefect"],
            id="container",
        ),
        pytest.param(
            b"Content-Type: text/plain; name*=x; name*1=y\r\n\r\nhi\r\n",
            "xy",
            ["MimeHeaderDefect"],
            id="leaf",
        ),
        pytest.param(
            # The feed parser reads no parameter of this container.
            b"Content-Type: message/rfc822; name*=x; name*1=y\r\n\r\n"
            b"Subject: a\r\n\r\nhi\r\n",
            "xy",
            ["MimeHeaderDefect"],
            id="embedded message",
        ),
        pytest.param(
            b"Content-Type: message/rfc822; name*"
            + _LONG_NUMBER.encode()
            + b"=x; name=y\r\n\r\nSubject: a\r\n\r\nhi\r\n",
            "y",
            [] if _CONVERTS_ANY_NUMBER else ["MimeHeaderDefect"],
            id="embedded message, long number",
        ),
        pytest.param(
            b"Content-Transfer-Encoding: base64\r\nContent-Type: text/html;"
            b" name*1*=x-unknown'en'q; charset*0*=idna'en'%FF\r\n\r\n"
            b"\xff\xfe\r\n",
            "q",
            [],
            id="payload",
        ),
    ],
)
def test_message_built_by_the_caller_is_parsed_as_given(
    raw, filename, defects
):
    """A plain ``Message`` is read through the helpers, not replaced."""
    message = email.message_from_bytes(raw)
    mail = mailparser.MailParser(message)

    assert mail.message is message
    assert type(mail.message) is Message
    assert mail.mime_tree[0]["filename"] == filename
    assert mail.mime_tree[0]["defects"] == defects


def test_root_boundary_of_a_plain_message_is_read_for_the_epilogue():
    """The epilogue is searched with a boundary the root cannot decode."""
    message = Message()
    message["Content-Type"] = "multipart/mixed; boundary*=undefined''A"
    inner = Message()
    inner["Content-Type"] = "multipart/alternative; boundary=B"
    inner.set_payload("x\n")
    inner.defects.append(email.errors.StartBoundaryNotFoundDefect())
    message.set_payload([inner])
    message.epilogue = "--A\nContent-Type: text/plain\n\nhidden\n--A--\n"
    mail = mailparser.MailParser(message)

    assert mail.mime_tree[-1]["recovered"] is True
    assert "hidden" in mail.body
    assert _mime_details(mail) == [
        "MimeHeaderDefect: part 0, invalid-boundary-parameter: "
        "raw=('undefined', '', 'A')"
    ]
