"""The MIME tree and the drawing of the message structure."""

import base64
import glob
import json
import os
import sys
from unittest.mock import patch

import pytest

import mailparser
from mailparser.__main__ import get_args, main
from mailparser.core import _walk_with_parents
from mailparser.structure import MAX_DRAWN_DEPTH, _delay, _size, _visible

_MAILS = sorted(
    path
    for path in glob.glob(
        os.path.join(os.path.dirname(__file__), "mails", "mail_*")
    )
    if "outlook" not in path
)

_HEADERS = (
    "Date: Thu, 01 Oct 2026 12:00:00 +0000\r\n"
    "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\n"
    "Subject: structure\r\nMessage-ID: <1@example.com>\r\n"
)

_CONFORMING = (
    _HEADERS + "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
    "preamble\r\n"
    '--outer\r\nContent-Type: multipart/alternative; boundary="inner"\r\n\r\n'
    "--inner\r\nContent-Type: text/plain; charset=UTF-8\r\n"
    "Content-Transfer-Encoding: 7bit\r\n\r\nplain\r\n"
    "--inner\r\nContent-Type: TEXT/HTML; charset=utf-8\r\n"
    "Content-Transfer-Encoding: Quoted-Printable \r\n\r\n<b>html</b>\r\n"
    "--inner--\r\n"
    "--outer\r\nContent-Type: text/csv\r\n"
    'Content-Disposition: ATTACHMENT; filename="report.csv"\r\n'
    "Content-Transfer-Encoding: base64\r\nContent-ID: <csv@example.com>\r\n"
    "\r\n" + base64.b64encode(b"a,b\r\n1,2\r\n").decode() + "\r\n--outer--\r\n"
)


def _nested_multipart(depth):
    """Return a message of ``depth`` multiparts around one text leaf."""
    head = "".join(
        f"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n"
        for i in range(depth)
    )
    tail = "".join(f"\r\n--b{i}--\r\n" for i in reversed(range(depth)))
    return _HEADERS + head + "Content-Type: text/plain\r\n\r\nleaf" + tail


def _pick(node, *keys):
    return tuple(node[key] for key in keys)


@pytest.mark.parametrize("path", _MAILS, ids=os.path.basename)
def test_tree_invariants_hold_on_corpus(path):
    """Indexes, parents and attachment links are consistent for real mail."""
    mail = mailparser.parse_from_file(path)
    tree = mail.mime_tree

    assert tree
    assert "mime_tree" not in mail.mail
    assert json.loads(mail.mime_tree_json) == tree
    for position, node in enumerate(tree):
        assert node["index"] == position
        if node["parent"] is None:
            assert position == 0 and node["depth"] == 0
        else:
            assert node["parent"] < position
            assert node["depth"] == tree[node["parent"]]["depth"] + 1
        assert set(node["roles"]) <= {"container", "body", "attachment"}
        assert set(node["defects"]) <= mail.defects_categories
        assert (node["size"] is None) == ("container" in node["roles"])
        if node["attachment"] is not None:
            assert "attachment" in node["roles"]
            assert 0 <= node["attachment"] < len(mail.attachments)
    linked = [n["attachment"] for n in tree if n["attachment"] is not None]
    assert linked == list(range(len(mail.attachments)))
    mailparser.render_structure(mail)
    # The iterative walk visits the parts exactly as Message.walk() does.
    message = mail.message
    assert message is not None
    walked = list(_walk_with_parents(message))
    assert [part for part, _ in walked] == list(message.walk())
    structural = [node for node in tree if not node["recovered"]]
    assert [parent for _, parent in walked] == [
        n["parent"] for n in structural
    ]


def test_conforming_multipart_is_described_as_declared():
    """RFC 2045 5.1/6.1: names are folded to lowercase, values kept."""
    mail = mailparser.parse_from_string(_CONFORMING)
    keys = ("index", "parent", "depth", "content_type", "roles")

    assert [_pick(node, *keys) for node in mail.mime_tree] == [
        (0, None, 0, "multipart/mixed", ["container"]),
        (1, 0, 1, "multipart/alternative", ["container"]),
        (2, 1, 2, "text/plain", ["body"]),
        (3, 1, 2, "text/html", ["body"]),
        (4, 0, 1, "text/csv", ["attachment"]),
    ]
    root, _, plain, html, csv = mail.mime_tree
    assert root["boundary"] == "outer"
    assert root["content_type_raw"] == 'multipart/mixed; boundary="outer"'
    assert plain["boundary"] is None
    assert _pick(plain, "content_transfer_encoding", "charset", "size") == (
        "7bit",
        "utf-8",
        5,
    )
    assert html["content_type_raw"] == "TEXT/HTML; charset=utf-8"
    assert html["content_transfer_encoding"] == "quoted-printable"
    assert csv["content_disposition"] == "attachment"
    assert csv["filename"] == "report.csv"
    assert csv["content_id"] == "<csv@example.com>"
    # Decoded octets, not the length of the base64 text.
    assert csv["size"] == len(b"a,b\r\n1,2\r\n")
    assert mail.attachments[csv["attachment"]]["filename"] == "report.csv"
    assert all(node["defects"] == [] for node in mail.mime_tree)
    assert not any(node["recovered"] for node in mail.mime_tree)
    assert mail.has_defects is False


def test_absent_headers_are_not_replaced_by_defaults():
    """RFC 2046 5.1: a part needs no header; only the type is defaulted."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        "--b\r\n\r\nno headers at all\r\n--b--\r\n"
    )
    part = mail.mime_tree[1]

    assert part["content_type"] == "text/plain"
    for key in (
        "content_type_raw",
        "content_transfer_encoding",
        "charset",
        "content_disposition",
        "filename",
        "content_id",
        "boundary",
        "attachment",
        "embedded_headers",
    ):
        assert part[key] is None, key
    assert part["roles"] == ["body"]
    assert "no Content-Type header" in mailparser.render_structure(mail)


def test_unusable_content_type_stays_visible_beside_the_default():
    """RFC 2045 5.2: the default is assumed; the declared value is kept."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: garbage\r\n\r\nhi\r\n"
    )
    (part,) = mail.mime_tree

    assert part["content_type"] == "text/plain"
    assert part["content_type_raw"] == "garbage"
    assert "declared Content-Type: garbage" in mailparser.render_structure(
        mail
    )


def test_digest_default_type_and_embedded_messages():
    """RFC 2046 5.1.5 and 5.2.1: digest parts default to message/rfc822."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: multipart/digest; boundary=d\r\n\r\n"
        "--d\r\n\r\nFrom: inner@example.net\r\nSubject: one\r\n\r\nfirst\r\n"
        "--d\r\nContent-Type: message/rfc822\r\n\r\n"
        "Subject: =?utf-8?q?two?=\r\nDate: Thu, 01 Oct 2026 10:00:00 +0000\r\n"
        "\r\nsecond\r\n--d--\r\n"
    )
    keys = ("index", "parent", "content_type", "content_type_raw")

    assert [_pick(node, *keys) for node in mail.mime_tree] == [
        (0, None, "multipart/digest", "multipart/digest; boundary=d"),
        (1, 0, "message/rfc822", None),
        (2, 1, "text/plain", None),
        (3, 0, "message/rfc822", "message/rfc822"),
        (4, 3, "text/plain", None),
    ]
    assert [node["embedded_headers"] for node in mail.mime_tree] == [
        None,
        None,
        {"from": "inner@example.net", "subject": "one", "date": None},
        None,
        {
            "from": None,
            # Literal header text: the embedded message is not decoded.
            "subject": "=?utf-8?q?two?=",
            "date": "Thu, 01 Oct 2026 10:00:00 +0000",
        },
    ]
    drawing = mailparser.render_structure(mail)
    assert "embedded message" in drawing
    assert "From: inner@example.net" in drawing


def test_named_inline_text_has_both_roles():
    """A part exposed as body text and as an attachment says so."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: text/plain\r\n"
        'Content-Disposition: inline; filename="note.txt"\r\n\r\nnote\r\n'
    )
    (part,) = mail.mime_tree

    assert part["roles"] == ["attachment", "body"]
    assert part["attachment"] == 0
    assert part["content_disposition"] == "inline"
    assert "[attachment+body]" in mailparser.render_structure(mail)


def test_attached_container_is_container_and_attachment():
    """RFC 2183 2.9: the disposition applies to the multipart as a whole."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: multipart/mixed; boundary=o\r\n\r\n"
        "--o\r\nContent-Type: multipart/mixed; boundary=i\r\n"
        'Content-Disposition: attachment; filename="bundle"\r\n\r\n'
        "--i\r\nContent-Type: text/html\r\n\r\n<p>inside</p>\r\n--i--\r\n"
        "--o--\r\n"
    )
    _, container, leaf = mail.mime_tree

    assert container["roles"] == ["container", "attachment"]
    assert mail.attachments[container["attachment"]]["filename"] == "bundle"
    assert container["size"] is None
    # The wire structure stays visible under the attached container.
    assert _pick(leaf, "parent", "content_type") == (1, "text/html")


def test_omitted_container_representation_keeps_the_part():
    """ADR 0001: no attachment entry, an explicit defect on the part."""
    raw = "x"
    for i in range(160):
        raw = (
            f'Content-Type: multipart/mixed; boundary="b{i:04d}"\r\n'
            f'Content-Disposition: attachment; filename="a{i}.eml"\r\n'
            f"\r\n--b{i:04d}\r\n{raw}\r\n--b{i:04d}--\r\n"
        )
    mail = mailparser.parse_from_string(
        'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        f"--outer\r\n{raw}\r\n--outer--\r\n"
    )
    omitted = [
        n for n in mail.mime_tree if "ResourceLimitDefect" in n["defects"]
    ]

    assert omitted
    assert {d["part"] for d in mail.resource_limit_defects} == {
        node["index"] for node in omitted
    }
    for node in omitted:
        assert node["roles"] == ["container", "attachment"]
        assert node["attachment"] is None


def test_epilogue_recovery_is_marked_and_kept_apart():
    """A recovered part is distinguishable from the wire structure."""
    path = os.path.join(os.path.dirname(__file__), "mails", "mail_malformed_1")
    mail = mailparser.parse_from_file(path)
    *structural, recovered = mail.mime_tree

    assert not any(node["recovered"] for node in structural)
    assert _pick(recovered, "parent", "depth", "recovered") == (0, 1, True)
    assert recovered["roles"] == ["attachment"]
    assert (
        mail.attachments[recovered["attachment"]]["filename"]
        == (recovered["filename"])
    )
    assert "recovered from epilogue" in mailparser.render_structure(mail)


def _parse(raw, as_bytes):
    """Parse ``raw`` through the string or the bytes entry point."""
    if as_bytes:
        return mailparser.parse_from_bytes(raw.encode("ascii"))
    return mailparser.parse_from_string(raw)


_BOTH_ENTRY_POINTS = pytest.mark.parametrize(
    "as_bytes", [False, True], ids=["string", "bytes"]
)
_NESTED_WITHOUT_START = (
    "From: a@b\nContent-Type: multipart/mixed; boundary=A\n\n"
    "--A\nContent-Type: multipart/alternative; boundary=B\n\nx\n"
)
_TREE_KEYS = ("content_type", "roles", "defects", "recovered")
_NESTED_NODE = (
    "multipart/alternative",
    ["body"],
    ["StartBoundaryNotFoundDefect"],
    False,
)


@_BOTH_ENTRY_POINTS
@pytest.mark.parametrize(
    "raw, epilogue, categories, tree",
    [
        pytest.param(
            _NESTED_WITHOUT_START,
            None,
            {"CloseBoundaryNotFoundDefect", "StartBoundaryNotFoundDefect"},
            [
                (
                    "multipart/mixed",
                    ["container"],
                    ["CloseBoundaryNotFoundDefect"],
                    False,
                ),
                _NESTED_NODE,
            ],
            id="root never closed, no epilogue",
        ),
        pytest.param(
            "From: a@b\nContent-Type: message/rfc822\n\n"
            "Content-Type: multipart/mixed; boundary=Z\n\nx\n",
            None,
            {"StartBoundaryNotFoundDefect"},
            [
                ("message/rfc822", ["container"], [], False),
                (
                    "multipart/mixed",
                    ["body"],
                    ["StartBoundaryNotFoundDefect"],
                    False,
                ),
            ],
            id="root not multipart, no boundary",
        ),
        pytest.param(
            _NESTED_WITHOUT_START + "--A--",
            "",
            {"StartBoundaryNotFoundDefect"},
            [("multipart/mixed", ["container"], [], False), _NESTED_NODE],
            id="root closed, empty epilogue",
        ),
    ],
)
def test_nested_defect_no_epilogue(raw, epilogue, categories, tree, as_bytes):
    """The root hides nothing: the nested defect parses as it is."""
    mail = _parse(raw, as_bytes)

    assert mail.message is not None
    assert mail.message.epilogue == epilogue
    assert mail.body == "x\n"
    assert mail.has_defects is True
    assert mail.defects_categories == categories
    assert [_pick(node, *_TREE_KEYS) for node in mail.mime_tree] == tree
    assert "recovered from epilogue" not in mailparser.render_structure(mail)


@_BOTH_ENTRY_POINTS
@pytest.mark.parametrize(
    "boundary, delimiter, root_defects",
    [
        pytest.param("A", "--A", [], id="boundary"),
        # RFC 2046 section 5.1.1 requires one character at least.
        pytest.param('""', "--", ["MimeHeaderDefect"], id="empty boundary"),
    ],
)
def test_nested_defect_with_epilogue(
    boundary, delimiter, root_defects, as_bytes
):
    """A part hidden after the root's close delimiter is recovered."""
    mail = _parse(
        f"From: a@b\nContent-Type: multipart/mixed; boundary={boundary}\n\n"
        f"{delimiter}\nContent-Type: multipart/alternative; boundary=B\n\n"
        f"x\n{delimiter}--\n"
        f"{delimiter}\nContent-Type: text/plain\n\nhidden\n{delimiter}--\n",
        as_bytes,
    )

    assert mail.body == "hidden\n--- mail_boundary ---\nx\n"
    assert mail.has_defects is True
    assert mail.defects_categories == {
        "StartBoundaryNotFoundDefect",
        *root_defects,
    }
    assert [_pick(node, "parent", *_TREE_KEYS) for node in mail.mime_tree] == [
        (None, "multipart/mixed", ["container"], root_defects, False),
        (0, *_NESTED_NODE),
        (0, "text/plain", ["body"], [], True),
    ]
    assert "recovered from epilogue" in mailparser.render_structure(mail)


def test_defects_are_attributed_to_their_part():
    """Two parts of one type stay distinguishable by index."""
    mail = mailparser.parse_from_string(
        _HEADERS + "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        "--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nfine\r\n"
        "--b\r\nContent-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\nbad \udcff byte\r\n--b--\r\n"
    )

    assert [node["defects"] for node in mail.mime_tree] == [
        [],
        [],
        ["CharsetDecodeDefect"],
    ]
    assert "CharsetDecodeDefect" in mailparser.render_structure(mail)


@pytest.mark.parametrize("name", ["Mime-Tree", "mime_tree", "Mime_Tree_json"])
def test_wire_header_cannot_replace_the_tree(name):
    """The computed name is never resolved from a sender-chosen header."""
    mail = mailparser.parse_from_string(
        _HEADERS + f"{name}: forged\r\n\r\nhi\r\n"
    )

    assert [node["content_type"] for node in mail.mime_tree] == ["text/plain"]
    assert json.loads(mail.mime_tree_json) == mail.mime_tree
    assert mail.headers[name] == "forged"


def test_tree_of_invalid_octets_is_serializable():
    """Non-UTF-8 MIME metadata does not reach the tree as surrogates."""
    mail = mailparser.parse_from_bytes(
        _HEADERS.encode()
        + b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: text/pl\xff; name=\xfe.txt\r\n"
        b"Content-ID: <\xfd>\r\n\r\nhi\r\n"
        b"--b\r\nContent-Type: message/rfc822\r\n\r\n"
        b"Subject: caf\xc3\xa9 \xff\r\n\r\ninner\r\n--b--\r\n"
    )

    mail.mime_tree_json.encode("utf-8")
    assert "MimeHeaderDefect" in mail.mime_tree[1]["defects"]
    assert mail.mime_tree[3]["embedded_headers"]["subject"] == "café \\xff"
    mailparser.render_structure(mail).encode("utf-8")


def test_unparsed_message_has_an_empty_tree():
    parser = mailparser.MailParser()
    parser.parse()

    assert parser.mime_tree == []
    assert parser.mime_tree_json == "[]"
    assert "(no parts)" in mailparser.render_structure(parser)


@pytest.mark.parametrize("depth", [MAX_DRAWN_DEPTH, 400])
def test_deep_nesting_is_listed_whole_and_drawn_bounded(depth):
    """Depth chosen by the sender costs neither stack nor columns."""
    mail = mailparser.parse_from_string(_nested_multipart(depth))
    tree = mail.mime_tree

    assert len(tree) == depth + 1
    assert tree[-1]["depth"] == depth
    drawing = mailparser.render_structure(mail)
    hidden = depth - MAX_DRAWN_DEPTH
    marker = f"{hidden} deeper parts not drawn (deepest level {depth})"
    assert (marker in drawing) == bool(hidden)
    assert max(len(line) for line in drawing.splitlines()) < 200
    assert f"{MAX_DRAWN_DEPTH} " in drawing


def test_drawing_shows_every_part_under_its_parent():
    mail = mailparser.parse_from_string(_CONFORMING)
    drawing = mailparser.render_structure(mail)
    tree_lines = drawing.split("MIME TREE\n")[1].splitlines()

    assert [line.split("  [")[0].rstrip() for line in tree_lines] == [
        "  0 multipart/mixed",
        "  ├─ 1 multipart/alternative",
        "  │  ├─ 2 text/plain          7bit  utf-8  5 B",
        "  │  └─ 3 text/html           quoted-printable  utf-8  11 B",
        "  └─ 4 text/csv               base64  10 B",
    ]
    assert tree_lines[-1].endswith(
        '[attachment]  disposition:attachment  "report.csv"'
    )
    assert "  From:         Alice <alice@example.com>" in drawing
    assert "  Message-ID:   <1@example.com>" in drawing
    assert "Defects:" not in drawing
    assert "(no Received headers)" in drawing


def test_hostile_text_cannot_reach_the_terminal():
    """ANSI, carriage return and bidi override are drawn as escapes."""
    mail = mailparser.parse_from_string(
        "From: x@example.com\r\n"
        "Subject: back\\slash \x1b[2J\r\n"
        "Content-Type: application/x\x7f-y; charset=\x1b[31m\r\n"
        "Content-Disposition: attachment;\r\n"
        " filename*=utf-8''a%1B%5B2K%0D%E2%80%AEfdp%C2%A0.exe%E2%80%8B\r\n\r\n"
        "x\r\n"
    )
    drawing = mailparser.render_structure(mail)

    assert mail.mime_tree[0]["filename"] == "a\x1b[2K\r\u202efdp\xa0.exe\u200b"
    for hostile in ("\x1b", "\r", "\x7f", "\u202e", "\u200b", "\xa0"):
        assert hostile not in drawing
    assert '"a\\x1b[2K\\x0d\\u202efdp\\xa0.exe\\u200b"' in drawing
    # A literal backslash is doubled, so an escape is never ambiguous.
    assert "back\\\\slash \\x1b[2J" in drawing
    assert set(drawing) >= {"\n"} and "\t" not in drawing


def test_ascii_only_drawing_is_ascii():
    mail = mailparser.parse_from_string(
        _HEADERS.replace("structure", "caffè ☕").replace("Alice", "Ålice")
        + "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        '--b\r\nContent-Type: text/plain; name="résumé.txt"\r\n\r\nx\r\n'
        "--b--\r\n"
    )
    drawing = mailparser.render_structure(mail, ascii_only=True)

    drawing.encode("ascii")
    assert "caff\\xe8 \\u2615" in drawing
    assert "`- 1 text/plain" in drawing
    assert "caffè ☕" in mailparser.render_structure(mail)


def test_long_values_are_cut_with_a_mark():
    mail = mailparser.parse_from_string(
        "Subject: " + "s" * 5000 + "\r\n"
        'Content-Type: text/plain; name="' + "n" * 5000 + '.exe"\r\n\r\nx\r\n'
    )
    drawing = mailparser.render_structure(mail)

    assert max(len(line) for line in drawing.splitlines()) < 200
    assert "s" * 100 + "…" in drawing
    assert "n" * 48 + "…" in drawing
    assert ".exe" not in drawing
    assert mail.mime_tree[0]["filename"].endswith(".exe")


def test_repeated_and_unselected_headers_stay_visible():
    """RFC 5322 3.6 allows one From and one Subject; show what is there."""
    mail = mailparser.parse_from_string(
        "From: first@example.com\r\nFrom: second@example.net\r\n"
        "Subject: one\r\nSubject: two\r\n"
        "To: not an address\r\n\r\nx\r\n"
    )
    drawing = mailparser.render_structure(mail)

    assert "From:         first@example.com  (+1 more occurrences)" in drawing
    assert "Subject:      one\n  Subject:      two" in drawing
    assert "To:           not an address  (no mailbox selected)" in drawing


def test_hops_are_marked_for_recorded_defects_only():
    """A long delay or an unparsed header is shown, not judged."""
    mail = mailparser.parse_from_string(
        "Received: from c.example by d.example (unclosed;"
        " Thu, 01 Oct 2026 16:00:00 +0000\r\n"
        "Received: (qmail 123 invoked from network);"
        " Thu, 01 Oct 2026 15:30:00 +0000\r\n"
        "Received: from b.example by c.example with ESMTP;"
        " Thu, 01 Oct 2026 15:00:00 +0000\r\n"
        "Received: from a.example (a.example [192.0.2.1])\r\n"
        "\tby b.example with ESMTPS; Thu, 01 Oct 2026 12:00:00 +0000\r\n"
        "From: a@example.com\r\n\r\nx\r\n"
    )
    lines = mailparser.render_structure(mail).split("DELIVERY PATH\n")[1]
    lines = lines.split("\n\nMIME TREE")[0].splitlines()

    assert [d["occurrence"] for d in mail.received_header_defects] == [0]
    assert lines == [
        "  1  2026-10-01T12:00:00+00:00  a.example (a.example [192.0.2.1])"
        " ──▶ b.example  ESMTPS",
        "  │  +3h",
        "  2  2026-10-01T15:00:00+00:00  b.example                        "
        " ──▶ c.example  ESMTP",
        "  │  +30m",
        "  3  2026-10-01T15:30:00+00:00  (no from or by clause)",
        "  │  +0s",
        "  4  -                          unparsed: from c.example by d.example"
        " (unclosed; Thu, 01 Oct 2026 16:00:00 +0000  ⚠",
    ]


def test_message_with_nothing_but_a_body_draws():
    mail = mailparser.parse_from_string("\r\njust a body\r\n")
    drawing = mailparser.render_structure(mail)

    assert "(no headers)" in drawing
    assert "(no Received headers)" in drawing
    assert "0 text/plain" in drawing


def test_base64_attachment_is_not_decoded_by_parsing():
    """Measuring a wire-text attachment waits for the tree to be read."""
    mail = mailparser.parse_from_string(_CONFORMING)

    with patch.object(
        type(mail.message), "get_payload", side_effect=AssertionError
    ) as decode:
        assert mail.attachments[0]["payload"]
        assert mail.mail["attachments"]
    decode.assert_not_called()
    assert mail.mime_tree[4]["size"] == 10
    assert mail.mime_tree[4]["size"] == 10


def _run_cli(capsys, tmp_path, *flags):
    path = tmp_path / "mail.eml"
    path.write_bytes(_CONFORMING.encode())
    with patch.object(sys, "argv", ["mail-parser", "-f", str(path), *flags]):
        main()
    return capsys.readouterr().out


def test_cli_prints_the_tree_after_the_mail_as_two_documents(capsys, tmp_path):
    """mail-parser-api reads both documents from one run."""
    alone = _run_cli(capsys, tmp_path, "--json")
    both = _run_cli(capsys, tmp_path, "--json", "--mime-tree")
    decoder = json.JSONDecoder()

    assert both.startswith(alone)
    mail, end = decoder.raw_decode(both)
    tree, end = decoder.raw_decode(both, end + 1)
    assert both[end:] == "\n"
    assert "mime_tree" not in mail
    assert [node["content_type"] for node in tree][0] == "multipart/mixed"
    assert len(tree) == 5


def test_cli_draws_the_structure(capsys, tmp_path):
    assert "└─ 4 text/csv" in _run_cli(capsys, tmp_path, "--structure")


def test_cli_falls_back_to_ascii(capsys, tmp_path):
    with patch("mailparser.__main__.sys.stdout") as stdout:
        stdout.encoding = "ascii"
        path = tmp_path / "mail.eml"
        path.write_bytes(_CONFORMING.encode())
        with patch.object(
            sys, "argv", ["mail-parser", "-f", str(path), "-st"]
        ):
            with patch("builtins.print") as printed:
                main()
    (drawing,), _ = printed.call_args

    drawing.encode("ascii")
    assert "`- 4 text/csv" in drawing


@pytest.mark.parametrize(
    "octets, expected",
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KB"),
        (10 * 1024, "10 KB"),
        (5 * 1024**2, "5.0 MB"),
        (3 * 1024**3, "3.0 GB"),
        (5000 * 1024**3, "5000 GB"),
    ],
)
def test_size_units(octets, expected):
    assert _size(octets) == expected


@pytest.mark.parametrize(
    "seconds, expected",
    [
        (0, "+0s"),
        (0.4, "+0s"),
        (59, "+59s"),
        (3600, "+1h"),
        (11520, "+3h 12m"),
        (-8, "-8s"),
        (66528000, "+770d"),
        (90061, "+1d 1h"),
    ],
)
def test_delay_shows_its_two_largest_units(seconds, expected):
    assert _delay(seconds) == expected


def test_visible_stops_at_the_limit_whatever_the_input_length():
    """Work is bounded by the limit, not by the sender's value."""
    BS = chr(92)
    tag = chr(0xE0001)

    assert _visible("a" + tag, ascii_only=False, ellipsis="~") == (
        "a" + BS + "U000e0001"
    )
    # An escape that does not fit is dropped whole, never cut in half.
    assert _visible("abc" + tag, 5, ascii_only=False, ellipsis="~") == "abc~"
    with patch("mailparser.structure._FOLD") as fold:
        fold.sub.return_value = "y" * 40
        assert _visible("x" * 100000, 10, ascii_only=True, ellipsis="...") == (
            "y" * 10 + "..."
        )
    ((_, examined), _) = fold.sub.call_args
    assert examined == "x" * 33
    # A fold is not content; a line break that folds nothing is shown.
    folded = "a" + chr(13) + chr(10) + chr(9) + "b" + chr(10) + "c"
    assert _visible(folded, ascii_only=False, ellipsis="~") == (
        "a b" + BS + "x0ac"
    )


def _strings(value):
    """Yield every string held anywhere in a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.mark.parametrize(
    "parameter",
    [
        "utf-7''%2B2AA-",
        "unicode_escape''%5Cud800",
        "raw_unicode_escape''%5Cud800",
    ],
)
@pytest.mark.parametrize("factory", ["string", "bytes"])
def test_boundary_decoded_to_a_surrogate_stays_serializable(
    parameter, factory
):
    """RFC 2231 decoding runs a sender-chosen codec: its result is escaped.

    Security review: a lone surrogate in ``boundary`` made
    ``mime_tree_json`` impossible to encode and the CLI exit with a
    traceback after printing the mail.
    """
    raw = f"Content-Type: multipart/mixed; boundary*={parameter}\r\n\r\nx\r\n"
    if factory == "string":
        mail = mailparser.parse_from_string(raw)
    else:
        mail = mailparser.parse_from_bytes(raw.encode())
    (root,) = mail.mime_tree

    for text in _strings(mail.mime_tree):
        text.encode("utf-8")
    json.loads(mail.mime_tree_json.encode("utf-8"))
    assert root["boundary"] == chr(92) + "ud800"
    assert "MimeHeaderDefect" in root["defects"]
    assert any(
        "invalid-boundary-parameter" in detail
        for defect in mail.defects
        for detail in defect.get("mime-headers", [])
    )
    mailparser.render_structure(mail).encode("utf-8")


def test_ordinary_boundaries_are_not_diagnosed():
    """A quoted, a non-ASCII and an RFC 2231 boundary are all text."""
    for declared, expected in (
        ('boundary="simple boundary"', "simple boundary"),
        ("boundary*=utf-8''caf%C3%A9", "caf" + chr(0xE9)),
    ):
        mail = mailparser.parse_from_string(
            f"Content-Type: multipart/mixed; {declared}\r\n\r\n"
            f"--{expected}\r\n\r\nhi\r\n--{expected}--\r\n"
        )
        assert mail.mime_tree[0]["boundary"] == expected
        assert mail.has_defects is False


@pytest.mark.parametrize(
    "code",
    [
        0x034F,
        0x115F,
        0x17B4,
        0x180B,
        0x2800,
        0x303F,
        0x3164,
        0xFE0F,
        0xFFA0,
        0x13441,
        0x13442,
        0x16FE4,
        0x1D159,
        0xE0100,
        0xE000,
    ],
)
def test_characters_that_draw_nothing_are_made_visible(code):
    """Security review: fillers and variation selectors forged look-alikes.

    ``mx.goo<U+034F>gle.com`` and ``invoice.pdf<U+3164 x6>.exe`` were
    drawn exactly like the names they imitate.
    """
    hidden = chr(code)
    mail = mailparser.parse_from_string(
        f"Received: from a.example by mx.goo{hidden}gle.com with ESMTP;"
        " Thu, 01 Oct 2026 12:00:00 +0000\r\n"
        f"From: CEO{hidden} <ceo@example.com>\r\n"
        f'Content-Type: text/plain; name="invoice.pdf{hidden}.exe"\r\n\r\n'
        f"x\r\n"
    )
    drawing = mailparser.render_structure(mail)
    escape = chr(92) + (f"u{code:04x}" if code <= 0xFFFF else f"U{code:08x}")

    assert hidden not in drawing
    assert f"mx.goo{escape}gle.com" in drawing
    assert f"CEO{escape} <ceo@example.com>" in drawing
    assert f'"invoice.pdf{escape}.exe"' in drawing


def test_marks_that_draw_something_stay_readable():
    """Escaping every combining mark would garble whole scripts."""
    # No precomposed form exists for either mark: both stay combining.
    subject = "x" + chr(0x0323) + " " + chr(0x0915) + chr(0x093F)
    mail = mailparser.parse_from_string(f"Subject: {subject}\r\n\r\nx\r\n")

    assert subject in mailparser.render_structure(mail)


def test_short_flags_keep_their_meaning():
    """Security review: ``-mt`` already means ``-m -t`` and must stay so."""
    args = get_args().parse_args(["-f", "mail.eml", "-mt"])

    assert (args.from_, args.to, args.mime_tree) == (True, True, False)
    assert get_args().parse_args(["-f", "mail.eml", "--mime-tree"]).mime_tree
    assert get_args().parse_args(["-f", "mail.eml", "-st"]).structure


def test_reading_the_tree_does_not_change_the_message():
    """Security review: measuring a base64 attachment added a defect."""
    mail = mailparser.parse_from_string(
        _HEADERS + 'Content-Type: application/octet-stream; name="a.bin"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\nQUJ\r\n"
    )
    message = mail.message
    assert message is not None
    before = (
        list(message.defects),
        mail.mail_json,
        set(mail.defects_categories),
    )

    assert mail.mime_tree[0]["size"] == 2
    assert mail.mime_tree is mail.mime_tree
    assert (
        list(message.defects),
        mail.mail_json,
        set(mail.defects_categories),
    ) == before
    mail.parse()
    assert set(mail.defects_categories) == before[2]


def test_unselected_address_header_keeps_its_octets():
    """The literal value is drawn, not the lossy decoded view."""
    mail = mailparser.parse_from_bytes(b"From: J\xc3\xb6rg \xff\r\n\r\nx\r\n")
    drawing = mailparser.render_structure(mail)

    assert mail.from_ == []
    assert (
        "From:         J"
        + chr(0xF6)
        + "rg "
        + chr(92) * 2
        + "xff  (no mailbox selected)"
    ) in drawing


def test_tree_is_built_on_first_use_only():
    """A caller that never reads the tree does not pay for its entries."""
    mail = mailparser.parse_from_string(_CONFORMING)

    with patch.object(
        mailparser.MailParser, "_build_mime_tree", wraps=mail._build_mime_tree
    ) as build:
        assert mail.mail_json and mail.attachments
        build.assert_not_called()
        assert len(mail.mime_tree) == 5
        assert len(mail.mime_tree) == 5
    build.assert_called_once()
    mail.parse()
    assert len(mail.mime_tree) == 5


def test_surrogate_supplied_as_text_is_escaped_in_embedded_headers():
    """A str caller can pass surrogates that are not escaped octets."""
    mail = mailparser.parse_from_string(
        "Content-Type: message/rfc822\r\n\r\n"
        "Subject: lone " + chr(0xD800) + "\r\n\r\ninner\r\n"
    )
    subject = mail.mime_tree[1]["embedded_headers"]["subject"]

    assert subject == "lone " + chr(92) + "ud800"
    mail.mime_tree_json.encode("utf-8")
    mailparser.render_structure(mail).encode("utf-8")
