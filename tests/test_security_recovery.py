"""Forensic recovery remains explicit and bounded on hostile MIME input."""

import base64
import json

import pytest

import mailparser
from mailparser import utils
from mailparser.serialization import (
    SerializationBudget,
    SerializationLimitError,
    bounded_flatten,
)
from mailparser.utils import as_string_safe


def _parse(raw, factory, tmp_path):
    if factory == "bytes":
        return mailparser.parse_from_bytes(raw)
    if factory == "file":
        path = tmp_path / "input.eml"
        path.write_bytes(raw)
        return mailparser.parse_from_file(path)
    return mailparser.parse_from_string(raw.decode("utf-8", "surrogateescape"))


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize(
    "value, expected",
    [
        ("日本語 =?utf-8?q?test?=", "日本語 test"),
        ("=?utf-8?q?test?= café", "test café"),
        ("café =?utf-8?q?test?= 日本語", "café test 日本語"),
        ("😀 =?utf-8?q?test?=", "😀 test"),
        ("pré\u00a0 =?utf-8?q?test?=", "pré\u00a0 test"),
        ("=?utf-8?q?test?= \u0085fin", "test \u0085fin"),
        (r"literal \u65e5 =?utf-8?q?test?=", r"literal \u65e5 test"),
        (
            "=?utf-8?q?one?= \u00a0 =?utf-8?q?two?=",
            "one \u00a0 two",
        ),
    ],
    ids=[
        "cjk",
        "suffix",
        "both",
        "emoji",
        "nbsp",
        "nel",
        "literal-escape",
        "unicode-between-words",
    ],
)
def test_mixed_unicode_header_preserves_literal_spans(
    factory, value, expected, tmp_path
):
    """Raw Unicode stays exact when adjacent encoded-words are decoded."""
    raw = f"Subject: {value}\r\nTo: good@example.com\r\n\r\nneighbor".encode()
    parsed = _parse(raw, factory, tmp_path)
    assert parsed.subject == expected
    assert parsed.headers["Subject"] == expected
    assert parsed.to == [("", "good@example.com")]
    assert parsed.body == "neighbor"
    assert not parsed.has_defects
    assert parsed.header_decoding_defects == []
    assert json.loads(parsed.mail_json)["subject"] == expected
    assert parsed.message is not None
    original = dict(parsed.message.raw_items())["Subject"]
    assert original.encode("utf-8", "surrogateescape") == value.encode()


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize(
    "value, expected",
    [
        ("=?UTF-8*en?q?hello?=", "hello"),
        ("=?iso-8859-1*fr?q?caf=E9?=", "café"),
        ("=?UTF-8*ja?b?5pel5pys6Kqe?=", "日本語"),
        ("=?UTF-8*en?q?hello?=\r\n \t=?UTF-8*fr?q?_ami?=", "hello ami"),
    ],
    ids=["utf8", "latin1", "base64", "folded-words"],
)
def test_encoded_word_language_is_separate_from_charset(
    factory, value, expected, tmp_path
):
    """RFC 2231 language metadata does not become part of the codec name."""
    parsed = _parse(f"Subject: {value}\r\n\r\n".encode(), factory, tmp_path)
    assert parsed.subject == expected
    assert not parsed.has_defects
    assert parsed.header_decoding_defects == []


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize("charset", ["utf-8", "no-such-codec", "utf\x00-8"])
def test_language_tag_keeps_strict_decoding(factory, charset, tmp_path):
    """Removing language metadata must retain strict byte/codec checks."""
    value = f"=?{charset}*en?b?YWJj/2RlZg==?="
    parsed = _parse(f"Subject: {value}\r\n\r\n".encode(), factory, tmp_path)
    assert parsed.subject == value
    assert parsed.has_defects
    assert parsed.header_decoding_defects[0]["raw"] == value
    assert parsed.header_decoding_defects[0]["occurrence"] == 0
    assert parsed.header_decoding_defects[0]["part"] == 0


@pytest.mark.parametrize("count", [128, 512, 2048])
def test_mixed_header_decoder_work_is_bounded(count, monkeypatch):
    """Decoder input stays linear and cached views do not repeat decoding."""
    real_decoder = utils.decode_header
    decoded_size = 0

    def counted_decoder(value):
        nonlocal decoded_size
        decoded_size += len(value)
        return real_decoder(value)

    monkeypatch.setattr(utils, "decode_header", counted_decoder)
    value = "日本語 =?UTF-8*en?q?test?= " * count
    raw = f"Subject: {value}\r\n\r\n".encode()
    parsed = mailparser.parse_from_bytes(raw)
    assert parsed.subject == ("日本語 test " * count).strip()
    assert not parsed.has_defects
    assert 0 < decoded_size <= len(raw)
    first_pass = decoded_size
    assert parsed.headers["Subject"] == parsed.subject
    assert json.loads(parsed.mail_json)["subject"] == parsed.subject
    assert decoded_size == first_pass


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize(
    "charset",
    ["utf-8", "ascii", "no-such-charset", "utf\x00-8"],
)
def test_damaged_word_keeps_literal_and_context(factory, charset, tmp_path):
    """Strict failures cannot join text across undecodable bytes."""
    word = f"=?{charset}?b?YWJj/2RlZg==?="
    damaged = f"prefix =?utf-8?q?valid?= {word} suffix"
    headers = f"Subject: valid\r\nSubject: {damaged}\r\n"
    raw = (headers + "To: good@example.com\r\n\r\nneighbor").encode()
    parsed = _parse(raw, factory, tmp_path)
    assert parsed.subject == ["valid", damaged]
    assert parsed.to == [("", "good@example.com")]
    assert parsed.body == "neighbor"
    assert parsed.has_defects
    assert "HeaderDecodeDefect" in parsed.defects_categories
    assert parsed.header_decoding_defects == [
        {
            "reason": "invalid-encoded-word",
            "raw": damaged,
            "header": "subject",
            "occurrence": 1,
            "part": 0,
            "recovered": True,
        }
    ]
    expected = parsed.header_decoding_defects
    for value in (parsed.mail, parsed.mail_partial):
        assert value["header_decoding_defects"] == expected
    assert parsed.message is not None
    assert list(parsed.message.raw_items())[1] == ("Subject", damaged)


@pytest.mark.parametrize("charset", ["utf-8", "ascii", "no-such-charset"])
def test_charset_failure_with_readable_bytes_is_still_diagnosed(charset):
    """An unknown charset cannot imply successful declared decoding."""
    word = f"=?{charset}?b?YWJjZGVm?="
    parsed = mailparser.parse_from_string(f"Subject: {word}\r\n\r\n")
    if charset == "no-such-charset":
        assert parsed.subject == word
        assert parsed.has_defects
    else:
        assert parsed.subject == "abcdef"
        assert not parsed.has_defects
        assert parsed.header_decoding_defects == []


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize(
    "metadata",
    [
        'Content-Type: text/plain; charset="utf\x00-8"',
        "Content-Type: text/plain; charset*=utf\x00-8''utf-8",
        "Content-Disposition: attachment; filename*=utf\x00-8''literal.bin",
        'Content-Disposition: attachment; filename="=?utf\x00-8?b?YWJj?="',
    ],
    ids=[
        "body-charset",
        "encoded-charset",
        "filename-charset",
        "filename-word",
    ],
)
def test_nul_charset_in_mime_recovers_payload(metadata, factory, tmp_path):
    """A rejected codec name cannot abort neighboring evidence recovery."""
    raw = (
        'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
        f"--x\r\n{metadata}\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\nREFUQQ==\r\n"
        "--x\r\nContent-Type: text/plain\r\n\r\nneighbor\r\n--x--\r\n"
    ).encode()
    parsed = _parse(raw, factory, tmp_path)
    assert parsed.has_defects
    assert "neighbor" in parsed.body
    if metadata.startswith("Content-Disposition"):
        assert base64.b64decode(parsed.attachments[0]["payload"]) == b"DATA"
    else:
        assert "DATA" in parsed.body
    assert parsed.message is not None
    assert next(parsed.message.walk()).is_multipart()
    assert parsed.mail_json


@pytest.mark.parametrize(
    "value, expected",
    [
        ("=?iso-8859-1?q?caf=E9?=\r\n \t=?utf-8?q?_ok?=", "café ok"),
        ("one\r\n \r\n two", "one\r\n \r\n two"),
    ],
    ids=["valid-encoded-fold", "obsolete-consecutive-folds"],
)
def test_valid_and_obsolete_header_folding_remains_readable(value, expected):
    """Strict recovery must not classify permitted obsolete folding invalid."""
    parsed = mailparser.parse_from_string(f"Subject: {value}\r\n\r\n")
    assert parsed.subject == expected
    assert not parsed.has_defects
    assert parsed.header_decoding_defects == []


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
def test_bad_filename_and_nested_header_keep_part_context(factory, tmp_path):
    """Malformed metadata never hides the attachment or its valid sibling."""
    word = "=?utf-8?b?YWJj/2RlZg==?="
    raw = (
        'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
        f'--x\r\nContent-Disposition: attachment; filename="{word}"\r\n'
        f"Subject: {word}\r\n\r\nDATA\r\n"
        '--x\r\nContent-Disposition: attachment; filename="good.bin"\r\n'
        "\r\nGOOD\r\n--x--\r\n"
    ).encode()
    parsed = _parse(raw, factory, tmp_path)
    assert [a["filename"] for a in parsed.attachments] == [word, "good.bin"]
    assert [base64.b64decode(a["payload"]) for a in parsed.attachments] == [
        b"DATA",
        b"GOOD",
    ]
    assert all(d["part"] == 1 for d in parsed.header_decoding_defects)
    assert parsed.has_defects
    assert "MimeHeaderDefect" in parsed.defects_categories
    parsed.write_attachments(tmp_path / "out")
    assert (tmp_path / "out" / "good.bin").read_bytes() == b"GOOD"
    safe_name = parsed.attachments[0]["safe_filename"]
    assert (tmp_path / "out" / safe_name).read_bytes() == b"DATA"


def _nested(depth, leaf="x"):
    raw = f'Content-Disposition: attachment; filename="leaf.bin"\r\n\r\n{leaf}'
    for i in range(depth):
        raw = (
            f'Content-Type: multipart/mixed; boundary="b{i:04d}"\r\n'
            f'Content-Disposition: attachment; filename="a{i}.eml"\r\n'
            f"\r\n--b{i:04d}\r\n{raw}\r\n--b{i:04d}--\r\n"
        )
    return raw


@pytest.mark.parametrize("factory", ["bytes", "file", "string"])
@pytest.mark.parametrize("depth", [40, 80, 160])
def test_container_budget_recovers_leaf_and_neighbors(
    factory, depth, tmp_path, monkeypatch
):
    """Real generator visits and buffer writes obey one cumulative budget."""
    original_spend = SerializationBudget.spend
    observed = {}

    def counted_spend(self, characters=0, nodes=0):
        initial = observed.setdefault(id(self), (self.characters, self.nodes))
        original_spend(self, characters=characters, nodes=nodes)
        assert 0 <= self.characters <= initial[0]
        assert 0 <= self.nodes <= initial[1]

    monkeypatch.setattr(SerializationBudget, "spend", counted_spend)
    raw = (
        'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        f"--outer\r\n{_nested(depth)}\r\n"
        "--outer\r\nContent-Type: text/plain\r\n\r\nneighbor\r\n"
        '--outer\r\nContent-Disposition: attachment; filename="good.bin"\r\n'
        "\r\nGOOD\r\n--outer--\r\n"
    ).encode()
    parsed = _parse(raw, factory, tmp_path)
    assert observed
    assert parsed.has_defects
    assert "ResourceLimitDefect" in parsed.defects_categories
    assert parsed.resource_limit_defects
    assert all(
        d["reason"] == "container-serialization-limit" and not d["recovered"]
        for d in parsed.resource_limit_defects
    )
    assert parsed.body == "neighbor"
    selected = {a["filename"]: a for a in parsed.attachments}
    assert base64.b64decode(selected["leaf.bin"]["payload"]) == b"x"
    assert base64.b64decode(selected["good.bin"]["payload"]) == b"GOOD"
    assert all(a["payload"] for a in parsed.attachments)
    assert parsed.message is not None
    original_parts = list(parsed.message.walk())
    assert len(original_parts) == depth + 4
    for defect in parsed.resource_limit_defects:
        assert original_parts[defect["part"]].is_multipart()
        assert defect["filename"] not in selected
    for output in (parsed.mail_json, parsed.mail_partial_json):
        assert json.loads(output)["resource_limit_defects"]
    before = list(parsed.resource_limit_defects)
    parsed.parse()
    assert parsed.resource_limit_defects == before


def test_shallow_container_and_child_are_both_complete():
    """An ordinary attachment retains the existing serialized format."""
    parsed = mailparser.parse_from_string(_nested(2))
    assert not parsed.has_defects
    assert parsed.resource_limit_defects == []
    assert [a["filename"] for a in parsed.attachments] == [
        "a1.eml",
        "a0.eml",
        "leaf.bin",
    ]
    assert parsed.message is not None
    for part, attachment in zip(parsed.message.walk(), parsed.attachments):
        if part.is_multipart():
            expected = "".join(as_string_safe(c) for c in part.get_payload())
            assert attachment["payload"] == expected


@pytest.mark.parametrize("binary", [False, True])
def test_internal_generator_buffers_fail_before_excess_write(binary):
    """The actual writer guard works even without the preflight estimate."""
    parsed = mailparser.parse_from_string(_nested(3, "x" * 100))
    assert parsed.message is not None
    budget = SerializationBudget(list(parsed.message.walk()))
    budget.characters = 10
    with pytest.raises(SerializationLimitError):
        bounded_flatten(parsed.message, budget, binary=binary)
    assert 0 <= budget.characters <= 10


def test_wire_names_cannot_shadow_new_diagnostics():
    """Sender-chosen diagnostic names remain literal header evidence."""
    headers = "Header_Decoding_Defects: attacker\r\n"
    headers += "Resource_Limit_Defects: attacker\r\n"
    parsed = mailparser.parse_from_string(headers + "\r\n")
    assert parsed.header_decoding_defects == []
    assert parsed.resource_limit_defects == []
    assert parsed.headers["Header_Decoding_Defects"] == "attacker"
    assert parsed.headers["Resource_Limit_Defects"] == "attacker"
    assert "header_decoding_defects" not in parsed.mail
    assert "resource_limit_defects" not in parsed.mail
