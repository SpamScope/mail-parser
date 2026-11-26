#!/usr/bin/env python

"""
Copyright 2016 Fedele Mantuano (https://twitter.com/fedelemantuano)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
import datetime
import email
import email.errors
import email.policy
import glob
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from email.generator import Generator
from email.message import Message
from unittest.mock import patch

import pytest
from work_budget import WorkBudget

import mailparser
from mailparser.const import REGXIP6
from mailparser.exceptions import (
    MailParserOSError,
    MailParserOutlookError,
    MailParserPathError,
    MailParserRecursionError,
)
from mailparser.serialization import SerializationBudget
from mailparser.utils import (
    _deduplicate_filename,
    _safe_attachment_filename,
    _truncate_filename,
    as_string_safe,
    convert_mail_date,
    extract_msg_convert,
    fingerprints,
    get_addresses,
    get_from_clause,
    get_header,
    get_mail_keys,
    get_to_domains,
    group_spans,
    in_spans,
    parse_received,
    ported_open,
    ported_string,
    random_string,
    receiveds_parsing,
)

# base paths
base_path = os.path.realpath(os.path.dirname(__file__))
root = os.path.join(base_path, "..")

# raw mails to test
mail_test_1 = os.path.join(base_path, "mails", "mail_test_1")
mail_test_2 = os.path.join(base_path, "mails", "mail_test_2")
mail_test_3 = os.path.join(base_path, "mails", "mail_test_3")
mail_test_4 = os.path.join(base_path, "mails", "mail_test_4")
mail_test_5 = os.path.join(base_path, "mails", "mail_test_5")
mail_test_6 = os.path.join(base_path, "mails", "mail_test_6")
mail_test_7 = os.path.join(base_path, "mails", "mail_test_7")
mail_test_8 = os.path.join(base_path, "mails", "mail_test_8")
mail_test_9 = os.path.join(base_path, "mails", "mail_test_9")
mail_test_10 = os.path.join(base_path, "mails", "mail_test_10")
mail_test_11 = os.path.join(base_path, "mails", "mail_test_11")
mail_test_12 = os.path.join(base_path, "mails", "mail_test_12")
mail_test_13 = os.path.join(base_path, "mails", "mail_test_13")
mail_test_14 = os.path.join(base_path, "mails", "mail_test_14")
mail_test_15 = os.path.join(base_path, "mails", "mail_test_15")
mail_test_16 = os.path.join(base_path, "mails", "mail_test_16")
mail_test_17 = os.path.join(base_path, "mails", "mail_test_17")
mail_test_18 = os.path.join(base_path, "mails", "mail_test_18")
mail_test_19 = os.path.join(base_path, "mails", "mail_test_19")
mail_malformed_1 = os.path.join(base_path, "mails", "mail_malformed_1")
mail_malformed_2 = os.path.join(base_path, "mails", "mail_malformed_2")
mail_malformed_3 = os.path.join(base_path, "mails", "mail_malformed_3")
mail_outlook_1 = os.path.join(base_path, "mails", "mail_outlook_1")


class TestMailParser(unittest.TestCase):
    def setUp(self):
        self.all_mails = (
            mail_test_1,
            mail_test_2,
            mail_test_3,
            mail_test_4,
            mail_test_5,
            mail_test_6,
            mail_test_7,
            mail_test_8,
            mail_test_9,
            mail_test_10,
            mail_test_11,
            mail_test_12,
            mail_test_13,
            mail_malformed_1,
            mail_malformed_2,
            mail_malformed_3,
        )

    def test_write_attachments(self):
        attachments = [
            "<_1_0B4E44A80B15F6FC005C1243C12580DD>",
            "<_1_0B4E420C0B4E3DD0005C1243C12580DD>",
            "<_1_0B4E24640B4E1564005C1243C12580DD>",
            "Move To Eight ZWEP6227F.pdf",
        ]
        random_path = os.path.join(root, "tests", random_string())
        mail = mailparser.parse_from_file(mail_test_10)
        os.makedirs(random_path)
        mail.write_attachments(random_path)
        for i in attachments:
            self.assertTrue(os.path.exists(os.path.join(random_path, i)))
        shutil.rmtree(random_path)

    def test_write_attachments_sanitizes_and_deduplicates_filenames(self):
        raw_mail = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=boundary

--boundary
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=../marker.txt

Zmlyc3Q=
--boundary
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename*=utf-8''..%2Fmarker.txt

c2Vjb25k
--boundary
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: ../content-id.txt

dGhpcmQ=
--boundary--
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail = mailparser.parse_from_string(raw_mail)

            self.assertEqual(
                [attachment["filename"] for attachment in mail.attachments],
                ["../marker.txt", "../marker.txt", "../content-id.txt"],
            )
            self.assertEqual(
                [
                    attachment["safe_filename"]
                    for attachment in mail.attachments
                ],
                ["marker.txt", "marker.txt", "content-id.txt"],
            )

            mail.write_attachments(output_dir)

            self.assertEqual(
                sorted(os.listdir(output_dir)),
                ["content-id.txt", "marker.txt", "marker_1.txt"],
            )
            with open(
                os.path.join(output_dir, "marker.txt"), "rb"
            ) as attachment:
                self.assertEqual(attachment.read(), b"first")
            with open(
                os.path.join(output_dir, "marker_1.txt"), "rb"
            ) as attachment:
                self.assertEqual(attachment.read(), b"second")
            with open(
                os.path.join(output_dir, "content-id.txt"), "rb"
            ) as attachment:
                self.assertEqual(attachment.read(), b"third")

            self.assertFalse(
                os.path.exists(os.path.join(temp_dir, "marker.txt"))
            )
            self.assertFalse(
                os.path.exists(os.path.join(temp_dir, "content-id.txt"))
            )

    def test_write_attachments_skips_invalid_filename(self):
        # A NUL byte smuggled in through RFC 2231 percent-encoding used to
        # raise ValueError out of write_attachments(), so every attachment
        # after the hostile one was silently never written.
        raw_mail = (
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; "
            "filename*=us-ascii''evil%00.bin\r\n\r\nxx\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=good.bin\r\n\r\nyy\r\n"
            "--b--\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)
        self.assertEqual(mail.attachments[0]["filename"], "evil\x00.bin")
        self.assertIsNone(mail.attachments[0]["safe_filename"])

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail.write_attachments(output_dir)
            self.assertEqual(os.listdir(output_dir), ["good.bin"])

    def test_write_attachments_truncates_long_filename(self):
        # A basename longer than NAME_MAX used to raise OSError out of
        # write_sample() and abort the rest of the batch.
        long_name = "a" * 300 + ".bin"
        raw_mail = (
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Disposition: attachment; filename={long_name}\r\n\r\n"
            f"xx\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=good.bin\r\n\r\nyy\r\n"
            "--b--\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail.write_attachments(output_dir)
            written = sorted(os.listdir(output_dir))

        self.assertEqual(len(written), 2)
        self.assertIn("good.bin", written)
        truncated = next(i for i in written if i != "good.bin")
        self.assertTrue(truncated.endswith(".bin"))
        self.assertLessEqual(len(truncated.encode("utf-8")), 240)

    def test_write_attachments_repairs_malformed_payload(self):
        # base64.b64decode() raises binascii.Error, a ValueError subclass,
        # so a payload with a length no padding can fix used to abort the
        # batch and leave a zero-byte stub behind. Every MUA repairs it, so
        # neither attachment may be lost.
        raw_mail = (
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "Content-Disposition: attachment; filename=evil.bin\r\n\r\n"
            "AAAAA\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=good.bin\r\n\r\nyy\r\n"
            "--b--\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail.write_attachments(output_dir)
            self.assertEqual(
                sorted(os.listdir(output_dir)), ["evil.bin", "good.bin"]
            )
            with open(
                os.path.join(output_dir, "evil.bin"), "rb"
            ) as attachment:
                # The orphan character carries no complete byte and is
                # dropped, exactly as a mail client would.
                self.assertEqual(attachment.read(), b"\x00\x00\x00")

    def test_base64_attachment_with_orphan_character(self):
        # Adding one character makes the length 1 more than a multiple of
        # four, which no padding can repair. Rejecting it deleted the
        # attachment from the extraction directory while the recipient's
        # client still saved it intact.
        original = b"MZ\x90\x00PAYLOAD-EXE"
        poisoned = base64.b64encode(original).decode("ascii") + "A"
        raw_mail = (
            "From: a@b.c\r\nContent-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            f'Content-Disposition: attachment; filename="x.bin"\r\n\r\n'
            f"{poisoned}"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            self.assertEqual(os.listdir(temp_dir), ["x.bin"])
            with open(os.path.join(temp_dir, "x.bin"), "rb") as attachment:
                self.assertEqual(attachment.read(), original)

    def test_base64_data_after_padding_is_ignored(self):
        # RFC 2045 ends the stream at the padding and every client stops
        # there. Splicing what follows onto the payload let a sender append
        # bytes only this tool sees, changing the hash it reports.
        original = b"MZ\x90\x00EICAR-MARKER"
        poisoned = base64.b64encode(original).decode("ascii") + "QUJD"
        raw_mail = (
            "From: a@b.c\r\nContent-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            f'Content-Disposition: attachment; filename="x.bin"\r\n\r\n'
            f"{poisoned}"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            with open(os.path.join(temp_dir, "x.bin"), "rb") as attachment:
                self.assertEqual(attachment.read(), original)

    def test_multipart_subpart_with_unencodable_charset(self):
        # BytesGenerator bypasses the charset only for text parts, so a
        # part typed multipart but carrying no boundary made the as_bytes()
        # fallback raise exactly like as_string() had.
        for charset in (b"undefined", b"idna"):
            raw_mail = (
                b'Content-Type: multipart/mixed; boundary="B1"\r\n\r\n--B1\r\n'
                b'Content-Type: multipart/mixed; boundary="B2"\r\n'
                b'Content-Disposition: attachment; filename="p.zip"\r\n\r\n'
                b"--B2\r\n"
                b"Content-Type: multipart/report; charset=" + charset + b"\r\n"
                b"Content-Transfer-Encoding: 8bit\r\n\r\n\xff\xfe\x80 body\r\n"
                b"--B1--\r\n"
            )

            mail = mailparser.parse_from_bytes(raw_mail)

            self.assertEqual(len(mail.attachments), 1)
            self.assertIsInstance(mail.mail_json, str)

    def test_nested_multipart_with_unencodable_charset(self):
        # The refusing part can be nested any depth down, so the fallback
        # must walk a conforming multipart's sub-parts instead of trying to
        # decode the list of them.
        raw_mail = (
            b'Content-Type: multipart/mixed; boundary="B1"\r\n\r\n--B1\r\n'
            b'Content-Type: multipart/mixed; boundary="B2"\r\n'
            b'Content-Disposition: attachment; filename="p.zip"\r\n\r\n'
            b"--B2\r\n"
            b'Content-Type: multipart/mixed; boundary="B3"\r\n\r\n--B3\r\n'
            b'Content-Type: multipart/report; charset="undefined"\r\n'
            b"Content-Transfer-Encoding: 8bit\r\n\r\n\xff\xfe\x80 body\r\n"
            b"--B3--\r\n--B2--\r\n--B1--\r\n"
        )

        mail = mailparser.parse_from_bytes(raw_mail)

        self.assertEqual(len(mail.attachments), 1)
        self.assertIsInstance(mail.mail_json, str)

    def test_message_as_string_with_unencodable_charset(self):
        raw_mail = (
            b'Content-Type: multipart/report; charset="undefined"\r\n'
            b"Content-Transfer-Encoding: 8bit\r\n\r\n\xff\xfe\x80 body\r\n"
        )

        mail = mailparser.parse_from_bytes(raw_mail)

        self.assertIsInstance(mail.message_as_string, str)

    def test_multipart_attachment_with_unencodable_charset(self):
        # as_string() re-encodes an 8-bit body with the charset the sender
        # declared, and utf-16 (like idna, or a non-text codec) cannot
        # represent the surrogates that carry those bytes.
        for charset in (
            b"utf-16",
            b"utf-32",
            b"idna",
            b"undefined",
            b"base64",
        ):
            raw_mail = (
                b"From: a@b.c\r\nContent-Type: multipart/mixed; "
                b"boundary=BB\r\n\r\n"
                b"--BB\r\nContent-Type: message/rfc822\r\n"
                b'Content-Disposition: attachment; filename="fwd.eml"\r\n\r\n'
                b"Content-Type: text/plain; charset=" + charset + b"\r\n"
                b"\r\n\xff\xfeA\x00\r\n--BB--\r\n"
            )

            mail = mailparser.parse_from_bytes(raw_mail)

            self.assertEqual(len(mail.attachments), 1)
            self.assertIsInstance(mail.mail_json, str)

    def test_write_attachments_keeps_truncated_names_distinct(self):
        # Truncation makes distinct long names collide.  Appending "_1" past
        # the length limit did not help: write_sample() sanitizes again and
        # the clamp cut the suffix back off, so every colliding attachment
        # landed on one file and only the last payload survived.
        prefix = "a" * 236
        names = (
            prefix + "A" * 60 + ".bin",
            prefix + "B" * 60 + ".bin",
            prefix + "A" * 60 + ".bin",
        )
        payloads = ("one", "two", "three")
        parts = "".join(
            "--b\r\nContent-Type: application/octet-stream\r\n"
            f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
            f"{payload}\r\n"
            for name, payload in zip(names, payloads)
        )
        raw_mail = (
            f"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            f"{parts}--b--\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail.write_attachments(output_dir)
            written = os.listdir(output_dir)

            self.assertEqual(len(written), 3)
            for name in written:
                self.assertLessEqual(len(name.encode("utf-8")), 240)

            contents = []
            for name in written:
                with open(os.path.join(output_dir, name)) as attachment:
                    contents.append(attachment.read())
            self.assertEqual(sorted(contents), ["one", "three", "two"])

    def test_write_attachments_long_extension_collision(self):
        # An extension longer than half the budget left no room for the
        # dedup marker, so the reserved budget went negative and sliced the
        # root from the wrong end. The name then no longer survived the
        # clamp inside write_sample(), and a third attachment named like
        # the re-clamped result could overwrite it.
        names = ("a." + "b" * 238, "a." + "b" * 238, "_1." + "b" * 237)
        payloads = ("first", "second", "third")
        parts = "".join(
            "--b\r\nContent-Type: application/octet-stream\r\n"
            f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
            f"{payload}\r\n"
            for name, payload in zip(names, payloads)
        )
        raw_mail = (
            f"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            f"{parts}--b--\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            mail.write_attachments(output_dir)
            written = os.listdir(output_dir)

            self.assertEqual(len(written), 3)
            contents = []
            for name in written:
                self.assertLessEqual(len(name.encode("utf-8")), 240)
                with open(os.path.join(output_dir, name)) as attachment:
                    contents.append(attachment.read())
            self.assertEqual(sorted(contents), ["first", "second", "third"])

    def test_deduplicated_names_survive_resanitization(self):
        # write_sample() sanitizes again, so every name dedup hands out must
        # already be a fixed point of _truncate_filename().
        used_filenames = {}
        base = _safe_attachment_filename("a." + "b" * 238)

        for _ in range(150):
            candidate = _deduplicate_filename(base, used_filenames)
            self.assertEqual(_truncate_filename(candidate), candidate)

    def test_write_attachments_reports_path_escape(self):
        # The per-attachment guard must not swallow a containment failure.
        raw_mail = (
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=attachment.txt\r\n\r\n"
            "xx\r\n"
        )
        mail = mailparser.parse_from_string(raw_mail)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = os.path.join(temp_dir, "attachments")
            os.makedirs(output_dir)
            target = os.path.join(temp_dir, "outside.txt")
            try:
                os.symlink(target, os.path.join(output_dir, "attachment.txt"))
            except (NotImplementedError, OSError):  # pragma: no cover
                self.skipTest("symlinks are not supported")

            with self.assertRaises(MailParserPathError):
                mail.write_attachments(output_dir)
            self.assertFalse(os.path.exists(target))

    def test_truncate_filename(self):
        self.assertEqual(_truncate_filename("short.bin"), "short.bin")

        # Extension is preserved, including compound tar extensions.
        truncated = _truncate_filename("a" * 300 + ".tar.gz")
        self.assertTrue(truncated.endswith(".tar.gz"))
        self.assertEqual(len(truncated.encode("utf-8")), 240)

        # The limit is measured in bytes, not characters, and a multi-byte
        # character cut in half by the budget is dropped, not mangled.
        truncated = _truncate_filename("è" * 300 + ".bin")
        self.assertTrue(truncated.endswith(".bin"))
        self.assertLessEqual(len(truncated.encode("utf-8")), 240)
        self.assertEqual(truncated, truncated.encode("utf-8").decode("utf-8"))

        # An extension big enough to eat the whole budget is not honoured
        # as an extension, and the result still fits.
        truncated = _truncate_filename("a." + "b" * 300)
        self.assertEqual(len(truncated.encode("utf-8")), 240)

    def test_attachment_with_unusable_filename_remains_parseable(self):
        raw_mail = """MIME-Version: 1.0
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=/
Content-Transfer-Encoding: base64

Y29udGVudA==
"""

        mail = mailparser.parse_from_string(raw_mail)

        self.assertEqual(mail.attachments[0]["filename"], "/")
        self.assertIsNone(mail.attachments[0]["safe_filename"])

    def test_issue62(self):
        mail = mailparser.parse_from_file(mail_test_14)
        received_spf = mail.Received_SPF
        self.assertIsInstance(received_spf, list)
        self.assertIn("custom_header1", received_spf)
        self.assertIn("custom_header2", received_spf)

    def test_html_field(self):
        mail = mailparser.parse_from_file(mail_malformed_1)
        self.assertIsInstance(mail.text_html, list)
        self.assertIsInstance(mail.text_html_json, str)
        self.assertEqual(len(mail.text_html), 1)

    def test_text_not_managed(self):
        mail = mailparser.parse_from_file(mail_test_14)
        self.assertIsInstance(mail.text_not_managed, list)
        self.assertIsInstance(mail.text_not_managed_json, str)
        self.assertEqual(len(mail.text_not_managed), 1)
        self.assertEqual("PNG here", mail.text_not_managed[0])

    def test_get_mail_keys(self):
        mail = mailparser.parse_from_file(mail_test_11)
        all_parts = get_mail_keys(mail.message)
        mains_parts = get_mail_keys(mail.message, False)
        self.assertNotEqual(all_parts, mains_parts)
        self.assertIn("message-id", mains_parts)
        self.assertIn("x-filterd-recvd-size", all_parts)
        self.assertNotIn("x-filterd-recvd-size", mains_parts)

    def test_mail_partial(self):
        mail = mailparser.parse_from_file(mail_test_10)
        self.assertNotEqual(mail.mail, mail.mail_partial)
        self.assertIn("message-id", mail.mail_partial)
        self.assertIn("x-ibm-av-version", mail.mail)
        self.assertNotIn("x-ibm-av-version", mail.mail_partial)
        result = mail.mail_partial_json
        self.assertIsInstance(result, str)
        nr_attachments = len(mail._attachments)
        self.assertEqual(nr_attachments, 4)

    def test_not_parsed_received(self):
        mail = mailparser.parse_from_file(mail_test_9)
        for i in mail.received:
            self.assertNotIn("raw", i)
            self.assertIn("hop", i)

    def test_issue_received(self):
        mail = mailparser.parse_from_file(mail_test_8)
        for i in mail.received:
            self.assertIn("date_utc", i)
            self.assertIsNotNone(i["date_utc"])

    def test_received_date_out_of_range(self):
        # A year whose epoch seconds overflow int64 makes calendar.timegm()
        # raise OverflowError, which used to escape receiveds_format() and
        # abort the parse of the whole message.
        raw_mail = (
            "Received: from x ([1.2.3.4]) by mx.victim.com; "
            "Tue, 7 Mar 292277026596 14:29:24 +0000\r\n\r\nbody\r\n"
        )

        mail = mailparser.parse_from_string(raw_mail)

        self.assertIsNone(mail.received[0]["date_utc"])
        self.assertIsInstance(mail.mail_json, str)

    def test_received_date_magnitude_sweep(self):
        # Every year magnitude must fail closed, whatever the stdlib raises.
        for exponent in range(4, 20):
            raw_mail = (
                "Received: from x ([1.2.3.4]) by mx; "
                f"Tue, 7 Mar {10**exponent} 14:29:24 +0000\r\n\r\nbody\r\n"
            )

            mail = mailparser.parse_from_string(raw_mail)
            self.assertIsNone(mail.received[0]["date_utc"])

    def test_received_date_offset_magnitude_sweep(self):
        # A huge timezone offset pushes the timestamp into the band where
        # datetime.fromtimestamp() reports EOVERFLOW as OSError, which is
        # neither ValueError nor OverflowError.
        for digits in range(4, 26):
            for sign in "+-":
                raw_mail = (
                    "Received: from a by b; 7 Mar 1970 14:29:24 "
                    f"{sign}{'9' * digits}\r\n\r\nbody\r\n"
                )

                mail = mailparser.parse_from_string(raw_mail)
                self.assertIsInstance(mail.mail_json, str)

    def test_get_header(self):
        mail = mailparser.parse_from_file(mail_test_1)
        h1 = get_header(mail.message, "from")
        self.assertIsInstance(h1, str)

    def test_receiveds_parsing(self):
        for i in self.all_mails:
            mail = mailparser.parse_from_file(i)
            receiveds = mail.received_raw
            result = receiveds_parsing(receiveds)
            self.assertIsInstance(result, list)
            for j in result:
                self.assertIsInstance(j, dict)
                self.assertIn("hop", j)
                self.assertIn("delay", j)

    def test_ipaddress(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        ip = "217.76.210.112"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(result, ip)

        trust = ""
        result = mail.get_server_ipaddress(trust)
        self.assertIsNone(result)

        trust = "   "
        result = mail.get_server_ipaddress(trust)
        self.assertIsNone(result)

    def test_ipaddress_unicodeerror(self):
        mail = mailparser.parse_from_file(mail_test_12)
        trust = "localhost"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(result, "96.202.181.20")

    def test_fingerprints_body(self):
        mail = mailparser.parse_from_file(mail_test_1)
        md5, sha1, sha256, sha512 = fingerprints(mail.body.encode("utf-8"))
        self.assertEqual(md5, "55852a2efe95e7249887c92cc02123f8")
        self.assertEqual(sha1, "62fef1e38327ed09363624c3aff8ea11723ee05f")
        self.assertEqual(
            sha256,
            (
                "cd4af1017f2e623f6d38f691048b6a28d8b1f44a0478137b4337eac6de78f71a"
            ),
        )
        self.assertEqual(
            sha512,
            (
                "4a573c7929b078f2a2c1c0f869d418b0c020d4"
                "d37196bd6dcc209f9ccb29ca67355aa5e47b97"
                "c8bf90377204f59efde7ba1fc071b6f250a665"
                "72f63b997e92e8"
            ),
        )

    def test_fingerprints_unicodeencodeerror(self):
        mail = mailparser.parse_from_file(mail_test_7)
        for i in mail.attachments:
            fingerprints(i["payload"])

    def test_malformed_mail(self):
        mail = mailparser.parse_from_file(mail_malformed_3)
        defects_categories = mail.defects_categories
        self.assertIn("StartBoundaryNotFoundDefect", defects_categories)
        self.assertIn("MultipartInvariantViolationDefect", defects_categories)
        self.assertIn("reply-to", mail.mail)
        self.assertNotIn("reply_to", mail.mail)
        reply_to = [("VICTORIA Souvenirs", "smgesi4@gmail.com")]
        self.assertEqual(mail.reply_to, reply_to)
        self.assertEqual(mail.fake_header, str())

        # This email has header X-MSMail-Priority
        msmail_priority = mail.X_MSMail_Priority
        self.assertEqual(msmail_priority, "High")

    def test_type_error(self):
        mail = mailparser.parse_from_file(mail_test_5)
        self.assertEqual(len(mail.attachments), 5)
        for i in mail.attachments:
            self.assertIsInstance(i["filename"], str)

    def test_filename_decode(self):
        mail = mailparser.parse_from_file(mail_test_11)
        for i in mail.attachments:
            self.assertIsInstance(i["filename"], str)

    def test_valid_mail(self):
        m = mailparser.parse_from_string("fake mail")
        self.assertFalse(m.message)

    def test_receiveds(self):
        mail = mailparser.parse_from_file(mail_test_1)
        self.assertEqual(len(mail.received), 6)

        self.assertIsInstance(mail.received, list)
        for i in mail.received:
            self.assertIsInstance(i, dict)

        self.assertIsInstance(mail.received_raw, list)
        for i in mail.received_raw:
            self.assertIsInstance(i, str)

        self.assertIsInstance(mail.received_json, str)

    def test_parsing_know_values(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertTrue(mail.has_defects)
        self.assertIn("CharsetDecodeDefect", mail.defects_categories)

        raw = "217.76.210.112"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(raw, result)

        raw = "<4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>"
        result = mail.message_id
        self.assertEqual(raw, result)

        raw = "echo@tu-berlin.de"
        result = mail.to
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], tuple)
        self.assertIsInstance(mail.to_json, str)
        self.assertIsInstance(mail.to_raw, str)
        self.assertEqual(raw, result[0][1])

        raw = "meteo@regione.vda.it"
        result = mail.from_
        self.assertEqual(raw, result[0][1])

        raw = "Bollettino Meteorologico del 29/11/2015"
        result = mail.subject
        self.assertEqual(raw, result)

        result = mail.has_defects
        self.assertTrue(result)

        result = len(mail.attachments)
        self.assertEqual(3, result)

        self.assertIsInstance(mail.date_raw, str)
        self.assertIsInstance(mail.date_json, str)
        raw_utc = "2015-11-29T08:45:18+00:00"
        assert mail.date is not None
        result = mail.date.isoformat()
        self.assertEqual(raw_utc, result)

    def test_types(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertTrue(mail.has_defects)
        self.assertIn("CharsetDecodeDefect", mail.defects_categories)

        result = mail.mail
        self.assertIsInstance(result, dict)
        self.assertIn("defects", result)
        self.assertIn("has_defects", result)

        result = mail.get_server_ipaddress(trust)
        self.assertIsInstance(result, str)

        result = mail.mail_json
        self.assertIsInstance(result, str)

        result = mail.headers_json
        self.assertIsInstance(result, str)

        result = mail.headers
        self.assertIsInstance(result, dict)

        result = mail.body
        self.assertIsInstance(result, str)

        result = mail.date
        self.assertIsInstance(result, datetime.datetime)

        result = mail.from_
        self.assertIsInstance(result, list)

        result = mail.to
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], tuple)
        self.assertEqual(len(result[0]), 2)

        result = mail.subject
        self.assertIsInstance(result, str)

        result = mail.message_id
        self.assertIsInstance(result, str)

        result = mail.attachments
        self.assertIsInstance(result, list)

        result = mail.date
        self.assertIsInstance(result, datetime.datetime)

        result = mail.defects
        self.assertIsInstance(result, list)

    def test_defects(self):
        mail = mailparser.parse_from_file(mail_malformed_1)

        self.assertTrue(mail.has_defects)
        self.assertEqual(1, len(mail.defects))
        self.assertEqual(1, len(mail.defects_categories))
        self.assertIn("defects", mail.mail)
        self.assertIn("StartBoundaryNotFoundDefect", mail.defects_categories)
        self.assertIsInstance(mail.mail_json, str)

        result = len(mail.attachments)
        self.assertEqual(1, result)

        mail = mailparser.parse_from_file(mail_test_1)
        self.assertTrue(mail.has_defects)
        self.assertEqual(2, len(mail.defects))
        self.assertEqual(2, len(mail.defects_categories))
        self.assertIn("defects", mail.mail)
        self.assertIn("CloseBoundaryNotFoundDefect", mail.defects_categories)
        self.assertIn("AddressHeaderDefect", mail.defects_categories)
        self.assertEqual(
            mail.address_header_defects[0]["reason"], "overlong-encoded-word"
        )

    def test_defects_bug(self):
        mail = mailparser.parse_from_file(mail_malformed_2)

        self.assertTrue(mail.has_defects)
        self.assertEqual(1, len(mail.defects))
        self.assertEqual(1, len(mail.defects_categories))
        self.assertIn("defects", mail.mail)
        self.assertIn("StartBoundaryNotFoundDefect", mail.defects_categories)
        self.assertIsInstance(mail.parsed_mail_json, str)

        result = len(mail.attachments)
        self.assertEqual(1, result)

    def test_quoted_printable_application_attachment(self):
        # A quoted-printable application/* attachment must keep its exact
        # bytes, not be decoded as UTF-8, which drops the non-UTF8 ones.
        # It is re-encoded to base64 so that the reported payload matches
        # the declared transfer encoding: reporting raw QP text as a binary
        # payload made write_attachments() base64-decode it, saving bytes
        # that are neither the attachment nor what was on the wire.
        import quopri

        original = b"\xff\xfe\x00\x01PDFdata\x80\x81\x82\xc0\xc1"
        qp = quopri.encodestring(original).decode("ascii")
        raw = (
            "From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
            '--B\r\nContent-Type: application/octet-stream; name="f.bin"\r\n'
            "Content-Transfer-Encoding: quoted-printable\r\n"
            'Content-Disposition: attachment; filename="f.bin"\r\n\r\n'
            + qp
            + "\r\n--B--\r\n"
        )
        mail = mailparser.parse_from_string(raw)
        attachment = mail.attachments[0]
        self.assertTrue(attachment["binary"])
        self.assertEqual(attachment["content_transfer_encoding"], "base64")
        self.assertEqual(base64.b64decode(attachment["payload"]), original)

        # The bytes written to disk are the attachment, not a re-reading of
        # the wire text under a different encoding.
        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            with open(os.path.join(temp_dir, "f.bin"), "rb") as written:
                self.assertEqual(written.read(), original)

    def test_transfer_encoding_is_stripped(self):
        # email's own get_payload() strips the header before comparing it.
        # Without the same normalisation a trailing space missed every
        # encoding branch, and the raw bytes fell through the text path,
        # which silently drops every non-UTF-8 byte.
        original = b"MZ\x90\x00\x03\xff\xfeEICAR-TEST"
        encoded = base64.b64encode(original).decode("ascii")

        for transfer_encoding in ("base64", "base64 ", " base64", "base64\t"):
            raw = (
                'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
                "--B\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Transfer-Encoding: {transfer_encoding}\r\n"
                'Content-Disposition: attachment; filename="f.bin"\r\n\r\n'
                f"{encoded}\r\n--B--\r\n"
            )

            mail = mailparser.parse_from_string(raw)
            self.assertTrue(mail.attachments[0]["binary"])

            with tempfile.TemporaryDirectory() as temp_dir:
                mail.write_attachments(temp_dir)
                with open(os.path.join(temp_dir, "f.bin"), "rb") as written:
                    self.assertEqual(written.read(), original)

    def test_undefined_charset(self):
        # The "undefined" codec raises a bare UnicodeError, which is not a
        # UnicodeDecodeError and used to escape parse() entirely.
        raw = (
            "From: a@b.c\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
            'Content-Type: text/plain; charset="undefined"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\nQUJD\r\n"
        )

        mail = mailparser.parse_from_string(raw)

        self.assertEqual(mail.text_plain, ["ABC"])

    def test_hostile_charset_does_not_escape_parse(self):
        # get_payload(decode=False) applies the declared charset, and the
        # email package guards that only against an unknown charset name,
        # not against a codec that refuses outright.
        cases = (
            b'Content-Type: application/octet-stream; charset="undefined"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"Content-Disposition: attachment; filename=x.bin\r\n\r\n"
            b"QUJD\xff\r\n",
            b'Content-Type: text/plain; charset="undefined"\r\n'
            b"Content-Transfer-Encoding: 8bit\r\n\r\n\xff\xfe body\r\n",
            b'Content-Type: text/plain; charset="idna"\r\n'
            b"Content-Transfer-Encoding: 8bit\r\n\r\n\xff body\r\n",
            b'Content-Type: text/plain; charset="unicode_escape"\r\n'
            b"Content-Transfer-Encoding: 8bit\r\n\r\n\\udc80\xff\r\n",
        )

        for raw in cases:
            mail = mailparser.parse_from_bytes(raw)
            self.assertIsInstance(mail.mail_json, str)

    def test_body_transfer_encoding_is_stripped(self):
        # A trailing space sent the body down the branch that re-reads the
        # text through raw-unicode-escape, turning it into literal escapes
        # and hiding every non-ASCII indicator from a content scanner.
        body = "Ваш пароль истёк"

        for transfer_encoding in ("8bit", "8bit ", "8bit\t", "8BIT"):
            raw = (
                "From: a@b.c\r\nMIME-Version: 1.0\r\n"
                'Content-Type: text/plain; charset="utf-8"\r\n'
                f"Content-Transfer-Encoding: {transfer_encoding}\r\n\r\n"
                f"{body}\r\n"
            )

            mail = mailparser.parse_from_string(raw)
            self.assertIn(body, mail.text_plain[0])

    def test_write_attachments_repairs_base64_padding(self):
        # base64.b64decode() rejects padding errors every MUA repairs, so a
        # sender could strip one character to drop the attachment from the
        # extraction directory while it still reached the recipient.
        original = b"MZ\x90\x00EICAR-STANDARD"
        unpadded = base64.b64encode(original).decode("ascii").rstrip("=")
        raw = (
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            'Content-Disposition: attachment; filename="f.bin"\r\n\r\n'
            f"{unpadded}\r\n--B--\r\n"
        )

        mail = mailparser.parse_from_string(raw)

        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            with open(os.path.join(temp_dir, "f.bin"), "rb") as written:
                self.assertEqual(written.read(), original)

    def test_write_attachments_leaves_no_empty_stub(self):
        # A hostile charset used to reach the write through the text path,
        # where the payload was encoded only after open() had created the
        # file, leaving a zero-byte stub behind. Attachments now stay bytes,
        # so the charset never touches them.
        body = "AAAA" + r"\udcff" + "BBBB"
        raw = (
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: application/octet-stream; "
            'charset="raw-unicode-escape"\r\n'
            "Content-Transfer-Encoding: 7bit\r\n"
            'Content-Disposition: attachment; filename="f.bin"\r\n\r\n'
            f"{body}\r\n--B--\r\n"
        )

        mail = mailparser.parse_from_string(raw)

        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            written = os.path.join(temp_dir, "f.bin")
            self.assertNotEqual(os.path.getsize(written), 0)
            with open(written, "rb") as attachment:
                self.assertEqual(attachment.read(), body.encode("ascii"))

    def test_unencoded_attachment_keeps_every_byte(self):
        # Attachments declaring 7bit/8bit/binary used to be read back
        # through the declared charset with errors="ignore", which dropped
        # every byte that charset could not represent — half of a binary
        # payload — so the extracted file never hashed like the one the
        # recipient received.
        original = bytes(range(256)) * 16

        for transfer_encoding in ("7bit", "8bit", "binary"):
            raw = (
                b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
                b"--B\r\nContent-Type: application/octet-stream\r\n"
                b"Content-Transfer-Encoding: "
                + transfer_encoding.encode("ascii")
                + b"\r\n"
                b'Content-Disposition: attachment; filename="setup.exe"\r\n'
                b"\r\n" + original + b"\r\n--B--\r\n"
            )

            mail = mailparser.parse_from_bytes(raw)
            attachment = mail.attachments[0]
            self.assertTrue(attachment["binary"])
            self.assertEqual(attachment["content_transfer_encoding"], "base64")
            self.assertEqual(base64.b64decode(attachment["payload"]), original)

            with tempfile.TemporaryDirectory() as temp_dir:
                mail.write_attachments(temp_dir)
                with open(
                    os.path.join(temp_dir, "setup.exe"), "rb"
                ) as written:
                    self.assertEqual(written.read(), original)

    def test_write_attachments_case_insensitive_collision(self):
        # os.path.normcase() is the identity on POSIX, so names differing
        # only in case were treated as distinct while APFS, exFAT and SMB
        # collapse them: the second attachment overwrote the first.
        parts = "".join(
            "--B\r\nContent-Type: application/octet-stream\r\n"
            f'Content-Disposition: attachment; filename="{name}"\r\n\r\n'
            f"{payload}\r\n"
            for name, payload in (
                ("Invoice.pdf", "benign"),
                ("invoice.pdf", "malware"),
            )
        )
        raw = (
            f'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            f"{parts}--B--\r\n"
        )

        mail = mailparser.parse_from_string(raw)

        with tempfile.TemporaryDirectory() as temp_dir:
            mail.write_attachments(temp_dir)
            written = os.listdir(temp_dir)

            self.assertEqual(len(written), 2)
            contents = []
            for name in written:
                with open(os.path.join(temp_dir, name), "rb") as attachment:
                    contents.append(attachment.read())
            self.assertEqual(sorted(contents), [b"benign", b"malware"])

    def test_add_content_type(self):
        mail = mailparser.parse_from_file(mail_test_3)

        self.assertFalse(mail.has_defects)

        result = mail.mail

        self.assertEqual(len(result["attachments"]), 1)
        self.assertIsInstance(
            result["attachments"][0]["mail_content_type"], str
        )
        # Attachments are kept as bytes, so a quoted-printable part is
        # reported base64-wrapped rather than re-read through its charset.
        self.assertTrue(result["attachments"][0]["binary"])
        self.assertIsInstance(result["attachments"][0]["payload"], str)
        self.assertEqual(
            result["attachments"][0]["content_transfer_encoding"], "base64"
        )
        self.assertEqual(result["attachments"][0]["charset"], "iso-8859-1")
        self.assertIn(
            b"The WatchGuard Firebox",
            base64.b64decode(result["attachments"][0]["payload"]),
        )
        self.assertEqual(
            result["attachments"][0]["content-disposition"], "inline"
        )

        mail = mailparser.parse_from_file(mail_malformed_1)
        attachments = mail.mail["attachments"]
        self.assertEqual(attachments[0]["content-disposition"], "")

    def test_classmethods(self):
        # MailParser.from_file
        m = mailparser.MailParser.from_file(mail_test_3)
        m.parse()
        result = m.mail
        self.assertEqual(len(result["attachments"]), 1)

        # MailParser.from_string
        m = mailparser.MailParser.from_string(m.message_as_string)
        m.parse()
        result = m.mail
        self.assertEqual(len(result["attachments"]), 1)

    def test_bug_UnicodeDecodeError(self):
        m = mailparser.parse_from_file(mail_test_6)
        self.assertIsInstance(m.mail, dict)
        self.assertIsInstance(m.mail_json, str)

    @patch("mailparser.core.importlib.util.find_spec", return_value=None)
    @patch("mailparser.core._safe_remove")
    @patch("mailparser.core.msgconvert")
    def test_parse_from_file_msg(
        self, mock_msgconvert, mock_remove, mock_find_spec
    ):
        """
        Tested mail from VirusTotal: md5 b89bf096c9e3717f2d218b3307c69bd0

        The email used for unittest were found randomly on VirusTotal and
        then already publicly available so can not be considered
        as privacy violation
        """
        mock_msgconvert.return_value = (mail_test_2, None)
        m = mailparser.parse_from_file_msg(mail_outlook_1)
        mock_remove.assert_called_once_with(mail_test_2)
        email = m.mail
        self.assertIn("attachments", email)
        self.assertEqual(len(email["attachments"]), 3)
        self.assertIn("from", email)
        self.assertEqual(email["from"][0][1], "meteo@regione.vda.it")
        self.assertIn("subject", email)

    def test_from_file_obj(self):
        with ported_open(mail_test_2) as fp:
            mail = mailparser.parse_from_file_obj(fp)
        trust = "smtp.customers.net"

        self.assertFalse(mail.has_defects)

        result = mail.mail
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
        self.assertNotIn("anomalies", result)
        self.assertIn("has_defects", result)

        result = mail.get_server_ipaddress(trust)
        self.assertIsInstance(result, str)

        result = mail.mail_json
        self.assertIsInstance(result, str)

        result = mail.headers
        self.assertIsInstance(result, dict)

        result = mail.headers_json
        self.assertIsInstance(result, str)

        result = mail.body
        self.assertIsInstance(result, str)

        result = mail.date
        self.assertIsInstance(result, datetime.datetime)

        result = mail.from_
        self.assertIsInstance(result, list)

        result = mail.to
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], tuple)
        self.assertEqual(len(result[0]), 2)

        result = mail.subject
        self.assertIsInstance(result, str)

        result = mail.message_id
        self.assertIsInstance(result, str)

        result = mail.attachments
        self.assertIsInstance(result, list)

        result = mail.date
        self.assertIsInstance(result, datetime.datetime)

        result = mail.defects
        self.assertIsInstance(result, list)

        result = mail.timezone
        self.assertEqual(result, "+1.0")

    def test_get_to_domains(self):
        m = mailparser.parse_from_file(mail_test_6)

        domains_1 = get_to_domains(m.to, m.reply_to)
        self.assertIsInstance(domains_1, list)
        self.assertIn("test.it", domains_1)

        domains_2 = m.to_domains
        self.assertIsInstance(domains_2, list)
        self.assertIn("test.it", domains_2)
        self.assertEqual(domains_1, domains_2)

        self.assertIsInstance(m.to_domains_json, str)

    def test_convert_mail_date(self):
        s = "Mon, 20 Mar 2017 05:12:54 +0600"
        d, t = convert_mail_date(s)
        self.assertEqual(t, "+6.0")
        self.assertEqual(str(d), "2017-03-19 23:12:54+00:00")
        s = "Mon, 20 Mar 2017 05:12:54 -0600"
        d, t = convert_mail_date(s)
        self.assertEqual(t, "-6.0")
        s = "Mon, 11 Dec 2017 15:27:44 +0530"
        d, t = convert_mail_date(s)
        self.assertEqual(t, "+5.5")

    def test_ported_string(self):
        raw_data = ""
        s = ported_string(raw_data)
        self.assertEqual(s, str())

        raw_data = "test"
        s = ported_string(raw_data)
        self.assertEqual(s, "test")

    def test_parse_domain_with_tld_dot_id(self):
        """Support for .id tld (Indonesia)"""
        received = """
            from web.myhost.id
            by smtp.domain.id (Proxmox) with ESMTPS id SOMEIDHERE
            for <email@example.id>; Wed, 19 Feb 2025 15:00:00 +0700 (WIB)
        """.strip()

        expected = {
            "from": "web.myhost.id",
            "by": "smtp.domain.id (Proxmox)",
            "with": "ESMTPS",
            "id": "SOMEIDHERE",
            "for": "<email@example.id>",
            "date": "Wed, 19 Feb 2025 15:00:00 +0700 (WIB)",
        }

        values_by_clause = parse_received(received)

        self.assertEqual(expected, values_by_clause)

    def test_parse_domain_with_tld_dot_by(self):
        """Support for .by tld (Belarus)"""
        received = """
            from web.myhost.by
            by smtp.domain.by (Proxmox) with ESMTPS id SOMEIDHERE
            for <email@example.by>; Wed, 19 Feb 2025 15:00:00 +0700 (WIB)
        """.strip()

        expected = {
            "from": "web.myhost.by",
            "by": "smtp.domain.by (Proxmox)",
            "with": "ESMTPS",
            "id": "SOMEIDHERE",
            "for": "<email@example.by>",
            "date": "Wed, 19 Feb 2025 15:00:00 +0700 (WIB)",
        }

        values_by_clause = parse_received(received)

        self.assertEqual(expected, values_by_clause)

    def test_standard_outlook(self):
        """Verify a basic outlook received header works."""
        received = """
            from DM3NAM03FT035
            by CY4PR0601CA0051.outlook.office365.com
            with Microsoft SMTP Server version=TLS1_2, cipher=TLS
            id 15.20.1185.23
            via Frontend Transport; Mon, 1 Oct 2018 09:49:21 +0000
        """.strip()

        expected = {
            "from": "DM3NAM03FT035",
            "by": "CY4PR0601CA0051.outlook.office365.com",
            "with": "Microsoft SMTP Server version=TLS1_2, cipher=TLS",
            "id": "15.20.1185.23",
            "via": "Frontend Transport",
            "date": "Mon, 1 Oct 2018 09:49:21 +0000",
        }
        values_by_clause = parse_received(received)

        self.assertEqual(expected, values_by_clause)

    def test_standard_google__with_cipher(self):
        """Verify that we don't match 'with cipher' a la google."""
        received = """
            from mail_yw1_f65.google.com
            by subdomain.domain.com Postfix with ESMTPS
            id abc123 for <user@domain.com>;
            Tue, 25 Sep 2018 13:09:36 +0000 (UTC)"""

        expected = {
            "from": "mail_yw1_f65.google.com",
            "by": "subdomain.domain.com Postfix",
            "with": "ESMTPS",
            "id": "abc123",
            "for": "<user@domain.com>",
            "date": "Tue, 25 Sep 2018 13:09:36 +0000 (UTC)",
        }
        values_by_clause = parse_received(received)
        self.assertEqual(expected, values_by_clause)

    @unittest.skipIf(sys.version_info[0] < 3, "Must be using Python 3")
    def test_parse_from_bytes(self):
        with open(mail_test_2, "rb") as f:
            mail_bytes = f.read()

        mail = mailparser.parse_from_bytes(mail_bytes)
        trust = "smtp.customers.net"

        self.assertTrue(mail.has_defects)
        self.assertIn("CharsetDecodeDefect", mail.defects_categories)
        self.assertIn(
            {
                "text/html": [
                    "CharsetDecodeDefect: part 4, charset 'utf-8' failed; "
                    "decoded with utf-8 replacement characters. "
                    "Original bytes remain in the MIME part."
                ]
            },
            mail.defects,
        )

        raw = "217.76.210.112"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(raw, result)

        raw = "<4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>"
        result = mail.message_id
        self.assertEqual(raw, result)

        raw = "echo@tu-berlin.de"
        result = mail.to
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], tuple)
        self.assertIsInstance(mail.to_json, str)
        self.assertIsInstance(mail.to_raw, str)
        self.assertEqual(raw, result[0][1])

        raw = "meteo@regione.vda.it"
        result = mail.from_
        self.assertEqual(raw, result[0][1])

        raw = "Bollettino Meteorologico del 29/11/2015"
        result = mail.subject
        self.assertEqual(raw, result)

        result = mail.has_defects
        self.assertTrue(result)

        result = len(mail.attachments)
        self.assertEqual(3, result)

        self.assertIsInstance(mail.date_raw, str)
        self.assertIsInstance(mail.date_json, str)
        raw_utc = "2015-11-29T08:45:18+00:00"
        assert mail.date is not None
        result = mail.date.isoformat()
        self.assertEqual(raw_utc, result)

    def test_write_uuencode_attachment(self):
        mail = mailparser.parse_from_file(mail_test_15)
        temp_dir = tempfile.mkdtemp()
        mail.write_attachments(temp_dir)
        md5 = hashlib.md5()
        with open(os.path.join(temp_dir, "REQUEST FOR QUOTE.zip"), "rb") as f:
            md5.update(f.read())
        shutil.rmtree(temp_dir)
        self.assertEqual(md5.hexdigest(), "4f2cf891e7cfb349fca812091f184ecc")

    def test_issue_139(self):
        # mail_test_16 carries a literal "headers: hello-world" header.  It
        # used to re-enter the headers property, and the first fix dropped
        # the name from the key set.  Header values no longer resolve
        # through attribute lookup, so the recursion is impossible and the
        # header is reported like any other instead of being hidden.
        mail = mailparser.parse_from_file(mail_test_16)
        assert mail.headers == {
            "MIME-Version": "1.0",
            "Precedence": "junk",
            "Content-Type": "text/plain; charset=us-ascii",
            "From": [("Sender", "sender@example.net")],
            "Date": "Wed, 23 Jul 2003 23:30:00 +0200",
            "Content-Transfer-Encoding": "7bit",
            "Message-ID": "<GTUBE1.1010101@example.net>",
            "Subject": "Test spam mail (GTUBE)",
            "To": [("Recipient", "recipient@example.net")],
            "headers": "hello-world",
        }

    def test_issue_136(self):
        mail = mailparser.parse_from_file(mail_test_17)
        assert mail.from_ == [
            ("", "notificaccion-clientes@bbva.mx"),
        ]

    def test_str_method_with_message(self):
        """Test __str__ method returns subject when message exists"""
        mail = mailparser.parse_from_file(mail_test_1)
        str_result = str(mail)
        self.assertEqual(str_result, mail.subject)

    def test_str_method_without_message(self):
        """Test __str__ method returns empty string when no message"""
        # Create a MailParser with None message
        parser = mailparser.MailParser.__new__(mailparser.MailParser)
        parser._message = None
        str_result = str(parser)
        self.assertEqual(str_result, "")

    def test_from_file_obj_seekable(self):
        """Test from_file_obj with seekable file object"""
        import os
        import tempfile

        content = "From: test@example.com\nSubject: Test Seekable\n\nBody"
        # Create a real file to test seekable behavior
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".eml"
        ) as f:
            f.write(content)
            fname = f.name

        try:
            with ported_open(fname) as fp:
                mail = mailparser.parse_from_file_obj(fp)
                self.assertEqual(mail.subject, "Test Seekable")
        finally:
            os.unlink(fname)

    def test_from_file_obj_non_seekable(self):
        """Test from_file_obj with non-seekable file object (like stdin/TTY)"""
        import io

        content = "From: test@example.com\nSubject: Test Non-Seekable\n\nBody"

        # Create a mock non-seekable file object that acts like text
        class NonSeekableIO(io.StringIO):
            def seek(self, *args):
                raise OSError("File is not seekable")

        fp = NonSeekableIO(content)

        mail = mailparser.parse_from_file_obj(fp)
        self.assertEqual(mail.subject, "Test Non-Seekable")

    def test_get_server_ipaddress_invalid_ip(self):
        """Test get_server_ipaddress with invalid IP that raises ValueError"""
        # Create mail with received header containing invalid IP
        raw_mail = """Received: from invalid.example.com (999.999.999.999)
    by mail.example.com
Subject: Test
From: test@example.com

Body"""
        mail = mailparser.parse_from_string(raw_mail)

        # Should return None for invalid IP
        result = mail.get_server_ipaddress("trust")
        # The IP validation should fail and return None
        self.assertIsNone(result)

    def test_get_server_ipaddress_private_ip(self):
        """Test get_server_ipaddress with private IP address"""
        raw_mail = """Received: from internal.example.com (192.168.1.100)
    by mail.example.com
Subject: Test
From: test@example.com

Body"""
        mail = mailparser.parse_from_string(raw_mail)

        # Private IP should return None
        result = mail.get_server_ipaddress("trust")
        self.assertIsNone(result)

    def test_epilogue_parsing_typeerror(self):
        """Test epilogue parsing with TypeError"""
        # Create mail with problematic epilogue that causes TypeError
        # This is edge case where epilogue exists but can't be parsed
        raw_mail = """Content-Type: multipart/mixed; boundary=boundary

--boundary
Content-Type: text/plain

Test
--boundary--
InvalidEpilogueData"""

        mail = mailparser.parse_from_string(raw_mail)
        # Should handle TypeError gracefully
        self.assertIsNotNone(mail)

    def test_epilogue_parsing_typeerror_coverage(self):
        """Test epilogue parsing TypeError exception handler coverage"""
        import email
        from unittest.mock import patch

        # Create a mail with StartBoundaryNotFoundDefect to trigger epilogue
        # parsing
        raw_mail = """Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Test content
--boundary123--
Extra epilogue content here"""

        # Parse to get the message
        msg = email.message_from_string(raw_mail)

        # Mock email.message_from_string to raise TypeError
        with patch("email.message_from_string") as mock_parse:
            # First call is for initial parsing (let it pass)
            # Second call is for epilogue parsing (raise TypeError)
            mock_parse.side_effect = [msg, TypeError("Test TypeError")]

            # This won't trigger the epilogue path without defects
            # So we need to mock find_between to return something
            with patch("mailparser.core.find_between") as mock_find:
                mock_find.return_value = "epilogue content"

                # Mock the message to have epilogue defects
                with patch.object(
                    mailparser.MailParser,
                    "defects_categories",
                    {"StartBoundaryNotFoundDefect"},
                ):
                    mail = mailparser.parse_from_string(raw_mail)
                    # Should handle TypeError and continue
                    self.assertIsNotNone(mail)

    def test_epilogue_parsing_general_exception_coverage(self):
        """Test epilogue parsing general Exception handler coverage"""
        import email
        from unittest.mock import patch

        # Create a mail with boundary
        raw_mail = """Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Test content
--boundary123--
Extra epilogue content"""

        # Parse to get the message
        msg = email.message_from_string(raw_mail)

        # Mock email.message_from_string to raise a general Exception
        with patch("email.message_from_string") as mock_parse:
            mock_parse.side_effect = [msg, Exception("General error")]

            with patch("mailparser.core.find_between") as mock_find:
                mock_find.return_value = "epilogue content"

                # Mock defects_categories to trigger epilogue parsing
                with patch.object(
                    mailparser.MailParser,
                    "defects_categories",
                    {"StartBoundaryNotFoundDefect"},
                ):
                    mail = mailparser.parse_from_string(raw_mail)
                    # Should handle Exception and log error
                    self.assertIsNotNone(mail)

    def test_attachment_with_content_id_no_subtype(self):
        """Test attachment handling with content-id but no html/plain
        subtype"""
        raw_mail = """Content-Type: multipart/mixed; boundary=boundary

--boundary
Content-Type: image/png
Content-ID: <image001>

ImageData
--boundary--"""

        mail = mailparser.parse_from_string(raw_mail)
        self.assertGreater(len(mail.attachments), 0)

    def test_attachment_rtf_type(self):
        """Test attachment handling for RTF content subtype"""
        raw_mail = """Content-Type: multipart/mixed; boundary=boundary

--boundary
Content-Type: application/rtf

RTFData
--boundary--"""

        mail = mailparser.parse_from_string(raw_mail)
        attachments = mail.attachments
        self.assertGreater(len(attachments), 0)
        # Should have generated RTF filename
        self.assertTrue(
            any(".rtf" in att.get("filename", "") for att in attachments)
        )

    def test_attachment_disposition_without_filename(self):
        """Test attachment with content-disposition but no filename"""
        raw_mail = """Content-Type: multipart/mixed; boundary=boundary

--boundary
Content-Type: text/plain
Content-Disposition: attachment

PlainTextData
--boundary--"""

        mail = mailparser.parse_from_string(raw_mail)
        attachments = mail.attachments
        self.assertGreater(len(attachments), 0)
        # Should have generated .txt filename
        self.assertTrue(
            any(".txt" in att.get("filename", "") for att in attachments)
        )

    def test_text_plain_7bit_encoding(self):
        """Test text/plain body part with 7bit encoding"""
        raw_mail = """Content-Type: text/plain
Content-Transfer-Encoding: 7bit

This is plain text with 7bit encoding."""

        mail = mailparser.parse_from_string(raw_mail)
        self.assertIn("This is plain text", mail.body)

    def test_text_plain_8bit_encoding(self):
        """Test text/plain body part with 8bit encoding"""
        raw_mail = """Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

This is plain text with 8bit encoding."""

        mail = mailparser.parse_from_string(raw_mail)
        self.assertIn("This is plain text", mail.body)

    def test_comma_in_name(self):
        """
        Tests the fixes for both the 'comma-in-encoded-name' issue and the
        'encoded-name-equals-email' issue (from test_issue_136).
        """

        mail = mailparser.parse_from_file(mail_test_18)

        assert mail.from_ == [
            ("LastßlName, FirstName", "comma.name@example.com")
        ]
        assert mail.to == [("", "tony.stark@example.com")]
        assert mail.cc == [
            ("", "simple@example.net"),
            ('John "Johnny" Doe', "john.doe@example.com"),
        ]

    def test_init_with_message_object_logs_headers(self):
        """Test core.py:126->128 — MailParser.__init__ with message is
        not None"""
        import email as email_module

        from mailparser.core import MailParser

        raw = "From: test@example.com\nSubject: LogTest\n\nBody"
        msg = email_module.message_from_string(raw)

        with self.assertLogs("mailparser", level="DEBUG") as cm:
            parser = MailParser(message=msg)

        # The debug log about headers must have been emitted
        self.assertTrue(
            any("All headers of emails" in line for line in cm.output)
        )
        self.assertEqual(parser.subject, "LogTest")

    def test_init_with_none_message_skips_log(self):
        """Test core.py:126->128 — MailParser.__init__ message=None
        skips debug log"""
        from mailparser.core import MailParser

        # message=None: the if-branch is False, no log.debug call
        parser = MailParser(message=None)
        self.assertFalse(parser.message)

    def test_date_json_returns_none_when_no_date(self):
        """Test core.py:703->exit — date_json returns None when
        self.date is falsy"""
        # A mail with no Date header will have self.date == None
        raw = "From: test@example.com\nSubject: NoDat\n\nBody"
        mail = mailparser.parse_from_string(raw)
        # date should be None/falsy
        self.assertIsNone(mail.date)
        # date_json should return None (the if branch is not taken)
        self.assertIsNone(mail.date_json)

    def test_mail_partial_json_date_branch(self):
        """Test core.py:735->737 — mail_partial_json sets isoformat date"""
        raw = (
            "From: test@example.com\n"
            "Subject: PartialDate\n"
            "Date: Mon, 01 Jan 2024 12:00:00 +0000\n"
            "\nBody"
        )
        mail = mailparser.parse_from_string(raw)
        self.assertIsNotNone(mail.date)
        # mail_partial_json should include the isoformat date string
        result = mail.mail_partial_json
        self.assertIsInstance(result, str)
        self.assertIn("2024-01-01", result)

    def test_mail_partial_json_no_date(self):
        """Test core.py:735->737 False branch — mail_partial_json
        without date"""
        # Mail with no Date header: condition is False, skip line 736
        raw = "From: test@example.com\nSubject: NoDate\n\nBody"
        mail = mailparser.parse_from_string(raw)
        self.assertIsNone(mail.date)
        result = mail.mail_partial_json
        self.assertIsInstance(result, str)

    def test_sender_ip_no_message(self):
        """Test core.py:502 — get_server_ipaddress returns None with no
        message"""
        mail = mailparser.parse_from_string("fake mail")
        self.assertFalse(mail.message)
        result = mail.get_server_ipaddress("anything")
        self.assertIsNone(result)

    def test_extract_ip_ipv6_fallback(self):
        """Test _extract_ip uses IPv6 when IPv4 not found"""
        # 2001:db8::/32 is the documentation range, which Python reports as
        # private, so it cannot stand in for a routable sender here.  This
        # test used to use it and passed only because REGXIP6 matched inside
        # the "IPv6:" tag and returned the unrelated "6:2001:db8::".
        raw_mail = (
            "Received: from sender.example.com (IPv6:2a00:1450:4864:20::32)\n"
            " by mail.trusted.net; Mon, 01 Jan 2024 12:00:00 +0000\n"
            "From: test@example.com\n"
            "Subject: IPv6 test\n\nBody"
        )
        mail = mailparser.parse_from_string(raw_mail)
        result = mail.get_server_ipaddress("trusted.net")
        # the whole address, and not a fragment of the tag before it
        self.assertEqual(result, "2a00:1450:4864:20::32")

    def test_public_ip_returns_none_for_unparsable_candidate(self):
        """_public_ip returns None when the candidate is not an IP address"""
        parser = mailparser.parse_from_string(
            "From: t@example.com\nSubject: x\n\nBody"
        )
        self.assertIsNone(parser._public_ip(["not_a_valid_ip"]))
        self.assertIsNone(parser._public_ip([]))

    def test_extract_ip_private_ip_returns_none(self):
        """Test core.py:544 — _extract_ip returns None when IP is private"""
        raw_mail = (
            "Received: from internal.corp (10.0.0.1)\n"
            " by mail.trusted.org; Mon, 01 Jan 2024 12:00:00 +0000\n"
            "From: test@example.com\n"
            "Subject: Private IP\n\nBody"
        )
        mail = mailparser.parse_from_string(raw_mail)
        result = mail.get_server_ipaddress("trusted.org")
        self.assertIsNone(result)

    def test_extract_ip_no_ip_found_returns_none(self):
        """Test core.py:533->544 — _extract_ip returns None when no IP
        found at all"""
        mail = mailparser.parse_from_string(
            "From: t@example.com\nSubject: x\n\nBody"
        )
        # A received header with no IP addresses at all
        result = mail._extract_ip("from hostname by other-hostname")
        self.assertIsNone(result)

    def test_unicode_decode_error_in_payload(self):
        """Test core.py:447-448 — UnicodeDecodeError fallback when
        decoding payload"""
        # A body containing a backslash-u followed by non-hex characters
        # causes raw-unicode-escape to raise UnicodeDecodeError (line 447),
        # which is caught and falls back to ported_string (line 448).
        # The part has no CTE so the try/except branch is entered.
        backslash_u_invalid = chr(92) + "uggg"
        raw_mail = (
            "Content-Type: multipart/mixed; boundary=TEST_BOUND\n"
            "\n"
            "--TEST_BOUND\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "hello " + backslash_u_invalid + " world\n"
            "--TEST_BOUND--\n"
        )
        mail = mailparser.parse_from_string(raw_mail)
        # Should have parsed successfully and body contains the text
        self.assertIn("hello", mail.body)

    def _make_utf8_raw(self, cte_header=""):
        """Return a minimal raw email bytes with UTF-8 body (em-dash
        U+2014)."""
        cte_line = (
            f"Content-Transfer-Encoding: {cte_header}\n" if cte_header else ""
        )
        raw = (
            "From: a@example.com\n"
            "To: b@example.com\n"
            "Subject: probe\n"
            f"Content-Type: text/plain; charset=utf-8\n"
            "MIME-Version: 1.0\n"
            f"{cte_line}"
            "\n"
            "Hello — world\n"
        )
        return raw.encode("utf-8")

    def test_utf8_body_from_bytes_no_cte(self):
        """parse_from_bytes must not mojibake UTF-8 body with no CTE
        (issue #152)."""
        raw = self._make_utf8_raw()
        mail = mailparser.parse_from_bytes(raw)
        self.assertEqual(mail.text_plain[0], "Hello — world\n")

    def test_utf8_body_from_bytes_cte_8bit(self):
        """parse_from_bytes must not mojibake UTF-8 body with CTE: 8bit
        (issue #152)."""
        raw = self._make_utf8_raw("8bit")
        mail = mailparser.parse_from_bytes(raw)
        self.assertEqual(mail.text_plain[0], "Hello — world\n")

    def test_utf8_body_from_bytes_cte_7bit(self):
        """parse_from_bytes must not mojibake ASCII body with CTE: 7bit
        (issue #152)."""
        raw = (
            b"From: a@example.com\n"
            b"To: b@example.com\n"
            b"Content-Type: text/plain; charset=utf-8\n"
            b"Content-Transfer-Encoding: 7bit\n"
            b"\n"
            b"Hello world\n"
        )
        mail = mailparser.parse_from_bytes(raw)
        self.assertEqual(mail.text_plain[0], "Hello world\n")

    def test_utf8_body_from_bytes_matches_from_string(self):
        """parse_from_bytes and parse_from_string: identical text_plain
        (issue #152)."""
        raw_bytes = self._make_utf8_raw()
        raw_str = raw_bytes.decode("utf-8")
        mail_b = mailparser.parse_from_bytes(raw_bytes)
        mail_s = mailparser.parse_from_string(raw_str)
        self.assertEqual(mail_b.text_plain[0], mail_s.text_plain[0])

    def test_utf8_body_from_bytes_8bit_matches_from_string(self):
        """parse_from_bytes (8bit CTE) matches parse_from_string (issue
        #152)."""
        raw_bytes = self._make_utf8_raw("8bit")
        raw_str = raw_bytes.decode("utf-8")
        mail_b = mailparser.parse_from_bytes(raw_bytes)
        mail_s = mailparser.parse_from_string(raw_str)
        self.assertEqual(mail_b.text_plain[0], mail_s.text_plain[0])


class TestEmailAsDisplayName(unittest.TestCase):
    """
    Tests for address parsing when the display name is itself an email address.

    RFC 5322 §3.4 forbids unquoted "@" in the display-name phrase, so a header
    like ``From: alice@example.com <bob@example.com>`` is technically
    non-conforming.  Python's strict parser (CVE-2023-27043 hardening) returns
    ``[('', '')]`` for such input, which would silently hide the real sender.

    mail-parser is a security/forensics tool: it intentionally bypasses this
    strict compliance and applies a regex fallback so that analysts always see
    the address values that are actually present in the header.
    """

    def test_from_email_as_display_name(self):
        """From header with an email address as display name is parsed
        correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.from_
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "bob@example.com")
        self.assertEqual(name, "alice@example.com")

    def test_cc_email_as_display_name(self):
        """CC header with an email address as display name is parsed
        correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.cc
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "frank@example.com")
        self.assertEqual(name, "eve@example.com")

    def test_reply_to_email_as_display_name(self):
        """Reply-To header with an email address as display name is
        parsed correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.reply_to
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "ivan@example.com")
        self.assertEqual(name, "henry@example.com")

    def test_to_mixed_addresses(self):
        """To header with a mix of quoted name and bare address is
        parsed correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.to
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        # "Charlie Brown" <charlie@example.com>
        name0, addr0 = result[0]
        self.assertEqual(addr0, "charlie@example.com")
        self.assertEqual(name0, "Charlie Brown")
        # dave@example.com  (bare address, no display name)
        name1, addr1 = result[1]
        self.assertEqual(addr1, "dave@example.com")
        self.assertEqual(name1, "")

    # ------------------------------------------------------------------
    # Edge-case tests via parse_from_string (no additional mail files needed)
    # ------------------------------------------------------------------

    def test_same_email_as_name_and_address_suppresses_name(self):
        """When display name == address, name is suppressed to empty string.

        This covers the case ``From: bob@example.com <bob@example.com>`` which
        is both RFC non-compliant (unquoted @) AND redundant.  After the regex
        fallback recovers the address, the existing name-suppression logic
        (decoded_name == email_addr → "") must still fire correctly.
        """
        mail = mailparser.parse_from_string(
            "From: bob@example.com <bob@example.com>\nSubject: x\n\nBody"
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "bob@example.com")
        self.assertEqual(name, "")

    def test_quoted_email_as_display_name(self):
        """Properly quoted email-as-name (RFC-compliant) is parsed by
        strict parser."""
        mail = mailparser.parse_from_string(
            'From: "alice@example.com" <bob@example.com>\nSubject: x\n\nBody'
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "bob@example.com")
        self.assertEqual(name, "alice@example.com")

    def test_standard_display_name_unchanged(self):
        """Standard ``Name <email>`` format still works correctly (no
        regression)."""
        mail = mailparser.parse_from_string(
            "From: Alice Smith <alice@example.com>\nSubject: x\n\nBody"
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "alice@example.com")
        self.assertEqual(name, "Alice Smith")

    def test_bare_address_no_display_name(self):
        """Bare address with no display name returns empty name (no
        regression)."""
        mail = mailparser.parse_from_string(
            "From: alice@example.com\nSubject: x\n\nBody"
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "alice@example.com")
        self.assertEqual(name, "")

    def test_empty_header_returns_empty_list(self):
        """A missing address header returns [] — absent headers must not
        appear."""
        mail = mailparser.parse_from_string("Subject: x\n\nBody")
        # Python's getaddresses("") yields [('', '')], but we filter out
        # entries
        # with an empty address so that absent headers are not included in the
        # parsed mail object.
        self.assertEqual(mail.from_, [])

    # ------------------------------------------------------------------
    # Unit tests for get_addresses() helper directly
    # ------------------------------------------------------------------

    def test_get_addresses_email_as_name(self):
        """get_addresses() fallback recovers address when display name
        is an email."""
        result = get_addresses("alice@example.com <bob@example.com>")
        self.assertEqual(result, [("alice@example.com", "bob@example.com")])

    def test_get_addresses_standard_format(self):
        """get_addresses() strict path handles normal ``Name <email>``
        correctly."""
        result = get_addresses("Alice Smith <alice@example.com>")
        self.assertEqual(result, [("Alice Smith", "alice@example.com")])

    def test_get_addresses_bare_email(self):
        """get_addresses() handles bare email address with no display name."""
        result = get_addresses("alice@example.com")
        self.assertEqual(result, [("", "alice@example.com")])

    def test_get_addresses_empty_header(self):
        """get_addresses() on empty string returns [('', '')] — raw
        Python lib result.

        The ('', '') entry is filtered out in __getattr__ (core.py) so that
        absent headers do not appear in the parsed mail output.
        """
        result = get_addresses("")
        self.assertEqual(result, [("", "")])

    def test_get_addresses_multiple_with_email_as_name(self):
        """get_addresses() fallback handles multiple addresses when all
        fail strict."""
        result = get_addresses(
            "alice@example.com <bob@example.com>, eve@example.com "
            "<frank@example.com>"
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("alice@example.com", "bob@example.com"))
        self.assertEqual(result[1], ("eve@example.com", "frank@example.com"))


# ---------------------------------------------------------------------------
# Outlook .msg conversion backends (extract-msg vs deprecated msgconvert)
# ---------------------------------------------------------------------------


def test_from_file_msg_prefers_extract_msg(mocker):
    """extract-msg is preferred and msgconvert is NOT called when available."""
    mocker.patch("importlib.util.find_spec", return_value=object())
    extract = mocker.patch(
        "mailparser.core.extract_msg_convert",
        return_value=(mail_test_2, "info"),
    )
    msgconv = mocker.patch("mailparser.core.msgconvert")
    remove = mocker.patch("mailparser.core._safe_remove")

    mailparser.parse_from_file_msg(mail_outlook_1)

    extract.assert_called_once_with(mail_outlook_1)
    msgconv.assert_not_called()
    remove.assert_called_once_with(mail_test_2)


def test_from_file_msg_fallback_warns(mocker, caplog):
    """When extract-msg is absent, msgconvert runs and a deprecation warns."""
    mocker.patch("importlib.util.find_spec", return_value=None)
    msgconv = mocker.patch(
        "mailparser.core.msgconvert",
        return_value=(mail_test_2, None),
    )
    mocker.patch("mailparser.core._safe_remove")

    with caplog.at_level(logging.WARNING, logger="mailparser.core"):
        mailparser.parse_from_file_msg(mail_outlook_1)

    msgconv.assert_called_once_with(mail_outlook_1)
    messages = [r.message for r in caplog.records]
    assert any("deprecated" in m for m in messages)
    assert any("mail-parser[outlook]" in m for m in messages)


def test_from_file_msg_no_backend_raises(mocker):
    """No backend at all → MailParserOSError mentioning both install paths."""
    mocker.patch("importlib.util.find_spec", return_value=None)
    mocker.patch(
        "mailparser.utils.subprocess.Popen",
        side_effect=OSError("no msgconvert"),
    )

    with pytest.raises(MailParserOSError) as exc:
        mailparser.parse_from_file_msg(mail_outlook_1)

    assert "mail-parser[outlook]" in str(exc.value)
    assert "msgconvert" in str(exc.value)


@pytest.mark.integration
def test_outlook_backend_parity():
    """mail_outlook_1 parses to the same result under both backends.

    Requires both the optional ``extract-msg`` dependency and the
    ``msgconvert`` Perl tool; skips otherwise. The two converters do not
    emit byte-identical ``.eml`` files, so only the meaningful parsed
    result is compared (key headers, attachment names/count). The raw
    body is intentionally not compared: msgconvert and extract-msg differ
    in line endings, MIME structure and RTF/HTML reconstruction.
    """

    # Force each backend explicitly via its util. from_file(..., True)
    # removes the temporary converted .eml after parsing.
    f_extract, _ = extract_msg_convert(mail_outlook_1)
    parsed_extract = mailparser.MailParser.from_file(f_extract, True)

    # Parsing from the original .msg Outlook file
    parsed_msgconv = mailparser.MailParser.from_file_msg(mail_outlook_1)

    for key in ("from", "to", "subject"):
        assert parsed_extract.mail.get(key) == parsed_msgconv.mail.get(key)

    assert parsed_extract.date == parsed_msgconv.date

    extract_names = sorted(a["filename"] for a in parsed_extract.attachments)
    msgconv_names = sorted(a["filename"] for a in parsed_msgconv.attachments)
    assert extract_names == msgconv_names


def test_deeply_nested_multipart_raises_controlled_error():
    """
    Regression: a deeply nested multipart 'bomb' must raise the library's own
    MailParserRecursionError (a MailParserError), not a bare RecursionError.

    Python's email parser recurses per nesting level; without the guard an
    attacker-supplied ~55 KB message would crash the parsing worker with an
    exception outside the documented MailParser* hierarchy (crash-DoS,
    CWE-674).
    """
    raw = (
        "From: a@b.c\r\n"
        + "".join(
            f"Content-Type: multipart/mixed; boundary=B{i}\r\n\r\n--B{i}\r\n"
            for i in range(3000)
        )
        + "text\r\n"
    )
    with pytest.raises(MailParserRecursionError):
        mailparser.parse_from_string(raw)
    # And the bytes entry point is guarded identically.
    with pytest.raises(MailParserRecursionError):
        mailparser.parse_from_bytes(raw.encode())


def _nested_multipart(depth, closed=True):
    """
    A text leaf under ``depth`` nested multiparts; ``closed=False`` leaves
    out every close delimiter.
    """
    opening = "".join(
        f'Content-Type: multipart/mixed; boundary="B{i}"\r\n\r\n--B{i}\r\n'
        for i in range(depth)
    )
    closing = "".join(f"--B{i}--\r\n" for i in reversed(range(depth)))
    return (
        "From: a@b.example\r\n"
        + opening
        + "Content-Type: text/plain\r\n\r\nleaf\r\n"
        + (closing if closed else "")
    )


def _nested_rfc822(depth):
    """A text leaf under ``depth`` nested ``message/rfc822`` parts."""
    return (
        "From: a@b.example\r\n"
        + "Content-Type: message/rfc822\r\n\r\n" * depth
        + "Content-Type: text/plain\r\n\r\nleaf\r\n"
    )


def _unterminated_multipart(depth):
    return _nested_multipart(depth, closed=False)


NESTED_SHAPES = pytest.mark.parametrize(
    ("build", "defects_categories"),
    [
        (_nested_multipart, set()),
        (_nested_rfc822, set()),
        (_unterminated_multipart, {"CloseBoundaryNotFoundDefect"}),
    ],
)


@NESTED_SHAPES
def test_message_as_string_too_deep_raises_controlled_error(
    build, defects_categories
):
    """
    Regression (GHSA-j23h-c3w8-q63p): the generator recurses four frames
    per nesting level, so a message the parser accepts can be too deep to
    flatten.  The export must fail inside the MailParser* hierarchy, and
    everything the parse recovered must stay readable.
    """
    depth = sys.getrecursionlimit() // 3
    mail = mailparser.parse_from_string(build(depth))

    with pytest.raises(MailParserRecursionError) as raised:
        mail.message_as_string
    assert isinstance(raised.value.__cause__, RecursionError)

    # Nesting depth is not a MIME violation: no defect is invented, and
    # the ones the message does have are kept.
    assert mail.defects_categories == defects_categories
    assert mail.from_ == [("", "a@b.example")]
    assert mail.body.strip() == "leaf"
    assert len(mail.mime_tree) == depth + 1
    assert len(list(_walk_iteratively(mail.message))) == depth + 1


@NESTED_SHAPES
def test_message_as_string_flattens_shallow_nesting(build, defects_categories):
    """A nesting the generator can walk is flattened and parses back."""
    depth = 5
    mail = mailparser.parse_from_string(build(depth))

    flattened = mail.message_as_string

    assert mail.defects_categories == defects_categories
    reparsed = mailparser.parse_from_string(flattened)
    assert reparsed.from_ == [("", "a@b.example")]
    assert reparsed.body.strip() == "leaf"
    assert len(reparsed.mime_tree) == depth + 1


def _walk_iteratively(message):
    """Yield every part without recursing: ``Message.walk()`` recurses."""
    pending = [message]
    while pending:
        part = pending.pop()
        yield part
        if part.is_multipart():
            pending.extend(part.get_payload())


# A part both generators refuse: its type says multipart, it has no
# boundary, and ``undefined`` is a codec that decodes nothing.
_REFUSED_PART = (
    'Content-Type: multipart/report; charset="undefined"\r\n'
    "Content-Transfer-Encoding: 8bit\r\n\r\n\udcff\udcfe refused\r\n"
)
# A part ``as_string()`` refuses and ``as_bytes()`` writes as it is.
_REFUSED_TEXT = (
    'Content-Type: text/plain; charset="undefined"\r\n'
    "Content-Transfer-Encoding: 8bit\r\n\r\n\udcff\udcfe text\r\n"
)
_PLAIN_TEXT = "Content-Type: text/plain\r\n\r\n{}\r\n"


def _multipart(boundary, *entities, preamble="", epilogue=""):
    """A multipart entity around the given entities."""
    return (
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
        + preamble
        + "".join(f"--{boundary}\r\n{entity}" for entity in entities)
        + f"--{boundary}--\r\n"
        + epilogue
    )


def _around(leaf, depth):
    """``leaf`` under ``depth`` multiparts, with a sibling on each side."""
    entity = leaf
    for level in range(depth):
        entity = _multipart(
            f"N{level}",
            _PLAIN_TEXT.format("before"),
            entity,
            _PLAIN_TEXT.format("after"),
        )
    return "From: a@b.example\r\n" + entity


def _refusing_multiparts(depth):
    return _around(_REFUSED_PART, depth)


def _refusing_rfc822(depth):
    return (
        "From: a@b.example\r\n"
        + "Content-Type: message/rfc822\r\n\r\n" * depth
        + _REFUSED_PART
    )


def _refusing_container(depth):
    """
    A multipart whose boundary ``as_bytes()`` cannot write, around a part
    ``as_string()`` refuses: no part refuses both, the container does.
    """
    return _around(_multipart("\xe9", _REFUSED_TEXT), depth)


def _refused_by_as_string_only(depth):
    return _around(_REFUSED_TEXT, depth)


def _conforming_multiparts(depth):
    return _around(_PLAIN_TEXT.format("leaf"), depth)


def _from_octets(text):
    return mailparser.parse_from_bytes(text.encode("ascii", "surrogateescape"))


@pytest.fixture
def flattened(monkeypatch):
    """Every part a generator flattens, once for each time it does."""
    parts = []
    flatten = Generator.flatten

    def counting(self, msg, *args, **kwargs):
        parts.append(msg)
        return flatten(self, msg, *args, **kwargs)

    monkeypatch.setattr(Generator, "flatten", counting)
    return parts


@pytest.mark.parametrize(
    ("parse", "build", "passes"),
    [
        (_from_octets, _refusing_multiparts, 3),
        (_from_octets, _refusing_rfc822, 3),
        (mailparser.parse_from_string, _refusing_container, 3),
        (_from_octets, _refused_by_as_string_only, 2),
        (_from_octets, _conforming_multiparts, 1),
    ],
)
@pytest.mark.parametrize("depth", [1, 10, 40])
def test_message_as_string_flattens_each_part_a_bounded_number_of_times(
    parse, build, passes, depth, flattened
):
    """
    Regression: the fallback flattened a container again for every level
    between it and the part that refused, so a refusing part under
    ``depth`` containers cost the size of the message times ``depth``.
    Each part is now flattened at most three times: by a pass of
    ``as_string()`` that fails, by one of ``as_bytes()`` that fails,
    and by the pass that writes it.
    """
    mail = parse(build(depth))
    parts = len(mail.mime_tree)
    assert parts > depth
    del flattened[:]

    text = mail.message_as_string

    assert isinstance(text, str)
    assert len(flattened) <= passes * parts
    if build is _conforming_multiparts:
        assert len(flattened) == parts


_FALLBACK_TREE = (
    "From: a@b.example\r\n"
    + _multipart(
        "A",
        _PLAIN_TEXT.format("before A"),
        _multipart(
            "B",
            _PLAIN_TEXT.format("before B"),
            _REFUSED_PART,
            _REFUSED_TEXT,
        ),
        _multipart("C", _PLAIN_TEXT.format("after A")),
        preamble="preamble A\r\n",
        epilogue="epilogue A\r\n",
    )
).encode("ascii", "surrogateescape")

_FALLBACK_RFC822 = (
    "From: a@b.example\r\n"
    "Content-Type: message/rfc822\r\n\r\n"
    "Subject: one\r\nContent-Type: message/rfc822\r\n\r\n"
    "Subject: two\r\n" + _REFUSED_PART
).encode("ascii", "surrogateescape")

_NO_BOUNDARY = (
    "NoBoundaryInMultipartDefect: A message claimed to be a multipart but "
    "had no boundary parameter."
)
_NO_SUBPARTS = (
    "MultipartInvariantViolationDefect: A message claimed to be a multipart "
    "but no subparts were found."
)


def _charset_defect(part):
    return (
        f"CharsetDecodeDefect: part {part}, charset 'undefined' failed; "
        "decoded with utf-8 replacement characters. Original bytes remain "
        "in the MIME part."
    )


@pytest.mark.parametrize(
    ("parse", "raw", "expected", "body", "defects", "tree"),
    [
        pytest.param(
            mailparser.parse_from_bytes,
            _FALLBACK_TREE,
            # A and B are written from their raw headers and their
            # sub-parts, without delimiters, preamble or epilogue; the
            # parts that flatten are written by the generator.
            "From: a@b.example\n"
            'Content-Type: multipart/mixed; boundary="A"\n\n'
            "Content-Type: text/plain\n\nbefore A"
            'Content-Type: multipart/mixed; boundary="B"\n\n'
            "Content-Type: text/plain\n\nbefore B"
            'Content-Type: multipart/report; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe refused\r\n"
            'Content-Type: text/plain; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe text"
            'Content-Type: multipart/mixed; boundary="C"\n\n'
            "--C\nContent-Type: text/plain\n\nafter A\n--C--\n",
            "before A\n--- mail_boundary ---\nbefore B\n"
            "--- mail_boundary ---\n\ufffd\ufffd text\n"
            "--- mail_boundary ---\nafter A\n"
            "--- mail_boundary ---\n\ufffd\ufffd refused\r\n",
            [
                {"multipart/report": [_NO_BOUNDARY]},
                {"multipart/report": [_charset_defect(4)]},
                {"text/plain": [_charset_defect(5)]},
            ],
            [
                ("multipart/mixed", None),
                ("text/plain", 0),
                ("multipart/mixed", 0),
                ("text/plain", 2),
                ("multipart/report", 2),
                ("text/plain", 2),
                ("multipart/mixed", 0),
                ("text/plain", 6),
            ],
            id="multiparts",
        ),
        pytest.param(
            mailparser.parse_from_bytes,
            _FALLBACK_RFC822,
            "From: a@b.example\nContent-Type: message/rfc822\n\n"
            "Subject: one\nContent-Type: message/rfc822\n\n"
            "Subject: two\n"
            'Content-Type: multipart/report; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe refused\r\n",
            "\ufffd\ufffd refused\r\n",
            [
                {"multipart/report": [_NO_BOUNDARY]},
                {"multipart/report": [_charset_defect(2)]},
            ],
            [
                ("message/rfc822", None),
                ("message/rfc822", 0),
                ("multipart/report", 1),
            ],
            id="rfc822",
        ),
        pytest.param(
            mailparser.parse_from_bytes,
            ("From: a@b.example\r\n" + _REFUSED_PART).encode(
                "ascii", "surrogateescape"
            ),
            "From: a@b.example\n"
            'Content-Type: multipart/report; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe refused\r\n",
            "\ufffd\ufffd refused\r\n",
            [
                {"multipart/report": [_NO_BOUNDARY, _NO_SUBPARTS]},
                {"multipart/report": [_charset_defect(0)]},
            ],
            [("multipart/report", None)],
            id="no-boundary-root",
        ),
        pytest.param(
            mailparser.parse_from_string,
            "From: a@b.example\r\n"
            + _multipart(
                "A",
                _PLAIN_TEXT.format("before A"),
                _multipart(
                    "\xe9",
                    _PLAIN_TEXT.format("before B"),
                    _REFUSED_TEXT,
                ),
                _PLAIN_TEXT.format("after A"),
            ),
            # No part refuses as_bytes() here: the container does, at
            # its own boundary, after its sub-parts were written.
            "From: a@b.example\n"
            'Content-Type: multipart/mixed; boundary="A"\n\n'
            "Content-Type: text/plain\n\nbefore A"
            'Content-Type: multipart/mixed; boundary="\xe9"\n\n'
            "Content-Type: text/plain\n\nbefore B"
            'Content-Type: text/plain; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe text"
            "Content-Type: text/plain\n\nafter A",
            "before A\n--- mail_boundary ---\nbefore B\n"
            "--- mail_boundary ---\n\ufffd\ufffd text\n"
            "--- mail_boundary ---\nafter A",
            [{"text/plain": [_charset_defect(4)]}],
            [
                ("multipart/mixed", None),
                ("text/plain", 0),
                ("multipart/mixed", 0),
                ("text/plain", 2),
                ("text/plain", 2),
                ("text/plain", 0),
            ],
            id="container-refuses-as-bytes",
        ),
    ],
)
def test_message_as_string_fallback_output_is_unchanged(
    parse, raw, expected, body, defects, tree
):
    """
    The strings are the ones the fallback produced before it stopped
    flattening a refusing part twice.  What the parse recovered and the
    defects it recorded are the same before and after the export.
    """
    mail = parse(raw)

    for _ in range(2):
        assert mail.body == body
        assert mail.defects == defects
        assert mail.has_defects is True
        assert mail.attachments == []
        assert mail.resource_limit_defects == []
        assert mail.from_ == [("", "a@b.example")]
        assert [
            (entry["content_type"], entry["parent"])
            for entry in mail.mime_tree
        ] == tree
        assert mail.message_as_string == expected


def test_message_as_string_flattens_again_under_another_policy():
    """
    A part is known to refuse only when flattening it alone repeats what
    the failed pass did.  Here the root has a policy of its own, under
    which ``as_bytes()`` applies the charset; the inner multipart has
    not, and is still flattened: its delimiters are in the output.
    """
    message = email.message_from_bytes(
        (
            "From: a@b.example\r\n"
            + _multipart("A", _multipart("B", _REFUSED_TEXT))
        ).encode("ascii", "surrogateescape")
    )
    message.policy = email.policy.compat32.clone(cte_type="7bit")

    assert mailparser.MailParser(message).message_as_string == (
        "From: a@b.example\n"
        'Content-Type: multipart/mixed; boundary="A"\n\n'
        'Content-Type: multipart/mixed; boundary="B"\n\n'
        '--B\nContent-Type: text/plain; charset="undefined"\n'
        "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe text\n--B--\n"
    )


class _RefusesUnfoldedHeader(email.policy.EmailPolicy):
    """Refuses to write ``X-Long`` when lines have no length limit."""

    def fold_binary(self, name, value):
        if name == "X-Long" and self.max_line_length == 0:
            raise UnicodeEncodeError("ascii", value, 0, 1, "unfolded")
        return super().fold_binary(name, value)


def test_message_as_string_flattens_again_below_a_signed_part():
    """
    Below ``multipart/signed`` the generator writes headers without a
    line length limit, which is not how it writes the same part alone.
    Container C refuses ``as_bytes()`` in the pass over the root only
    for that reason: alone it flattens, and its delimiters are written.
    """
    signed = (
        'Content-Type: multipart/signed; boundary="S"\r\n\r\n'
        "--S\r\nX-Long: value\r\n"
        + _multipart("C", _REFUSED_TEXT)
        + "--S--\r\n"
    )
    message = email.message_from_bytes(
        ("From: a@b.example\r\n" + _multipart("A", signed)).encode(
            "ascii", "surrogateescape"
        ),
        policy=_RefusesUnfoldedHeader(),
    )

    text = mailparser.MailParser(message).message_as_string

    assert "--C\n" in text
    assert "--C--\n" in text
    assert "--S" not in text


def test_message_as_string_with_a_wrapped_generator(monkeypatch):
    """
    A tool that wrapped ``Generator.flatten`` before the parser was
    imported leaves frames with the code the fallback looks for and
    none of the locals it reads.  No part is named then: the export
    costs more passes and gives the same string.
    """
    mail = _from_octets(_refusing_multiparts(3))
    expected = mail.message_as_string
    flatten = Generator.flatten

    def wrapper(self, *args, **kwargs):
        return flatten(self, *args, **kwargs)

    monkeypatch.setattr(Generator, "flatten", wrapper)
    monkeypatch.setattr("mailparser.utils._FLATTEN_CODE", wrapper.__code__)

    assert mail.message_as_string == expected


class _FlattensItself(Message):
    """A part with a text of its own, whatever its charset."""

    def as_string(self, unixfrom=False, maxheaderlen=0, policy=None):
        return "written by the part itself\n"


def test_message_as_string_flattens_again_a_part_of_another_class():
    """
    The pass over the root never calls ``as_string()`` of a sub-part,
    so it says nothing about a sub-part whose class overrides it.
    """
    message = email.message_from_bytes(
        (
            "From: a@b.example\r\n" + _multipart("A", _PLAIN_TEXT.format("x"))
        ).encode()
    )
    message.set_payload(
        [
            email.message_from_bytes(
                _REFUSED_PART.encode("ascii", "surrogateescape"),
                _class=_FlattensItself,
            )
        ]
    )

    text = mailparser.MailParser(message).message_as_string

    assert text.endswith("written by the part itself\n")


def test_message_as_string_too_deep_beside_a_refusing_part():
    """
    The refusing part ends both passes over the root early, and the
    fallback reaches the deep sibling on its own: the ``RecursionError``
    of that pass is not a charset error and still reaches the guard.
    """
    depth = sys.getrecursionlimit() // 3
    deep = _nested_multipart(depth).partition("\r\n")[2]
    mail = mailparser.parse_from_string(
        "From: a@b.example\r\n" + _multipart("A", _REFUSED_PART, deep)
    )

    with pytest.raises(MailParserRecursionError) as raised:
        mail.message_as_string
    assert isinstance(raised.value.__cause__, RecursionError)
    assert len(mail.mime_tree) == depth + 3


@pytest.mark.parametrize("value", ["\ud800", "a\udfffb", "é\udcff"])
def test_message_as_string_writes_a_header_with_a_lone_surrogate(value):
    """
    A str, from JSON for one, can hold a surrogate no octet escapes to.
    Both generators refuse it and the email package cannot read it as
    octets: the hand-built text writes it as it was parsed.
    """
    mail = mailparser.parse_from_string(
        f"From: a@b.example\r\nX-A: {value}\r\nSubject: hello\r\n"
        "Content-Type: text/plain\r\n\r\nbody\r\n"
    )

    assert mail.message_as_string == (
        f"From: a@b.example\nX-A: {value}\nSubject: hello\n"
        "Content-Type: text/plain\n\nbody\r\n"
    )
    assert mail.subject == "hello"
    assert mail.body == "body\r\n"


def test_parse_keeps_an_attachment_with_a_lone_surrogate_header():
    """The parse flattens an attached container without a generator."""
    mail = mailparser.parse_from_string(
        'From: a@b.example\r\nContent-Type: multipart/mixed; boundary="R"\r\n'
        "\r\n"
        "--R\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        '--R\r\nContent-Type: multipart/mixed; boundary="I"\r\n'
        'Content-Disposition: attachment; filename="a.bin"\r\n\r\n'
        "--I\r\nContent-Type: text/plain\r\nX-H: \ud800\r\nX-B: kept\r\n\r\n"
        "inner\r\n--I--\r\n--R--\r\n"
    )

    [attachment] = mail.attachments
    assert attachment["filename"] == "a.bin"
    assert attachment["mail_content_type"] == "multipart/mixed"
    assert attachment["payload"] == (
        "Content-Type: text/plain\nX-H: \ud800\nX-B: kept\n\ninner"
    )
    assert mail.text_plain == ["body", "inner"]
    assert "\nX-H: \ud800\nX-B: kept\n\ninner" in mail.message_as_string


def test_message_as_string_keeps_an_escaped_octet_in_a_header():
    """An octet escaped by surrogateescape is written as it always was."""
    header = "X-A: x\udcffy\r\n"
    plain = mailparser.parse_from_string(
        f"From: a@b.example\r\n{header}Content-Type: text/plain\r\n\r\n"
        f"body\r\n"
    )
    refused = mailparser.parse_from_string(
        f"From: a@b.example\r\n{header}" + _REFUSED_PART
    )

    assert plain.message_as_string == (
        "From: a@b.example\nX-A: =?unknown-8bit?b?eP95?=\n"
        "Content-Type: text/plain\n\nbody\n"
    )
    assert refused.message_as_string == (
        "From: a@b.example\nX-A: x�y\n"
        'Content-Type: multipart/report; charset="undefined"\n'
        "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe refused\r\n"
    )


def _with_inner_header(header, attached):
    """A container, attached or not, whose text part has ``header``."""
    disposition = (
        'Content-Disposition: attachment; filename="c.eml"\r\n'
        if attached
        else ""
    )
    return (
        "From: a@b.example\r\nSubject: kept\r\n"
        'Content-Type: multipart/mixed; boundary="A"\r\n\r\n'
        "--A\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        '--A\r\nContent-Type: multipart/mixed; boundary="B"\r\n'
        f"{disposition}\r\n"
        f"--B\r\nContent-Type: text/plain\r\n{header}\r\n"
        "X-After: kept\r\n\r\ninner\r\n--B--\r\n--A--\r\n"
    ).encode("latin-1")


@pytest.mark.parametrize(
    "value",
    [
        "a\x0cb",
        "a\x0cB: c",
        "a\x0b--A",
        "a\x1cb",
        "a\x1d--B--",
        "a\x1e\x0cX-Forged: yes",
    ],
)
@pytest.mark.parametrize("attached", [True, False])
def test_header_the_generator_refuses_does_not_stop_the_parse(value, attached):
    """
    Regression: ``Header.encode()`` takes a form feed, and the other
    characters ``str.splitlines()`` breaks at, for a line break.  The
    generator then refuses the header with ``HeaderWriteError`` or
    ``HeaderParseError``, which are no charset errors: they left
    ``parse_from_bytes()`` when the part was below an attached
    container, and ``message_as_string`` wherever it was.  RFC 5322
    section 4.1 accepts these characters in a field body as obsolete
    syntax (``obs-NO-WS-CTL``), so no defect is reported.
    """
    mail = mailparser.parse_from_bytes(
        _with_inner_header(f"X-A: {value}", attached)
    )

    assert mail.message is not None
    inner = mail.message.get_payload(1).get_payload(0)
    assert inner["X-A"] == value
    assert inner["X-After"] == "kept"
    assert mail.subject == "kept"
    assert mail.has_defects is False
    assert mail.resource_limit_defects == []
    filenames = [attachment["filename"] for attachment in mail.attachments]
    assert filenames == (["c.eml"] if attached else [])
    reparsed = mailparser.parse_from_string(mail.message_as_string)
    assert reparsed.subject == "kept"
    assert "X-Forged" not in reparsed.headers


@pytest.mark.parametrize("attached", [True, False])
def test_header_the_generator_refuses_is_written_as_it_was_parsed(attached):
    """
    The value below is refused by every Python release, as an embedded
    header.  The part is written by hand with the value as it was
    parsed, on one line: nothing is dropped and no header is forged.
    """
    mail = mailparser.parse_from_bytes(
        _with_inner_header("X-A: a\x0cB: c", attached)
    )
    written = (
        "Content-Type: text/plain\nX-A: a\x0cB: c\nX-After: kept\n\ninner"
    )

    assert written in mail.message_as_string
    payloads = [attachment["payload"] for attachment in mail.attachments]
    assert payloads == ([written] if attached else [])


@pytest.mark.skipif(
    not hasattr(email.errors, "HeaderWriteError"),
    reason="this Python lacks the fix of CVE-2024-6923",
)
@pytest.mark.parametrize("attached", [True, False])
def test_header_the_generator_refuses_is_not_given_to_the_bytes_pass(attached):
    """
    The text generator refuses the header below, and the bytes
    generator of some releases writes it, with a line break for each
    form feed: a line ``--B`` the sender chose, which a second parse
    reads as a delimiter.  The part is written by hand instead.
    """
    value = "a\x0c--B\x0cforged"
    mail = mailparser.parse_from_bytes(
        _with_inner_header(f"X-A: {value}", attached)
    )

    text = mail.message_as_string

    assert f"X-A: {value}\nX-After: kept\n\ninner" in text
    assert "\nforged\n" not in text
    for attachment in mail.attachments:
        assert f"X-A: {value}\nX-After: kept" in attachment["payload"]
        assert "\nforged\n" not in attachment["payload"]


def test_as_string_safe_with_a_budget_debits_every_pass(flattened):
    """
    At parse time every pass is debited, also one that fails, and the
    debit decides which containers reach the resource limit: with a
    budget no pass is skipped and the amounts stay what they were.
    """
    mail = _from_octets(_refusing_multiparts(6))
    assert mail.message is not None
    unbounded = mail.message_as_string
    budget = SerializationBudget(list(mail.message.walk()))
    characters, nodes = budget.characters, budget.nodes
    del flattened[:]

    text = as_string_safe(mail.message, budget=budget)

    assert text == unbounded
    assert characters - budget.characters == 5398
    assert nodes - budget.nodes == 117
    assert len(flattened) == 110


def _empty_boundary(declared='boundary=""'):
    """A multipart entity whose boundary is empty: ``--`` and ``----``."""
    return (
        f"Content-Type: multipart/mixed; {declared}\r\n\r\n"
        "--\r\n" + _PLAIN_TEXT.format("inside") + "----\r\n"
    )


def _raw_headers(message):
    """The headers of every part, as the message stores them."""
    return [
        [(name, str(value)) for name, value in part.raw_items()]
        for part in _walk_iteratively(message)
    ]


def _tree_shape(mail):
    return [
        (entry["content_type"], entry["parent"], entry["boundary"])
        for entry in mail.mime_tree
    ]


def _empty_boundary_defect(part, raw_value: object = ""):
    """The defect of the part that declares an empty boundary."""
    return {
        "mime-headers": [
            f"MimeHeaderDefect: part {part}, "
            f"invalid-boundary-parameter: empty; raw={raw_value!r}"
        ]
    }


@pytest.mark.parametrize(
    ("declared", "raw_value", "other_defects"),
    [
        ('boundary=""', "", []),
        ("boundary=", "", []),
        ('boundary=" "', " ", []),
        ("boundary*=utf-8''", ("utf-8", "", ""), []),
        ("boundary*=utf-8''%20", ("utf-8", "", " "), []),
        ('boundary*0=""; boundary*1=""', "", []),
        ('boundary=""; boundary="evidence"', "", []),
        (
            "boundary*=undefined''%20",
            ("undefined", "", " "),
            ["invalid-boundary-parameter: raw=('undefined', '', ' ')"],
        ),
        (
            "boundary*=utf-8''; boundary*1=\"\"",
            ("utf-8", "", ""),
            [
                "content-type[0]: invalid-parameter-continuation; raw="
                + repr("multipart/mixed; boundary*=utf-8''; boundary*1=\"\"")
            ],
        ),
    ],
)
@pytest.mark.parametrize("tree_first", [True, False])
def test_message_as_string_keeps_an_empty_boundary(
    declared, raw_value, other_defects, tree_first
):
    """
    Regression: the generator takes an empty boundary for a missing one,
    invents another and writes it into the part.  Reading
    ``message_as_string`` rewrote ``mail.message``, erased the anomaly
    (RFC 2046 section 5.1.1 requires one character) and made what
    ``mime_tree`` reports depend on which property was read first.
    The anomaly is a defect of the part, with the value as evidence.
    """
    raw = "From: a@b.example\r\n" + _empty_boundary(declared)
    details = [
        *other_defects,
        f"invalid-boundary-parameter: empty; raw={raw_value!r}",
    ]
    expected_defects = [
        {
            "mime-headers": [
                f"MimeHeaderDefect: part 0, {detail}" for detail in details
            ]
        }
    ]
    mail = mailparser.parse_from_string(raw)
    untouched = mailparser.parse_from_string(raw)
    assert mail.message is not None
    headers = _raw_headers(mail.message)
    assert headers[0][1] == ("Content-Type", f"multipart/mixed; {declared}")
    if tree_first:
        assert mail.mime_tree == untouched.mime_tree

    text = mail.message_as_string

    assert text == (
        f"From: a@b.example\nContent-Type: multipart/mixed; {declared}\n\n"
        "--\nContent-Type: text/plain\n\ninside\n----\n"
    )
    assert mail.message_as_string == text
    assert mailparser.parse_from_string(raw).message_as_string == text
    assert _raw_headers(mail.message) == headers
    assert mail.mime_tree == untouched.mime_tree
    assert _tree_shape(mail) == [
        ("multipart/mixed", None, ""),
        ("text/plain", 0, None),
    ]
    json.dumps(mail.mime_tree).encode("utf-8")
    assert mail.body == "inside"
    assert mail.defects == untouched.defects == expected_defects
    assert mail.has_defects is True
    assert mail.mime_tree[0]["defects"] == ["MimeHeaderDefect"]
    # Outside a generator pass the accessor answers as Message does.
    boundary = mail.message.get_boundary()
    assert type(boundary) is str
    assert not boundary


def test_parse_keeps_an_empty_boundary_below_an_attached_container():
    """
    Regression: ``parse()`` flattens the sub-parts of an attached
    container, so the parse itself rewrote the empty boundary below it,
    and the payload of the attachment held a boundary that differed
    from one parse to the next.
    """
    raw = "From: a@b.example\r\n" + _multipart(
        "A",
        'Content-Type: multipart/mixed; boundary="T"\r\n'
        "Content-Disposition: attachment\r\n\r\n"
        "--T\r\n" + _empty_boundary("boundary*=utf-8''") + "--T--\r\n",
    )
    wire_headers = [
        [
            ("From", "a@b.example"),
            ("Content-Type", 'multipart/mixed; boundary="A"'),
        ],
        [
            ("Content-Type", 'multipart/mixed; boundary="T"'),
            ("Content-Disposition", "attachment"),
        ],
        [("Content-Type", "multipart/mixed; boundary*=utf-8''")],
        [("Content-Type", "text/plain")],
    ]

    mail = mailparser.parse_from_string(raw)

    assert mail.message is not None
    assert _raw_headers(mail.message) == wire_headers
    assert _tree_shape(mail) == [
        ("multipart/mixed", None, "A"),
        ("multipart/mixed", 0, "T"),
        ("multipart/mixed", 1, ""),
        ("text/plain", 2, None),
    ]
    payloads = [attachment["payload"] for attachment in mail.attachments]
    assert payloads == [
        "Content-Type: multipart/mixed; boundary*=utf-8''\n\n"
        "--\nContent-Type: text/plain\n\ninside\n----\n"
    ]
    again = mailparser.parse_from_string(raw)
    assert [
        attachment["payload"] for attachment in again.attachments
    ] == payloads
    assert mail.defects == [_empty_boundary_defect(2, ("utf-8", "", ""))]
    assert mail.has_defects is True
    assert mail.resource_limit_defects == []
    mail.message_as_string
    assert _raw_headers(mail.message) == wire_headers
    assert mail.mime_tree == again.mime_tree


def test_message_as_string_keeps_the_boundary_of_a_conforming_sibling():
    """
    A conforming multipart beside the one with an empty boundary is
    written with its own boundary, and the text parses back to the same
    tree.
    """
    raw = "From: a@b.example\r\n" + _multipart(
        "A", _empty_boundary(), _multipart("C", _PLAIN_TEXT.format("sibling"))
    )
    mail = mailparser.parse_from_string(raw)
    assert mail.message is not None
    headers = _raw_headers(mail.message)
    tree = [
        ("multipart/mixed", None, "A"),
        ("multipart/mixed", 0, ""),
        ("text/plain", 1, None),
        ("multipart/mixed", 0, "C"),
        ("text/plain", 3, None),
    ]

    text = mail.message_as_string

    assert text == (
        'From: a@b.example\nContent-Type: multipart/mixed; boundary="A"\n\n'
        '--A\nContent-Type: multipart/mixed; boundary=""\n\n'
        "--\nContent-Type: text/plain\n\ninside\n----\n\n"
        '--A\nContent-Type: multipart/mixed; boundary="C"\n\n'
        "--C\nContent-Type: text/plain\n\nsibling\n--C--\n\n"
        "--A--\n"
    )
    assert _raw_headers(mail.message) == headers
    assert _tree_shape(mail) == tree
    assert _tree_shape(mailparser.parse_from_string(text)) == tree
    # The defect names the part with the empty boundary, not its sibling.
    assert mail.defects == [_empty_boundary_defect(1)]
    assert [entry["defects"] for entry in mail.mime_tree] == [
        [],
        ["MimeHeaderDefect"],
        [],
        [],
        [],
    ]


def test_empty_boundary_never_matched_is_a_defect_of_the_part():
    """
    The empty boundary is a defect of the header, whether or not a
    delimiter is found: here the body has none, and the defects of the
    email package are kept beside it.
    """
    mail = mailparser.parse_from_string(
        'From: a@b.example\r\nContent-Type: multipart/mixed; boundary=""\r\n'
        "\r\n"
        "no delimiter\r\n"
    )

    assert mail.has_defects is True
    assert mail.defects_categories == {
        "MimeHeaderDefect",
        "MultipartInvariantViolationDefect",
        "StartBoundaryNotFoundDefect",
    }
    assert _empty_boundary_defect(0) in mail.defects
    assert mail.body == "no delimiter\r\n"


@pytest.mark.parametrize(
    "content_type",
    [
        # A boundary means nothing outside a multipart.
        'text/plain; boundary=""',
        # RFC 2046 section 5.1.1 allows one character.
        'multipart/mixed; boundary="x"',
    ],
)
def test_no_empty_boundary_defect_without_an_empty_multipart_boundary(
    content_type,
):
    """Neighbouring forms that are not an empty multipart boundary."""
    mail = mailparser.parse_from_string(
        f"From: a@b.example\r\nContent-Type: {content_type}\r\n\r\n"
        "--x\r\nContent-Type: text/plain\r\n\r\ninside\r\n--x--\r\n"
    )

    assert "MimeHeaderDefect" not in mail.defects_categories
    assert mail.has_defects is False


@pytest.mark.parametrize(
    ("refusing", "content_type", "expected", "defects"),
    [
        pytest.param(
            _REFUSED_PART,
            "multipart/report",
            # Both generators refuse the part: the container is written
            # by hand, the multipart before it by the generator.
            'From: a@b.example\nContent-Type: multipart/mixed; boundary="A"\n'
            "\n"
            'Content-Type: multipart/mixed; boundary=""\n\n'
            "--\nContent-Type: text/plain\n\ninside\n----\n"
            'Content-Type: multipart/report; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe refused\r\n",
            [
                {"multipart/report": [_NO_BOUNDARY]},
                _empty_boundary_defect(1),
                {"multipart/report": [_charset_defect(3)]},
            ],
            id="written-by-hand",
        ),
        pytest.param(
            _REFUSED_TEXT,
            "text/plain",
            # as_bytes() writes the whole message.
            'From: a@b.example\nContent-Type: multipart/mixed; boundary="A"\n'
            "\n"
            '--A\nContent-Type: multipart/mixed; boundary=""\n\n'
            "--\nContent-Type: text/plain\n\ninside\n----\n\n"
            '--A\nContent-Type: text/plain; charset="undefined"\n'
            "Content-Transfer-Encoding: 8bit\n\n\udcff\udcfe text\n--A--\n",
            [_empty_boundary_defect(1), {"text/plain": [_charset_defect(3)]}],
            id="written-as-bytes",
        ),
    ],
)
def test_message_as_string_keeps_an_empty_boundary_beside_a_refusing_part(
    refusing, content_type, expected, defects
):
    """
    The pass a refusing part ends has already written the multipart
    before it, and with it the boundary the generator invented.  The
    passes of the fallback go through that multipart again.
    """
    mail = _from_octets(
        "From: a@b.example\r\n" + _multipart("A", _empty_boundary(), refusing)
    )
    assert mail.message is not None
    headers = _raw_headers(mail.message)
    assert mail.defects == defects

    text = mail.message_as_string

    assert text == expected
    assert mail.message_as_string == text
    assert _raw_headers(mail.message) == headers
    assert _tree_shape(mail) == [
        ("multipart/mixed", None, "A"),
        ("multipart/mixed", 0, ""),
        ("text/plain", 1, None),
        (content_type, 0, None),
    ]
    assert mail.defects == defects
    assert not mail.message.get_payload(0).get_boundary()


def test_empty_boundary_is_false_again_after_a_too_deep_message():
    """
    The generator is given an empty boundary that is true only while a
    pass runs, also when the pass ends in a ``RecursionError``.
    """
    deep = _nested_multipart(sys.getrecursionlimit() // 3).partition("\r\n")[2]
    mail = mailparser.parse_from_string(
        "From: a@b.example\r\n"
        'Content-Type: multipart/mixed; boundary=""\r\n\r\n'
        "--\r\n" + deep + "----\r\n"
    )
    assert mail.message is not None
    headers = _raw_headers(mail.message)

    with pytest.raises(MailParserRecursionError):
        mail.message_as_string

    boundary = mail.message.get_boundary()
    assert type(boundary) is str
    assert not boundary
    assert _raw_headers(mail.message) == headers


def test_message_as_string_gives_a_caller_built_multipart_a_boundary():
    """
    A multipart the caller builds without a boundary, as a plain
    ``MIMEMultipart()`` is, has no delimiter to keep: the generator
    must invent one to write it, and stores it in the message of the
    caller.  The next read uses that boundary.
    """
    message = Message()
    message["Content-Type"] = "multipart/mixed"
    part = Message()
    part.set_payload("inside")
    message.attach(part)
    mail = mailparser.MailParser(message)
    assert message.get_boundary() is None

    text = mail.message_as_string

    boundary = message.get_boundary()
    assert boundary
    assert text == (
        f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n'
        f"--{boundary}\n\ninside\n--{boundary}--\n"
    )
    assert mail.message_as_string == text


def _text_message_returning(undecoded_payload):
    """
    A text/plain iso-8859-1 message whose ``get_payload(decode=False)`` returns
    a fixed value.

    ``email.message.Message`` re-decodes non-ASCII payloads on read, so it
    cannot present the surrogate-escaped str (or raw bytes) form that the
    from_bytes parse path produces. This subclass reproduces exactly that form
    to exercise core.py's payload-recovery branch.
    """
    import email.message

    class _Message(email.message.Message):
        def get_payload(self, i=None, decode=False):  # type: ignore[override]
            if not decode:
                return undecoded_payload
            return super().get_payload(i, decode)

    msg = _Message()
    msg["Content-Type"] = "text/plain; charset=iso-8859-1"
    msg["Content-Transfer-Encoding"] = "8bit"
    msg.set_payload(b"caf\xe9")  # backs the decode=True path
    return msg


def test_body_surrogate_str_payload_decoded_with_charset():
    """
    A text body whose undecoded payload is a surrogate-escaped str (the
    from_bytes case) is recovered to its original bytes and decoded with the
    declared charset.

    Encoding such a payload to UTF-8 raises UnicodeEncodeError; the parser must
    fall back to ascii+surrogateescape then the part charset (core.py
    surrogate-recovery branch).
    """
    m = mailparser.MailParser(_text_message_returning("caf\udce9"))
    assert m.text_plain == ["café"]


def test_body_bytes_payload_decoded_with_charset():
    """
    A text body whose undecoded payload is raw bytes (non-str) is decoded with
    the declared charset (core.py non-str payload branch).
    """
    m = mailparser.MailParser(_text_message_returning(b"caf\xe9"))
    assert m.text_plain == ["café"]


# --------------------------------------------------------------------- #
# Regression tests for the header-name attack surface.
#
# Every header name in a message is chosen by the sender, and MailParser
# exposes headers as attributes.  Resolving a name off the wire through
# getattr() therefore let the sender pick which Python attribute was read.
# These tests pin the four resulting defects shut.
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("count", [2000, 8000])
@pytest.mark.parametrize(
    "distinct", [True, False], ids=["distinct", "repeated"]
)
def test_distinct_header_names_scale_linearly(count, distinct, monkeypatch):
    """Bound full header-list rescans on both independent growth axes."""
    budget = WorkBudget(8 * (count + 1))
    original = Message.get_all

    def counted_get_all(message, *args, **kwargs):
        budget.spend(len(message._headers))
        return original(message, *args, **kwargs)

    monkeypatch.setattr(Message, "get_all", counted_get_all)
    headers = "".join(
        f"X{i if distinct else 0:05d}: v\r\n" for i in range(count)
    )
    mail = mailparser.parse_from_string(
        f"From: a@b.c\r\n{headers}\r\nbody\r\n"
    )
    parsed_headers = mail.headers
    assert len(parsed_headers) == (count + 1 if distinct else 2)
    if distinct:
        assert all(parsed_headers[f"X{i:05d}"] == "v" for i in range(count))
    else:
        assert parsed_headers["X00000"] == ["v"] * count


def test_header_named_after_a_method_does_not_break_mail_json():
    """
    A header named after a MailParser method must not put that method into
    the parsed mail.  Python resolves real attributes before __getattr__, so
    "Parse: x" used to store a bound method and mail_json raised
    "TypeError: Object of type method is not JSON serializable" — a crash
    DoS from a 12-byte message (CWE-407).
    """
    colliding = [
        name for name in dir(mailparser.MailParser) if not name.startswith("_")
    ]
    assert "parse" in colliding, "sanity: the sweep must cover real methods"

    for name in colliding:
        mail = mailparser.parse_from_string(f"{name}: x\r\n\r\n")
        # must not raise
        json.loads(mail.mail_json)
        json.loads(mail.mail_partial_json)


def test_header_named_parse_is_reported_as_a_header():
    """The colliding name resolves to the header value, not to the method."""
    mail = mailparser.parse_from_string("Parse: x\r\n\r\n")
    assert mail.mail["parse"] == "x"


def test_header_named_headers_json_does_not_recurse(monkeypatch):
    """
    "Headers_json: x" used to drive unbounded recursion: the headers property
    resolved the name through getattr, reaching the headers_json property,
    which re-serialized headers again.  Each cycle rebuilt the whole header
    dict, so the cost compounded with the per-name rescan — a 32 KB message
    burned ~48 s of CPU before the recursion guard aborted the parse.

    Excluding the name from the key set is not the fix and is not tested for:
    that is what the earlier "headers" exclusion did, and "headers_json"
    walked straight past it.
    """
    filler = "".join(f"Z{i:04d}: v\r\n" for i in range(3200))
    raw = f"Headers_json: x\r\n{filler}\r\nbody\r\n"

    def unexpected_serialization(self):
        pytest.fail("wire header invoked the headers_json property")

    monkeypatch.setattr(
        mailparser.MailParser,
        "headers_json",
        property(unexpected_serialization),
    )
    mail = mailparser.parse_from_string(raw)
    assert mail.headers["Headers_json"] == "x"
    assert json.loads(mail.mail_json)["headers_json"] == "x"


def test_header_named_headers_json_variants_do_not_recurse():
    """The alias and its double-suffixed form must be inert too."""
    for name in ("headers", "Headers", "Headers_json", "Headers_json_json"):
        mail = mailparser.parse_from_string(f"{name}: x\r\n\r\nbody\r\n")
        json.loads(mail.headers_json)


def test_reserved_defect_keys_are_not_shadowed_by_headers():
    """
    A header named after a defect output key must not replace the parsed
    value with a string from the wire.
    """
    raw = (
        "Defects: x\r\nDefects_categories: y\r\nHas_defects: z\r\n\r\nbody\r\n"
    )
    mail = mailparser.parse_from_string(raw)
    assert mail.mail["has_defects"] is False
    assert "defects" not in mail.mail


# --------------------------------------------------------------------- #
# Regression tests for sender-IP attribution.
# --------------------------------------------------------------------- #

_TRUST = "mx.victim.com"

# Genuine top hop written by the trusted MTA.  The hostname comes from the
# sender's HELO, so the sender controls it without controlling any DNS.
_GENUINE = (
    "Received: from {host} ({host} [{ip}])\r\n"
    "\tby mx.victim.com (Postfix) with ESMTP id ABC\r\n"
    "\tfor <v@victim.com>; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
)

# Older hop, entirely attacker-authored, that also carries the trust string.
_FORGED = (
    "Received: from fake.example (fake.example [6.6.6.6])\r\n"
    "\tby mx.victim.com (Postfix) with ESMTP id XYZ;"
    " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
)


def _sender_ip(*headers):
    raw = "".join(headers) + "From: a@b.c\r\n\r\nbody\r\n"
    return mailparser.parse_from_string(raw).get_server_ipaddress(_TRUST)


def test_sender_ip_not_spoofable_by_hostname_containing_by():
    """
    A HELO hostname containing "by" must not defeat sender attribution.

    get_server_ipaddress located the "by" clause with a substring search, so
    "derby.attacker.com" truncated the from clause at the "by" inside the
    hostname.  Extraction then failed on the genuine hop and the loop fell
    through to the older forged header — returning the attacker's chosen IP
    rather than nothing (CWE-345).
    """
    genuine = _GENUINE.format(host="derby.attacker.com", ip="1.2.3.4")
    assert _sender_ip(genuine, _FORGED) == "1.2.3.4"


def test_sender_ip_control_matrix():
    """
    Both conditions were needed, and the same flaw misattributes honest
    senders — so this is a correctness bug as well as an attack primitive.
    """
    benign = _GENUINE.format(host="real.attacker.com", ip="1.2.3.4")
    evil = _GENUINE.format(host="derby.attacker.com", ip="1.2.3.4")

    # forged header alone is not reached
    assert _sender_ip(benign, _FORGED) == "1.2.3.4"
    # malicious hostname alone must still resolve correctly
    assert _sender_ip(evil) == "1.2.3.4"
    # an ordinary hostname that merely contains "by" used to return None
    assert _sender_ip(
        _GENUINE.format(host="nearby.example.org", ip="9.9.9.9")
    ) == ("9.9.9.9")


def test_sender_ip_ignores_the_receiving_server():
    """
    The IP of the "by" server must never be returned as the sender's: only
    the from clause is searched.
    """
    received = (
        "Received: from helo.example (helo.example)\r\n"
        "\tby mx.victim.com (Postfix [8.8.8.8]) with ESMTP id ABC;"
        " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(received) is None


def test_get_from_clause_is_anchored():
    """get_from_clause splits on RFC 5321 keywords, not on substrings."""
    assert (
        get_from_clause(
            "from derby.example.com (derby.example.com [1.2.3.4]) by mx"
        )
        == "derby.example.com (derby.example.com [1.2.3.4])"
    )
    # no from clause: attribution fails closed rather than widening the
    # search to the by / for / with / id clauses
    assert get_from_clause("by mx.victim.com\r\n\twith ESMTP") == ""


def test_json_suffixed_header_name_does_not_amplify(monkeypatch):
    """
    A header named ``X_json_json_...`` must not build a tower of JSON.

    Applying the caller-facing ``_json`` suffix to a wire name made each
    level re-serialize the previous one, and json.dumps escapes every quote
    and backslash: the value doubled per five input bytes.  A 148-byte
    header produced a 536 MB string, and 40 such headers reached tens of GB
    — an out-of-memory kill of the worker (CWE-405).
    """
    name = "X" + "_json" * 40
    raw = "".join(f"{name}{i}: x\r\n" for i in range(40)) + "\r\nbody\r\n"

    original = mailparser.MailParser.__getattr__

    def checked_getattr(self, attribute):
        assert not attribute.lower().startswith("x_json"), (
            "wire header entered recursive attribute dispatch"
        )
        return original(self, attribute)

    monkeypatch.setattr(mailparser.MailParser, "__getattr__", checked_getattr)
    parsed = mailparser.parse_from_string(raw)
    assert parsed.headers == {f"{name}{i}": "x" for i in range(40)}
    assert len(parsed.headers_json) < 2 * len(raw)

    mail = mailparser.parse_from_string(f"{name}: x\r\n\r\n")
    # the wire value, not a JSON tower built out of it
    assert mail.mail[name.lower()] == "x"


def test_wire_header_names_are_not_rewritten():
    """
    A header name is reported and looked up literally.

    Folding ``_`` to ``-`` and honouring the ``_json`` / ``_raw`` suffixes
    on a sender-chosen name silently replaced one header's value with
    another's and dropped the original — indicators vanished from every
    output surface with no defect recorded (CWE-436).
    """
    raw = (
        "From: Real Sender <real@good.example>\r\n"
        "Subject: innocuous\r\n"
        "Subject_json: MALWARE-C2 http://evil.example/payload.exe\r\n"
        "X_Spam_Flag: YES\r\n"
        "\r\nbody\r\n"
    )
    mail = mailparser.parse_from_string(raw)

    assert mail.mail["subject"] == "innocuous"
    assert (
        mail.mail["subject_json"]
        == "MALWARE-C2 http://evil.example/payload.exe"
    )
    assert mail.headers["X_Spam_Flag"] == "YES"
    assert "MALWARE-C2" in mail.mail_json
    assert "MALWARE-C2" in mail.headers_json


def test_raw_suffix_survives_eight_bit_headers():
    """
    ``X_raw`` must not crash on a header carrying 8-bit bytes.

    compat32 hands back an ``email.header.Header`` rather than a str for
    those, and json.dumps raised "Object of type Header is not JSON
    serializable" — an exception outside the MailParser hierarchy, so
    _parse_guarded did not catch it and the worker died (CWE-248).
    """
    mail = mailparser.parse_from_bytes(b"Subject: caf\xe9\r\n\r\nbody\r\n")
    subject_raw = mail.subject_raw
    assert isinstance(subject_raw, str)
    # the undecodable byte survives as U+FFFD rather than killing the parse
    assert json.loads(subject_raw) == ["caf�"]

    # the same value reached through a crafted wire name must not crash
    crafted = mailparser.parse_from_bytes(
        b"Subject: caf\xe9\r\nSubject_raw: x\r\n\r\nbody\r\n"
    )
    assert crafted.mail["subject_raw"] == "x"
    json.loads(crafted.mail_json)


def test_private_attributes_raise_instead_of_resolving_as_headers():
    """
    An unset internal attribute must fail loudly.

    __getattr__ answered any missing name as an absent header, so a bug
    inside a property surfaced as "" instead of an error.
    """
    mail = mailparser.parse_from_string("Subject: x\r\n\r\nbody\r\n")
    with pytest.raises(AttributeError):
        mail._not_a_real_attribute
    # the documented trailing-underscore form still works
    assert mail.from_ == []


def test_message_without_headers_is_parsed():
    """
    A body-only message must still parse.

    ``Message.__len__`` is the header count, so a message with no headers
    is falsy: ``if not self.message`` returned before _reset(), leaving
    _mail and _text_plain unset, and __getattr__ then answered them as
    absent headers.  Every property returned "" — a pipeline grepping the
    body for indicators saw nothing and no error (CWE-754).
    """
    mail = mailparser.parse_from_string(
        "Click http://evil.example/pay.exe now\r\n"
    )
    assert "evil.example" in mail.body
    assert isinstance(mail.mail, dict)
    assert isinstance(mail.attachments, list)
    assert mail.has_defects is True


def test_sender_ip_ignores_the_helo_name():
    """
    The HELO/EHLO name is sender-supplied and may be an address literal,
    so it must be stripped before scanning the from clause — the last IP
    in the clause wins, and both Exim and CommuniGate record the HELO
    after the genuine IP.
    """
    exim = (
        "Received: from evil.example ([93.184.216.34]:45321 "
        "helo=[8.8.8.8])\r\n"
        "\tby mx.victim.com with esmtps id ABC;"
        " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    communigate = (
        "Received: from [93.184.216.34] (account bounce@tin.it HELO "
        "8.8.8.8)\r\n"
        "\tby mx.victim.com (CommuniGate) with ESMTP id ABC;"
        " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(exim) == "93.184.216.34"
    assert _sender_ip(communigate) == "93.184.216.34"


def test_sender_ip_fails_closed_on_the_trusted_hop():
    """
    When the trusted hop yields no public sender IP the answer is None.

    Continuing to older Received headers hands the result to whoever wrote
    them — the sender — so any future trick that defeats extraction on the
    genuine hop would again return an attacker-chosen IP instead of
    nothing (CWE-345).
    """
    # a trusted hop with no from clause at all names nothing readable, and
    # its envelope recipient is chosen by the sender at RCPT TO
    no_from = (
        "Received: by mx.victim.com (Postfix) id 9F2\r\n"
        "\tfor <bounce+6.6.6.6@x>; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(no_from) is None


def test_headers_dedupes_case_variants_of_one_name():
    """
    Repeating one header name in many casings must not blow up ``headers``.

    Header names compare case-insensitively, so every casing resolves to the
    same full value list.  Deduping on the exact spelling emitted one list
    per casing — an n x n blowup on a name the sender chooses (CWE-407):
    271 KB of headers cost 7.6 s and produced 540 MB of JSON.
    """
    name = "x-aaaaaaaaaaaaaaaaaaa"
    variants = (
        "".join(c.upper() if (i >> j) & 1 else c for j, c in enumerate(name))
        for i in range(8000)
    )
    raw = "".join(f"{v}: value\r\n" for v in variants) + "\r\nbody\r\n"

    mail = mailparser.parse_from_string(raw)
    headers = mail.headers

    assert len(headers) == 1
    assert next(iter(headers.values())) == ["value"] * 8000
    assert len(mail.headers_json) < len(raw)

    # honest duplicates keep every value under one key
    assert mailparser.parse_from_string(
        "Subject: a\r\nSUBJECT: b\r\n\r\n"
    ).headers == {"Subject": ["a", "b"]}


def test_multi_token_helo_never_steers_the_result():
    """
    A HELO of several words lets the sender write an RFC 5321 clause keyword
    into the trusted MTA's own Received header, truncating the from clause.

    The answer must never be the sender's chosen address.  Extending the
    clause to a later ``by`` to survive this is worse than the truncation:
    it pulls in the ``for`` and ``envelope-from`` values, which the sender
    also picks — so truncation is left to fail closed (CWE-345).
    """
    assert (
        _sender_ip(_GENUINE.format(host="evil.example", ip="1.2.3.4"))
        == "1.2.3.4"
    )

    for helo in (
        "evil 6.6.6.6 by z",
        "evil 6.6.6.6 with z",
        "evil 6.6.6.6 for z",
        "a by b by c 6.6.6.6 by d",
    ):
        assert (
            _sender_ip(_GENUINE.format(host=helo, ip="1.2.3.4"), _FORGED)
            is None
        ), f"HELO {helo!r} steered the result"


def test_sender_ip_ignores_addresses_the_sender_wrote():
    """
    Only an address the receiving MTA wrote — inside a bracket or paren
    group — can be the sender's.  The ``for`` and ``envelope-from`` values
    are chosen by the sender at RCPT TO / MAIL FROM, and a quoted local part
    supplies the whitespace needed to look like a clause (CWE-345).
    """
    exim = (
        "Received: from [45.33.32.156] (helo=evil.example)\r\n"
        "\tby mx.victim.com with esmtp (Exim 4.94)\r\n"
        '\t(envelope-from <"x 6.6.6.6 by q"@evil.example>)\r\n'
        "\tid 1abc for v@victim.com; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(exim, _FORGED) == "45.33.32.156"

    # the same trick aimed at the receiving server's own address
    receiving = (
        "Received: from helo.example (helo.example [45.33.32.156])\r\n"
        "\tby mx.victim.com (Postfix [6.6.6.6]) with ESMTP id ABC\r\n"
        '\tfor <"v by q"@victim.com>; Mon, 1 Jan 2024 00:00:00 +0000\r\n'
    )
    assert _sender_ip(receiving) == "45.33.32.156"


def test_ipv4_helo_literal_does_not_hide_an_ipv6_sender():
    """
    An address literal announced at EHLO is one bare token, never inside a
    group, so it is not a candidate.  Scanning IPv4 first and stopping on
    any hit meant ``EHLO 10.0.0.1`` on an IPv6 connection produced a single
    private candidate: attribution then resumed the walk into the sender's
    own forged headers.
    """
    genuine = (
        "Received: from 10.0.0.1 (evil.example "
        "[IPv6:2a00:1450:4864:20::32])\r\n"
        "\tby mx.victim.com (Postfix) with ESMTPS id ABC"
        " for <v@victim.com>; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(genuine, _FORGED) == "2a00:1450:4864:20::32"


def test_sender_ip_reads_real_world_clause_layouts():
    """The MTA layouts the candidate filter has to keep working on."""
    cases = {
        # sendmail, unverified rDNS
        "from 8.8.8.8 (helo [45.33.32.156] (may be forged))": "45.33.32.156",
        # a sender whose HELO name is literally the word "helo"
        "from helo ([45.33.32.156])": "45.33.32.156",
        # Exim / CommuniGate: the MTA writes the address as the first token
        # because it recorded the HELO name in the comment instead
        "from [45.33.32.156] (helo=evil.example)": "45.33.32.156",
        "from [45.33.32.156] (account a@b HELO evil.example)": "45.33.32.156",
        "from evil ([45.33.32.156]:45321 helo=[8.8.8.8])": "45.33.32.156",
        # a bare address with no HELO marker anywhere is indistinguishable
        # from "EHLO 139.88.66.159", so it fails closed
        "from 139.88.66.159": None,
    }
    for clause, expected in cases.items():
        received = (
            f"Received: {clause}\r\n"
            "\tby mx.victim.com (Postfix) id ABC;"
            " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
        )
        assert _sender_ip(received) == expected, clause


def test_sender_ip_ignores_an_address_literal_announced_at_ehlo():
    """
    ``EHLO [8.8.8.8]`` is the form RFC 5321 §4.1.3 requires of a client with
    no FQDN, so the first token of a from clause may be a bracketed address
    the sender chose.  It is never a candidate: a closed bracket pair the
    sender wrote is byte-identical to one the MTA wrote, so the rule is
    positional — the first token is the HELO name, whatever it looks like.
    """
    v6 = "2a00:1450:4864:20::32"
    for helo in ("[8.8.8.8]", "[10.0.0.1]", "[203.0.113.77]"):
        genuine = (
            f"Received: from {helo} (evil.example [IPv6:{v6}])\r\n"
            "\tby mx.victim.com (Postfix) with ESMTPS id ABC;"
            " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
        )
        assert _sender_ip(genuine, _FORGED) == v6, helo

    # with nothing else in the clause the answer is None, never the literal
    alone = (
        "Received: from [8.8.8.8] (unknown)\r\n"
        "\tby mx.victim.com (Postfix) id ABC; Mon, 1 Jan 2024 00:00:00 "
        "+0000\r\n"
    )
    assert _sender_ip(alone, _FORGED) is None


def test_sender_ip_rejects_a_helo_marker_the_sender_injected():
    """
    The HELO-marker concession applies only to a marker inside a comment
    group, where the MTA puts it.  A marker the sender types into their own
    HELO name sits at the top level and must not promote their address.
    """
    injected = (
        "Received: from 8.8.8.8 helo=x\r\n"
        "\tby mx.victim.com (Postfix) id ABC; Mon, 1 Jan 2024 00:00:00 "
        "+0000\r\n"
    )
    assert _sender_ip(injected, _FORGED) is None


def test_regxip6_matches_the_whole_address():
    """
    Python's ``re`` takes the first matching alternative, not the longest,
    so the compressed branches are ordered by descending trailing-group
    count.  A truncated address still parses and is still public, so it
    would be reported silently — a different host attributed and blocked.
    """
    for address in (
        "2a00:1450:4864:20::32",
        "2001:470:1f0b:16c0::2:1",
        "2a02:26f0:12d::1:2",
        "2600:1f18:63bf::a:b:c",
        "fe80::1234:5678",
        "2001:4860:4860::8888",
    ):
        match = REGXIP6.search(address)
        assert match is not None and match.group() == address, address


def test_helo_strip_keeps_a_sender_whose_helo_is_the_word_helo():
    """
    The HELO *argument* never sits at offset 0 of the from clause — that
    position holds the HELO *name*.  Without the lookbehind, a sender
    announcing ``EHLO helo`` matched there and the pattern ate the
    MTA-written IP, suppressing attribution entirely.
    """
    for helo in ("vps.ovh.net", "helo", "HELO", "ehelo"):
        received = (
            f"Received: from {helo} ([45.33.32.156])\r\n"
            "\tby mx.victim.com (sendmail) with ESMTP id ABC;"
            " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
        )
        assert _sender_ip(received) == "45.33.32.156", (
            f"HELO {helo!r} lost the IP"
        )


def test_sender_ip_walks_past_a_private_internal_relay():
    """
    A trusted hop naming a private IP is an internal relay, so the documented
    walk continues down the chain.  Only a hop naming *no* IP ends the
    search — that is the case where falling through would hand the answer to
    whoever wrote the older headers.
    """
    internal = (
        "Received: from relay.internal (relay.internal [10.0.0.5])\r\n"
        "\tby mx.victim.com (Postfix) id A; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    public = (
        "Received: from real.sender (real.sender [45.33.32.156])\r\n"
        "\tby mx.victim.com (Postfix) id B; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    assert _sender_ip(internal, public) == "45.33.32.156"


def test_group_spans_tracks_nesting_and_unclosed_groups():
    """
    Group membership decides which addresses the MTA wrote, so an unclosed
    delimiter must not silently drop the rest of the clause: a sender who
    opens a bracket would otherwise hide every later address from the scan.
    """
    # nesting collapses to the outermost group
    assert group_spans("a (b [c] d) e") == [(3, 10)]
    # an unclosed group runs to the end of the string
    assert group_spans("a (b [c") == [(3, 7)]
    assert group_spans("no groups here") == []
    # a stray closer is not a group
    assert group_spans("a) b") == []

    spans = group_spans("x (y)")
    assert in_spans(3, spans) is True
    assert in_spans(0, spans) is False


def test_raw_suffix_folds_underscores_to_dashes():
    """
    ``X_raw`` resolves the same header name as ``X``.

    The ``_raw`` branch used to look the name up with its underscores
    intact while every other branch folded them to dashes, so
    ``mail.x_mailer_raw`` reported "null" for a header ``mail.x_mailer``
    returned fine.
    """
    mail = mailparser.parse_from_string(
        "X-Mailer: Foo 1.0\r\nX-MSMail-Priority: High\r\nSubject: s\r\n\r\n"
        "body\r\n"
    )

    def raw(name):
        """Read a ``_raw`` attribute, which is always a JSON string."""
        value = getattr(mail, name)
        assert isinstance(value, str), name
        return json.loads(value)

    assert raw("x_mailer_raw") == ["Foo 1.0"]
    assert raw("X_MSMail_Priority_raw") == ["High"]
    # absent headers give an empty list, never "null"
    assert raw("x_nonexistent_raw") == []


@pytest.fixture
def extract_msg_lib():
    """Skip the test when the optional ``extract-msg`` is missing."""
    return pytest.importorskip("extract_msg")


def _outlook_temp_files():
    pattern = os.path.join(tempfile.gettempdir(), "outlook_*")
    return set(glob.glob(pattern))


def test_from_file_msg_valid_still_parses(extract_msg_lib):
    mail = mailparser.parse_from_file_msg(mail_outlook_1)
    assert mail.subject


def test_from_file_msg_garbage_raises_outlook_error(extract_msg_lib, tmp_path):
    path = tmp_path / "garbage.msg"
    path.write_bytes(b"not an OLE file\n" * 10)
    before = _outlook_temp_files()

    with pytest.raises(MailParserOutlookError) as exc:
        mailparser.parse_from_file_msg(str(path))

    assert isinstance(
        exc.value.__cause__, extract_msg_lib.exceptions.InvalidFileFormatError
    )
    assert _outlook_temp_files() == before


@pytest.mark.parametrize("divisor", [3, 2])
def test_from_file_msg_truncated_raises_outlook_error(
    extract_msg_lib, tmp_path, divisor
):
    with open(mail_outlook_1, "rb") as f:
        data = f.read()
    path = tmp_path / "truncated.msg"
    path.write_bytes(data[: len(data) // divisor])

    with pytest.raises(MailParserOutlookError) as exc:
        mailparser.parse_from_file_msg(str(path))

    assert isinstance(exc.value.__cause__, OSError)
    assert not isinstance(exc.value.__cause__, FileNotFoundError)


def test_from_file_msg_missing_file_stays_file_not_found(
    extract_msg_lib, tmp_path
):
    with pytest.raises(FileNotFoundError):
        mailparser.parse_from_file_msg(str(tmp_path / "missing.msg"))


@pytest.mark.parametrize(
    ("build", "error"),
    [
        pytest.param(lambda d: d, IsADirectoryError, id="a directory"),
        pytest.param(
            lambda d: d / "file" / "x.msg",
            NotADirectoryError,
            id="a path through a file",
        ),
    ],
)
def test_from_file_msg_path_error_is_not_a_malformed_file(
    extract_msg_lib, tmp_path, build, error
):
    """
    Regression: only three ``OSError`` classes were let through, so a
    path the caller got wrong was reported as a malformed ``.msg``.
    """
    (tmp_path / "file").write_bytes(b"x")

    with pytest.raises(error):
        mailparser.parse_from_file_msg(str(build(tmp_path)))


def test_from_file_msg_error_does_not_carry_the_stream(
    extract_msg_lib, mocker
):
    """
    Regression: the message held ``repr()`` of the library error, and
    that of a ``UnicodeDecodeError`` holds the whole stream that could
    not be decoded, four characters for each octet of the sender.
    """
    stream = b"\xff" * 1_000_001
    error = UnicodeDecodeError("utf-16-le", stream, 0, 1, "truncated data")
    mocker.patch.object(extract_msg_lib, "openMsg", side_effect=error)

    with pytest.raises(MailParserOutlookError) as exc:
        mailparser.parse_from_file_msg(mail_outlook_1)

    assert exc.value.__cause__ is error
    assert "UnicodeDecodeError" in str(exc.value)
    assert len(str(exc.value)) < 1024


def test_from_file_msg_too_deep_raises_recursion_error(
    extract_msg_lib, mocker
):
    """A ``.msg`` too deep to convert is not reported as malformed."""
    mocker.patch.object(
        extract_msg_lib, "openMsg", side_effect=RecursionError("deep")
    )

    with pytest.raises(MailParserRecursionError) as exc:
        mailparser.parse_from_file_msg(mail_outlook_1)

    assert isinstance(exc.value.__cause__, RecursionError)


def test_from_file_msg_memory_error_stays_what_it_is(extract_msg_lib, mocker):
    mocker.patch.object(extract_msg_lib, "openMsg", side_effect=MemoryError())

    with pytest.raises(MemoryError):
        mailparser.parse_from_file_msg(mail_outlook_1)


def test_from_file_msg_non_email_stays_os_error(extract_msg_lib, mocker):
    contact = mocker.Mock(spec=["close"])
    mocker.patch.object(extract_msg_lib, "openMsg", return_value=contact)

    with pytest.raises(MailParserOSError) as exc:
        mailparser.parse_from_file_msg(mail_outlook_1)

    assert not isinstance(exc.value, MailParserOutlookError)
    contact.close.assert_called_once_with()


def test_from_file_msg_serialization_failure_leaves_no_temp_file(
    extract_msg_lib, mocker
):
    eml = mocker.Mock()
    eml.get.return_value = ""
    eml.as_bytes.side_effect = ValueError("boom")
    msg = mocker.Mock()
    msg.asEmailMessage.return_value = eml
    mocker.patch.object(extract_msg_lib, "openMsg", return_value=msg)
    before = _outlook_temp_files()

    with pytest.raises(MailParserOutlookError) as exc:
        mailparser.parse_from_file_msg(mail_outlook_1)

    assert isinstance(exc.value.__cause__, ValueError)
    assert _outlook_temp_files() == before
    msg.close.assert_called_once_with()
