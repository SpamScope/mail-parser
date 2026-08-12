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

import datetime
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import pytest

import mailparser
from mailparser.const import REGXIP6
from mailparser.exceptions import MailParserOSError, MailParserRecursionError
from mailparser.utils import (
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
                [attachment["safe_filename"] for attachment in mail.attachments],
                ["marker.txt", "marker.txt", "content-id.txt"],
            )

            mail.write_attachments(output_dir)

            self.assertEqual(
                sorted(os.listdir(output_dir)),
                ["content-id.txt", "marker.txt", "marker_1.txt"],
            )
            with open(os.path.join(output_dir, "marker.txt"), "rb") as attachment:
                self.assertEqual(attachment.read(), b"first")
            with open(os.path.join(output_dir, "marker_1.txt"), "rb") as attachment:
                self.assertEqual(attachment.read(), b"second")
            with open(os.path.join(output_dir, "content-id.txt"), "rb") as attachment:
                self.assertEqual(attachment.read(), b"third")

            self.assertFalse(os.path.exists(os.path.join(temp_dir, "marker.txt")))
            self.assertFalse(os.path.exists(os.path.join(temp_dir, "content-id.txt")))

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
            ("cd4af1017f2e623f6d38f691048b6a28d8b1f44a0478137b4337eac6de78f71a"),
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

        self.assertFalse(mail.has_defects)

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
        self.assertFalse(result)

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

        self.assertFalse(mail.has_defects)

        result = mail.mail
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
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
        self.assertEqual(1, len(mail.defects))
        self.assertEqual(1, len(mail.defects_categories))
        self.assertIn("defects", mail.mail)
        self.assertIn("CloseBoundaryNotFoundDefect", mail.defects_categories)

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
        # A quoted-printable application/* attachment must be kept as binary
        # (raw QP text), not decoded as UTF-8, which drops the non-UTF8 bytes.
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
        attachment = mailparser.parse_from_string(raw).attachments[0]
        self.assertTrue(attachment["binary"])
        self.assertEqual(attachment["content_transfer_encoding"], "quoted-printable")
        self.assertEqual(
            quopri.decodestring(attachment["payload"].encode("ascii")), original
        )

    def test_add_content_type(self):
        mail = mailparser.parse_from_file(mail_test_3)

        self.assertFalse(mail.has_defects)

        result = mail.mail

        self.assertEqual(len(result["attachments"]), 1)
        self.assertIsInstance(result["attachments"][0]["mail_content_type"], str)
        self.assertFalse(result["attachments"][0]["binary"])
        self.assertIsInstance(result["attachments"][0]["payload"], str)
        self.assertEqual(
            result["attachments"][0]["content_transfer_encoding"], "quoted-printable"
        )
        self.assertEqual(result["attachments"][0]["charset"], "iso-8859-1")
        self.assertEqual(result["attachments"][0]["content-disposition"], "inline")

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
    def test_parse_from_file_msg(self, mock_msgconvert, mock_remove, mock_find_spec):
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

        self.assertFalse(mail.has_defects)

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
        self.assertFalse(result)

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
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".eml") as f:
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

        # Create a mail with StartBoundaryNotFoundDefect to trigger epilogue parsing
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
        """Test attachment handling with content-id but no html/plain subtype"""
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
        self.assertTrue(any(".rtf" in att.get("filename", "") for att in attachments))

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
        self.assertTrue(any(".txt" in att.get("filename", "") for att in attachments))

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

        assert mail.from_ == [("LastßlName, FirstName", "comma.name@example.com")]
        assert mail.to == [("", "tony.stark@example.com")]
        assert mail.cc == [
            ("", "simple@example.net"),
            ('John "Johnny" Doe', "john.doe@example.com"),
        ]

    def test_init_with_message_object_logs_headers(self):
        """Test core.py:126->128 — MailParser.__init__ with message is not None"""
        import email as email_module

        from mailparser.core import MailParser

        raw = "From: test@example.com\nSubject: LogTest\n\nBody"
        msg = email_module.message_from_string(raw)

        with self.assertLogs("mailparser", level="DEBUG") as cm:
            parser = MailParser(message=msg)

        # The debug log about headers must have been emitted
        self.assertTrue(any("All headers of emails" in line for line in cm.output))
        self.assertEqual(parser.subject, "LogTest")

    def test_init_with_none_message_skips_log(self):
        """Test core.py:126->128 — MailParser.__init__ message=None skips debug log"""
        from mailparser.core import MailParser

        # message=None: the if-branch is False, no log.debug call
        parser = MailParser(message=None)
        self.assertFalse(parser.message)

    def test_date_json_returns_none_when_no_date(self):
        """Test core.py:703->exit — date_json returns None when self.date is falsy"""
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
        """Test core.py:735->737 False branch — mail_partial_json without date"""
        # Mail with no Date header: condition is False, skip line 736
        raw = "From: test@example.com\nSubject: NoDate\n\nBody"
        mail = mailparser.parse_from_string(raw)
        self.assertIsNone(mail.date)
        result = mail.mail_partial_json
        self.assertIsInstance(result, str)

    def test_sender_ip_no_message(self):
        """Test core.py:502 — get_server_ipaddress returns None with no message"""
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
        parser = mailparser.parse_from_string("From: t@example.com\nSubject: x\n\nBody")
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
        """Test core.py:533->544 — _extract_ip returns None when no IP found at all"""
        mail = mailparser.parse_from_string("From: t@example.com\nSubject: x\n\nBody")
        # A received header with no IP addresses at all
        result = mail._extract_ip("from hostname by other-hostname")
        self.assertIsNone(result)

    def test_unicode_decode_error_in_payload(self):
        """Test core.py:447-448 — UnicodeDecodeError fallback when decoding payload"""
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
        """Return a minimal raw email bytes with UTF-8 body (em-dash U+2014)."""
        cte_line = f"Content-Transfer-Encoding: {cte_header}\n" if cte_header else ""
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
        """parse_from_bytes must not mojibake UTF-8 body with no CTE (issue #152)."""
        raw = self._make_utf8_raw()
        mail = mailparser.parse_from_bytes(raw)
        self.assertEqual(mail.text_plain[0], "Hello — world\n")

    def test_utf8_body_from_bytes_cte_8bit(self):
        """parse_from_bytes must not mojibake UTF-8 body with CTE: 8bit (issue #152)."""
        raw = self._make_utf8_raw("8bit")
        mail = mailparser.parse_from_bytes(raw)
        self.assertEqual(mail.text_plain[0], "Hello — world\n")

    def test_utf8_body_from_bytes_cte_7bit(self):
        """parse_from_bytes must not mojibake ASCII body with CTE: 7bit (issue #152)."""
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
        """parse_from_bytes and parse_from_string: identical text_plain (issue #152)."""
        raw_bytes = self._make_utf8_raw()
        raw_str = raw_bytes.decode("utf-8")
        mail_b = mailparser.parse_from_bytes(raw_bytes)
        mail_s = mailparser.parse_from_string(raw_str)
        self.assertEqual(mail_b.text_plain[0], mail_s.text_plain[0])

    def test_utf8_body_from_bytes_8bit_matches_from_string(self):
        """parse_from_bytes (8bit CTE) matches parse_from_string (issue #152)."""
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
        """From header with an email address as display name is parsed correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.from_
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "bob@example.com")
        self.assertEqual(name, "alice@example.com")

    def test_cc_email_as_display_name(self):
        """CC header with an email address as display name is parsed correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.cc
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "frank@example.com")
        self.assertEqual(name, "eve@example.com")

    def test_reply_to_email_as_display_name(self):
        """Reply-To header with an email address as display name is parsed correctly."""
        mail = mailparser.parse_from_file(mail_test_19)
        result = mail.reply_to
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "ivan@example.com")
        self.assertEqual(name, "henry@example.com")

    def test_to_mixed_addresses(self):
        """To header with a mix of quoted name and bare address is parsed correctly."""
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
        """Properly quoted email-as-name (RFC-compliant) is parsed by strict parser."""
        mail = mailparser.parse_from_string(
            'From: "alice@example.com" <bob@example.com>\nSubject: x\n\nBody'
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "bob@example.com")
        self.assertEqual(name, "alice@example.com")

    def test_standard_display_name_unchanged(self):
        """Standard ``Name <email>`` format still works correctly (no regression)."""
        mail = mailparser.parse_from_string(
            "From: Alice Smith <alice@example.com>\nSubject: x\n\nBody"
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "alice@example.com")
        self.assertEqual(name, "Alice Smith")

    def test_bare_address_no_display_name(self):
        """Bare address with no display name returns empty name (no regression)."""
        mail = mailparser.parse_from_string(
            "From: alice@example.com\nSubject: x\n\nBody"
        )
        result = mail.from_
        self.assertEqual(len(result), 1)
        name, addr = result[0]
        self.assertEqual(addr, "alice@example.com")
        self.assertEqual(name, "")

    def test_empty_header_returns_empty_list(self):
        """A missing address header returns [] — absent headers must not appear."""
        mail = mailparser.parse_from_string("Subject: x\n\nBody")
        # Python's getaddresses("") yields [('', '')], but we filter out entries
        # with an empty address so that absent headers are not included in the
        # parsed mail object.
        self.assertEqual(mail.from_, [])

    # ------------------------------------------------------------------
    # Unit tests for get_addresses() helper directly
    # ------------------------------------------------------------------

    def test_get_addresses_email_as_name(self):
        """get_addresses() fallback recovers address when display name is an email."""
        result = get_addresses("alice@example.com <bob@example.com>")
        self.assertEqual(result, [("alice@example.com", "bob@example.com")])

    def test_get_addresses_standard_format(self):
        """get_addresses() strict path handles normal ``Name <email>`` correctly."""
        result = get_addresses("Alice Smith <alice@example.com>")
        self.assertEqual(result, [("Alice Smith", "alice@example.com")])

    def test_get_addresses_bare_email(self):
        """get_addresses() handles bare email address with no display name."""
        result = get_addresses("alice@example.com")
        self.assertEqual(result, [("", "alice@example.com")])

    def test_get_addresses_empty_header(self):
        """get_addresses() on empty string returns [('', '')] — raw Python lib result.

        The ('', '') entry is filtered out in __getattr__ (core.py) so that
        absent headers do not appear in the parsed mail output.
        """
        result = get_addresses("")
        self.assertEqual(result, [("", "")])

    def test_get_addresses_multiple_with_email_as_name(self):
        """get_addresses() fallback handles multiple addresses when all fail strict."""
        result = get_addresses(
            "alice@example.com <bob@example.com>, eve@example.com <frank@example.com>"
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


def _timed_parse(raw):
    """Parse ``raw`` and return the elapsed wall-clock seconds."""
    start = time.perf_counter()
    mailparser.parse_from_string(raw)
    return time.perf_counter() - start


def test_distinct_header_names_scale_linearly():
    """
    Parsing cost must stay linear in the number of *distinct* header names.

    Every distinct name used to trigger its own full rescan of the header
    list (Message.get_all is O(total)), so cost grew as O(distinct x total):
    16,000 names cost ~5.8 s against ~0.06 s for 32,000 repeats of one name.
    Header names are attacker-chosen and cheap to generate (CWE-407).
    """

    def build(n):
        headers = "".join(f"X{i:05d}: v\r\n" for i in range(n))
        return f"From: a@b.c\r\n{headers}\r\nbody\r\n"

    small = min(_timed_parse(build(2000)) for _ in range(3))
    large = min(_timed_parse(build(8000)) for _ in range(3))

    # 4x the names must not cost anywhere near 16x the time.  The bound is
    # loose so the test does not flake on a loaded machine; the quadratic
    # behaviour it guards against was ~14x here.
    assert large < small * 8, f"{small=} {large=} — scaling is not linear"


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


def test_header_named_headers_json_does_not_recurse():
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

    elapsed = _timed_parse(raw)
    assert elapsed < 2, f"parse took {elapsed:.1f}s — recursion is back"


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
    raw = "Defects: x\r\nDefects_categories: y\r\nHas_defects: z\r\n\r\nbody\r\n"
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
    assert _sender_ip(_GENUINE.format(host="nearby.example.org", ip="9.9.9.9")) == (
        "9.9.9.9"
    )


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
        get_from_clause("from derby.example.com (derby.example.com [1.2.3.4]) by mx")
        == "derby.example.com (derby.example.com [1.2.3.4])"
    )
    # no from clause: attribution fails closed rather than widening the
    # search to the by / for / with / id clauses
    assert get_from_clause("by mx.victim.com\r\n\twith ESMTP") == ""


def test_json_suffixed_header_name_does_not_amplify():
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

    elapsed = _timed_parse(raw)
    assert elapsed < 2, f"parse took {elapsed:.1f}s — the suffix cycle is back"

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
    assert mail.mail["subject_json"] == "MALWARE-C2 http://evil.example/payload.exe"
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
    mail = mailparser.parse_from_string("Click http://evil.example/pay.exe now\r\n")
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
        "Received: from evil.example ([93.184.216.34]:45321 helo=[8.8.8.8])\r\n"
        "\tby mx.victim.com with esmtps id ABC;"
        " Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    )
    communigate = (
        "Received: from [93.184.216.34] (account bounce@tin.it HELO 8.8.8.8)\r\n"
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
    start = time.perf_counter()
    headers = mail.headers
    elapsed = time.perf_counter() - start

    assert len(headers) == 1
    assert elapsed < 2, f"headers took {elapsed:.1f}s — the blowup is back"

    # honest duplicates keep every value under one key
    assert mailparser.parse_from_string("Subject: a\r\nSUBJECT: b\r\n\r\n").headers == {
        "Subject": ["a", "b"]
    }


def test_multi_token_helo_never_steers_the_result():
    """
    A HELO of several words lets the sender write an RFC 5321 clause keyword
    into the trusted MTA's own Received header, truncating the from clause.

    The answer must never be the sender's chosen address.  Extending the
    clause to a later ``by`` to survive this is worse than the truncation:
    it pulls in the ``for`` and ``envelope-from`` values, which the sender
    also picks — so truncation is left to fail closed (CWE-345).
    """
    assert _sender_ip(_GENUINE.format(host="evil.example", ip="1.2.3.4")) == "1.2.3.4"

    for helo in (
        "evil 6.6.6.6 by z",
        "evil 6.6.6.6 with z",
        "evil 6.6.6.6 for z",
        "a by b by c 6.6.6.6 by d",
    ):
        assert _sender_ip(_GENUINE.format(host=helo, ip="1.2.3.4"), _FORGED) is None, (
            f"HELO {helo!r} steered the result"
        )


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
        "Received: from 10.0.0.1 (evil.example [IPv6:2a00:1450:4864:20::32])\r\n"
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
        "\tby mx.victim.com (Postfix) id ABC; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
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
        "\tby mx.victim.com (Postfix) id ABC; Mon, 1 Jan 2024 00:00:00 +0000\r\n"
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
        assert _sender_ip(received) == "45.33.32.156", f"HELO {helo!r} lost the IP"


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
        "X-Mailer: Foo 1.0\r\nX-MSMail-Priority: High\r\nSubject: s\r\n\r\nbody\r\n"
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
