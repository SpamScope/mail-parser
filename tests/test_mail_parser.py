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
import logging
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

import mailparser
from mailparser.exceptions import MailParserOSError
from mailparser.utils import (
    convert_mail_date,
    extract_msg_convert,
    fingerprints,
    get_addresses,
    get_header,
    get_mail_keys,
    get_to_domains,
    msgconvert,
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
    @patch("mailparser.core.os.remove")
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
        """Test core.py:531 — _extract_ip uses IPv6 when IPv4 not found"""
        raw_mail = (
            "Received: from sender.example.com (IPv6:2001:db8::1)\n"
            " by mail.trusted.net; Mon, 01 Jan 2024 12:00:00 +0000\n"
            "From: test@example.com\n"
            "Subject: IPv6 test\n\nBody"
        )
        mail = mailparser.parse_from_string(raw_mail)
        # 2001:db8:: is documentation range — it is not private
        result = mail.get_server_ipaddress("trusted.net")
        # Should find the IPv6 address (it is globally routable)
        self.assertIsNotNone(result)

    def test_extract_ip_invalid_ip_returns_none(self):
        """Test core.py:538-539 — _extract_ip returns None for unparsable IP string"""
        parser = mailparser.parse_from_string("From: t@example.com\nSubject: x\n\nBody")
        # Patch REGXIP to return a value that ipaddress.ip_address() cannot parse
        with patch("mailparser.core.REGXIP") as mock_regxip:
            with patch("mailparser.core.REGXIP6") as mock_regxip6:
                mock_regxip.findall.return_value = []
                mock_regxip6.findall.return_value = ["not_a_valid_ip"]
                result = parser._extract_ip("from invalid by host")
        self.assertIsNone(result)

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
    remove = mocker.patch("mailparser.core.os.remove")

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
    mocker.patch("mailparser.core.os.remove")

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
    pytest.importorskip("extract_msg")
    if shutil.which("msgconvert") is None:
        pytest.skip("msgconvert tool not installed")

    # Force each backend explicitly via its util. from_file(..., True)
    # removes the temporary converted .eml after parsing.
    f_extract, _ = extract_msg_convert(mail_outlook_1)
    parsed_extract = mailparser.MailParser.from_file(f_extract, True)

    f_msgconv, _ = msgconvert(mail_outlook_1)
    parsed_msgconv = mailparser.MailParser.from_file(f_msgconv, True)

    for key in ("from", "to", "subject"):
        assert parsed_extract.mail.get(key) == parsed_msgconv.mail.get(key)

    assert parsed_extract.date == parsed_msgconv.date

    extract_names = sorted(a["filename"] for a in parsed_extract.attachments)
    msgconv_names = sorted(a["filename"] for a in parsed_msgconv.attachments)
    assert extract_names == msgconv_names
