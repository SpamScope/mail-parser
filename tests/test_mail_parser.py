#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import os
import shutil
import six
import sys
import tempfile
import unittest
from unittest.mock import patch


import mailparser
from mailparser.utils import (
    convert_mail_date,
    fingerprints,
    get_header,
    get_mail_keys,
    get_to_domains,
    ported_open,
    ported_string,
    receiveds_parsing,
    parse_received,
    random_string,
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
        self.assertIsInstance(mail.text_html_json, six.text_type)
        self.assertEqual(len(mail.text_html), 1)

    def test_text_not_managed(self):
        mail = mailparser.parse_from_file(mail_test_14)
        self.assertIsInstance(mail.text_not_managed, list)
        self.assertIsInstance(mail.text_not_managed_json, six.text_type)
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
        self.assertIsInstance(result, six.text_type)
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
        self.assertIsInstance(h1, six.text_type)

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
        self.assertEqual(mail.fake_header, six.text_type())

        # This email has header X-MSMail-Priority
        msmail_priority = mail.X_MSMail_Priority
        self.assertEqual(msmail_priority, "High")

    def test_type_error(self):
        mail = mailparser.parse_from_file(mail_test_5)
        self.assertEqual(len(mail.attachments), 5)
        for i in mail.attachments:
            self.assertIsInstance(i["filename"], six.text_type)

    def test_filename_decode(self):
        mail = mailparser.parse_from_file(mail_test_11)
        for i in mail.attachments:
            self.assertIsInstance(i["filename"], six.text_type)

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
            self.assertIsInstance(i, six.text_type)

        self.assertIsInstance(mail.received_json, six.text_type)

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
        self.assertIsInstance(mail.to_json, six.text_type)
        self.assertIsInstance(mail.to_raw, six.text_type)
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

        self.assertIsInstance(mail.date_raw, six.text_type)
        self.assertIsInstance(mail.date_json, six.text_type)
        raw_utc = "2015-11-29T08:45:18+00:00"
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
        self.assertIsInstance(result, six.text_type)

        result = mail.mail_json
        self.assertIsInstance(result, six.text_type)

        result = mail.headers_json
        self.assertIsInstance(result, six.text_type)

        result = mail.headers
        self.assertIsInstance(result, dict)

        result = mail.body
        self.assertIsInstance(result, six.text_type)

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
        self.assertIsInstance(result, six.text_type)

        result = mail.message_id
        self.assertIsInstance(result, six.text_type)

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
        self.assertIsInstance(mail.mail_json, six.text_type)

        result = len(mail.attachments)
        self.assertEqual(1, result)

        mail = mailparser.parse_from_file(mail_test_1)
        if six.PY2:
            self.assertFalse(mail.has_defects)
            self.assertNotIn("defects", mail.mail)
        elif six.PY3:
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
        self.assertIsInstance(mail.parsed_mail_json, six.text_type)

        result = len(mail.attachments)
        self.assertEqual(1, result)

    def test_add_content_type(self):
        mail = mailparser.parse_from_file(mail_test_3)

        self.assertFalse(mail.has_defects)

        result = mail.mail

        self.assertEqual(len(result["attachments"]), 1)
        self.assertIsInstance(
            result["attachments"][0]["mail_content_type"], six.text_type
        )
        self.assertFalse(result["attachments"][0]["binary"])
        self.assertIsInstance(result["attachments"][0]["payload"], six.text_type)
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
        self.assertIsInstance(m.mail_json, six.text_type)

    @patch("mailparser.core.os.remove")
    @patch("mailparser.core.msgconvert")
    def test_parse_from_file_msg(self, mock_msgconvert, mock_remove):
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
        self.assertIsInstance(result, six.text_type)

        result = mail.mail_json
        self.assertIsInstance(result, six.text_type)

        result = mail.headers
        self.assertIsInstance(result, dict)

        result = mail.headers_json
        self.assertIsInstance(result, six.text_type)

        result = mail.body
        self.assertIsInstance(result, six.text_type)

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
        self.assertIsInstance(result, six.text_type)

        result = mail.message_id
        self.assertIsInstance(result, six.text_type)

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

        self.assertIsInstance(m.to_domains_json, six.text_type)

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
        self.assertEqual(s, six.text_type())

        raw_data = "test"
        s = ported_string(raw_data)
        self.assertEqual(s, "test")

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
        self.assertIsInstance(mail.to_json, six.text_type)
        self.assertIsInstance(mail.to_raw, six.text_type)
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

        self.assertIsInstance(mail.date_raw, six.text_type)
        self.assertIsInstance(mail.date_json, six.text_type)
        raw_utc = "2015-11-29T08:45:18+00:00"
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
