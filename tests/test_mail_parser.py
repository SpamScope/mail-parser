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
import os
import six
import sys
import unittest

base_path = os.path.realpath(os.path.dirname(__file__))
root = os.path.join(base_path, '..')

mail_test_1 = os.path.join(base_path, 'mails', 'mail_test_1')
mail_test_2 = os.path.join(base_path, 'mails', 'mail_test_2')
mail_test_3 = os.path.join(base_path, 'mails', 'mail_test_3')
mail_test_5 = os.path.join(base_path, 'mails', 'mail_test_5')
mail_test_6 = os.path.join(base_path, 'mails', 'mail_test_6')
mail_test_7 = os.path.join(base_path, 'mails', 'mail_test_7')
mail_malformed_1 = os.path.join(base_path, 'mails', 'mail_malformed_1')
mail_malformed_2 = os.path.join(base_path, 'mails', 'mail_malformed_2')
mail_malformed_3 = os.path.join(base_path, 'mails', 'mail_malformed_3')
mail_outlook_1 = os.path.join(base_path, 'mails', 'mail_outlook_1')

sys.path.append(root)
import mailparser
from mailparser.utils import fingerprints, msgconvert, ported_open


class TestMailParser(unittest.TestCase):

    @unittest.skip("skip")
    def test_ipaddress(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        ip = "217.76.210.112"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(result, ip)

        trust = ""
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(result, None)

        trust = "   "
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(result, None)

    @unittest.skip("skip")
    def test_fingerprints_body(self):
        mail = mailparser.parse_from_file(mail_test_1)
        md5, sha1, sha256, sha512 = fingerprints(
            mail.body.encode("utf-8"))
        self.assertEqual(md5, "1bbdb7dcf511113bbc0c1b214aeac392")
        self.assertEqual(sha1, "ce9e62b50fa4e2168278880b14460b905b24eb4b")
        self.assertEqual(sha256, ("1e9b96e3f1bc74702f9703391e8ba0715b849"
                                  "7127a7ff857013ab33385898574"))
        self.assertEqual(sha512, ("ad858f7b5ec5549e55650fd13df7683e403489"
                                  "77522995851fb6b625ac54744cf3a4bf652784"
                                  "dba971ef99afeec4e6caf2fdd10be72eabb730"
                                  "c312ffbe1c4de3"))

    @unittest.skip("skip")
    def test_fingerprints_unicodeencodeerror(self):
        mail = mailparser.parse_from_file(mail_test_7)
        for i in mail.attachments_list:
            fingerprints(i["payload"])

    @unittest.skip("skip")
    def test_malformed_mail(self):
        mail = mailparser.parse_from_file(mail_malformed_3)
        defects_category = mail.defects_category
        self.assertIn("StartBoundaryNotFoundDefect", defects_category)
        self.assertIn("MultipartInvariantViolationDefect", defects_category)

    @unittest.skip("skip")
    def test_type_error(self):
        mail = mailparser.parse_from_file(mail_test_5)
        self.assertEqual(len(mail.attachments_list), 5)
        for i in mail.attachments_list:
            self.assertIsInstance(i["filename"], six.text_type)

    @unittest.skip("skip")
    def test_valid_mail(self):
        with self.assertRaises(ValueError):
            mailparser.parse_from_string("fake mail")

    @unittest.skip("skip")
    def test_valid_date_mail(self):
        mail = mailparser.parse_from_file(mail_test_1)
        self.assertIn("mail_without_date", mail.anomalies)

    @unittest.skip("skip")
    def test_receiveds(self):
        mail = mailparser.parse_from_file(mail_test_1)
        self.assertIsInstance(mail.receiveds_obj, list)
        self.assertEqual(len(mail.receiveds_obj), 4)
        self.assertIsInstance(mail.receiveds, six.text_type)
        self.assertIn("Received:", mail.receiveds)

    @unittest.skip("skip")
    def test_parsing_know_values(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, mail.has_defects)

        raw = "217.76.210.112"
        result = mail.get_server_ipaddress(trust)
        self.assertEqual(raw, result)

        raw = "<4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>"
        result = mail.message_id
        self.assertEqual(raw, result)

        raw = "mporcile@server_mail.it"
        result = mail.to_
        self.assertEqual(raw, result[0][1])

        raw = "<meteo@regione.vda.it>"
        result = mail.from_
        self.assertEqual(raw, result)

        raw = "Bollettino Meteorologico del 29/11/2015"
        result = mail.subject
        self.assertEqual(raw, result)

        result = mail.has_defects
        self.assertEqual(False, result)

        result = len(mail.attachments_list)
        self.assertEqual(3, result)

        raw = "Sun, 29 Nov 2015 09:45:18 +0100"
        raw_utc = datetime.datetime(2015, 11, 29, 8, 45, 18, 0).isoformat()
        result = mail.date_mail.isoformat()
        self.assertEqual(raw_utc, result)

    @unittest.skip("skip")
    def test_types(self):
        mail = mailparser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, mail.has_defects)

        result = mail.parsed_mail_obj
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
        self.assertNotIn("anomalies", result)
        self.assertIn("has_defects", result)
        self.assertIn("has_anomalies", result)

        result = mail.get_server_ipaddress(trust)
        self.assertIsInstance(result, six.text_type)

        result = mail.parsed_mail_json
        self.assertIsInstance(result, six.text_type)

        result = mail.headers
        self.assertIsInstance(result, six.text_type)

        result = mail.body
        self.assertIsInstance(result, six.text_type)

        result = mail.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = mail.from_
        self.assertIsInstance(result, six.text_type)

        result = mail.to_
        self.assertIsInstance(result, tuple)
        self.assertEquals(len(result), 1)
        self.assertIsInstance(result[0], tuple)
        self.assertEquals(len(result[0]), 2)

        result = mail.subject
        self.assertIsInstance(result, six.text_type)

        result = mail.message_id
        self.assertIsInstance(result, six.text_type)

        result = mail.attachments_list
        self.assertIsInstance(result, list)

        result = mail.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = mail.defects
        self.assertIsInstance(result, list)

        result = mail.anomalies
        self.assertIsInstance(result, list)

    @unittest.skip("skip")
    def test_defects_anomalies(self):
        mail = mailparser.parse_from_file(mail_malformed_1)

        self.assertEqual(True, mail.has_defects)
        self.assertEqual(1, len(mail.defects))
        self.assertEqual(1, len(mail.defects_category))
        self.assertIn("defects", mail.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect",
                      mail.defects_category)
        self.assertIsInstance(mail.parsed_mail_json, six.text_type)

        result = len(mail.attachments_list)
        self.assertEqual(1, result)

        mail = mailparser.parse_from_file(mail_test_1)
        if six.PY2:
            self.assertEqual(False, mail.has_defects)
            self.assertNotIn("defects", mail.parsed_mail_obj)
        elif six.PY3:
            self.assertEqual(True, mail.has_defects)
            self.assertEqual(1, len(mail.defects))
            self.assertEqual(1, len(mail.defects_category))
            self.assertIn("defects", mail.parsed_mail_obj)
            self.assertIn(
                "CloseBoundaryNotFoundDefect", mail.defects_category)

        self.assertEqual(True, mail.has_anomalies)
        self.assertEqual(2, len(mail.anomalies))
        self.assertIn("anomalies", mail.parsed_mail_obj)
        self.assertIn("has_anomalies", mail.parsed_mail_obj)

    @unittest.skip("skip")
    def test_defects_bug(self):
        mail = mailparser.parse_from_file(mail_malformed_2)

        self.assertEqual(True, mail.has_defects)
        self.assertEqual(1, len(mail.defects))
        self.assertEqual(1, len(mail.defects_category))
        self.assertIn("defects", mail.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect",
                      mail.defects_category)
        self.assertIsInstance(mail.parsed_mail_json, six.text_type)

        result = len(mail.attachments_list)
        self.assertEqual(0, result)

    @unittest.skip("skip")
    def test_add_content_type(self):
        mail = mailparser.parse_from_file(mail_test_3)

        self.assertEqual(False, mail.has_defects)

        result = mail.parsed_mail_obj

        self.assertEqual(len(result["attachments"]), 1)
        self.assertIsInstance(
            result["attachments"][0]["mail_content_type"], six.text_type)
        self.assertFalse(result["attachments"][0]["binary"])
        self.assertIsInstance(
            result["attachments"][0]["payload"], six.text_type)
        self.assertEqual(
            result["attachments"][0]["content_transfer_encoding"],
            "quoted-printable")

    @unittest.skip("skip")
    def test_from_bytes(self):
        if six.PY2:
            with self.assertRaises(EnvironmentError):
                mailparser.MailParser.from_bytes(b"")

    @unittest.skip("skip")
    def test_classmethods(self):
        # MailParser.from_file
        m = mailparser.MailParser.from_file(mail_test_3)
        m.parse()
        result = m.parsed_mail_obj
        self.assertEqual(len(result["attachments"]), 1)

        # MailParser.from_string
        m = mailparser.MailParser.from_string(m.message_as_string)
        m.parse()
        result = m.parsed_mail_obj
        self.assertEqual(len(result["attachments"]), 1)

    @unittest.skip("skip")
    def test_parser_methods(self):
        m = mailparser.MailParser()
        self.assertIsNone(m.message)

        m.parse_from_file(mail_test_3)
        result = m.parsed_mail_obj
        self.assertEqual(len(result["attachments"]), 1)

        n = mailparser.MailParser()
        n.parse_from_string(m.message_as_string)
        self.assertEqual(len(result["attachments"]), 1)

        o = mailparser.MailParser()
        with open(mail_test_3) as fp:
            o.parse_from_file_obj(fp)
        self.assertEqual(len(result["attachments"]), 1)

    @unittest.skip("skip")
    def test_bug_UnicodeDecodeError(self):
        m = mailparser.parse_from_file(mail_test_6)
        self.assertIsInstance(m.parsed_mail_obj, dict)
        self.assertIsInstance(m.parsed_mail_json, six.text_type)

    @unittest.skip("skip")
    def test_parse_from_file_msg(self):
        """
        Tested mail from VirusTotal: md5 b89bf096c9e3717f2d218b3307c69bd0

        The email used for unittest were found randomly on VirusTotal and
        then already publicly available so can not be considered
        as privacy violation
        """

        m = mailparser.parse_from_file_msg(mail_outlook_1)
        email = m.parsed_mail_obj
        self.assertIn("attachments", email)
        self.assertEqual(len(email["attachments"]), 5)
        self.assertIn("from", email)
        self.assertEqual(email["from"], "<NueblingV@w-vwa.de>")
        self.assertIn("subject", email)

        m = mailparser.MailParser()
        m = m.parse_from_file_msg(mail_outlook_1)
        self.assertEqual(email["body"], m.body)

    @unittest.skip("skip")
    def test_msgconvert(self):
        """
        Tested mail from VirusTotal: md5 b89bf096c9e3717f2d218b3307c69bd0

        The email used for unittest were found randomly on VirusTotal and
        then already publicly available so can not be considered
        as privacy violation
        """

        f, _ = msgconvert(mail_outlook_1)
        self.assertTrue(os.path.exists(f))
        m = mailparser.parse_from_file(f)
        self.assertEqual(m.from_, "<NueblingV@w-vwa.de>")

    @unittest.skip("skip")
    def test_from_file_obj(self):
        with ported_open(mail_test_2) as fp:
            mail = mailparser.parse_from_file_obj(fp)
        trust = "smtp.customers.net"

        self.assertEqual(False, mail.has_defects)

        result = mail.parsed_mail_obj
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
        self.assertNotIn("anomalies", result)
        self.assertIn("has_defects", result)
        self.assertIn("has_anomalies", result)

        result = mail.get_server_ipaddress(trust)
        self.assertIsInstance(result, six.text_type)

        result = mail.parsed_mail_json
        self.assertIsInstance(result, six.text_type)

        result = mail.headers
        self.assertIsInstance(result, six.text_type)

        result = mail.body
        self.assertIsInstance(result, six.text_type)

        result = mail.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = mail.from_
        self.assertIsInstance(result, six.text_type)

        result = mail.to_
        self.assertIsInstance(result, tuple)
        self.assertEquals(len(result), 1)
        self.assertIsInstance(result[0], tuple)
        self.assertEquals(len(result[0]), 2)

        result = mail.subject
        self.assertIsInstance(result, six.text_type)

        result = mail.message_id
        self.assertIsInstance(result, six.text_type)

        result = mail.attachments_list
        self.assertIsInstance(result, list)

        result = mail.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = mail.defects
        self.assertIsInstance(result, list)

        result = mail.anomalies
        self.assertIsInstance(result, list)

    def test_getattr(self):
        mail = mailparser.parse_from_file(mail_test_2)
        print("\n\n")
        print mail.date_json
        print("\n\n")
        print mail.date_raw
        print("\n\n")


if __name__ == '__main__':
    unittest.main(verbosity=2)
