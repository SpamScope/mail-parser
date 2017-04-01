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
mail_malformed_1 = os.path.join(base_path, 'mails', 'mail_malformed_1')
mail_malformed_2 = os.path.join(base_path, 'mails', 'mail_malformed_2')
mail_malformed_3 = os.path.join(base_path, 'mails', 'mail_malformed_3')

sys.path.append(root)
from mailparser import MailParser
from mailparser.exceptions import InvalidMail
from mailparser.utils import fingerprints


class TestMailParser(unittest.TestCase):

    def setUp(self):
        # Init
        self.parser = MailParser()

    def test_fingerprints_body(self):
        self.parser.parse_from_file(mail_test_1)
        md5, sha1, sha256, sha512 = fingerprints(
            self.parser.body.encode("utf-8"))
        self.assertEqual(md5, "1bbdb7dcf511113bbc0c1b214aeac392")
        self.assertEqual(sha1, "ce9e62b50fa4e2168278880b14460b905b24eb4b")
        self.assertEqual(sha256, ("1e9b96e3f1bc74702f9703391e8ba0715b849"
                                  "7127a7ff857013ab33385898574"))
        self.assertEqual(sha512, ("ad858f7b5ec5549e55650fd13df7683e403489"
                                  "77522995851fb6b625ac54744cf3a4bf652784"
                                  "dba971ef99afeec4e6caf2fdd10be72eabb730"
                                  "c312ffbe1c4de3"))

    def test_malformed_mail(self):
        self.parser.parse_from_file(mail_malformed_3)
        defects_category = self.parser.defects_category
        self.assertIn("StartBoundaryNotFoundDefect", defects_category)
        self.assertIn("MultipartInvariantViolationDefect", defects_category)

    def test_type_error(self):
        self.parser.parse_from_file(mail_test_5)
        self.assertEqual(len(self.parser.attachments_list), 5)
        for i in self.parser.attachments_list:
            self.assertIsInstance(i["filename"], six.text_type)

    def test_valid_mail(self):
        with self.assertRaises(InvalidMail):
            self.parser.parse_from_string("fake mail")

    def test_valid_date_mail(self):
        self.parser.parse_from_file(mail_test_1),
        self.assertIn("mail_without_date", self.parser.anomalies)

    def test_parsing_know_values(self):
        self.parser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, self.parser.has_defects)

        raw = "217.76.210.112"
        result = self.parser.get_server_ipaddress(trust)
        self.assertEqual(raw, result)

        raw = "<4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>"
        result = self.parser.message_id
        self.assertEqual(raw, result)

        raw = "mporcile@server_mail.it"
        result = self.parser.to_
        self.assertEqual(raw, result)

        raw = "<meteo@regione.vda.it>"
        result = self.parser.from_
        self.assertEqual(raw, result)

        raw = "Bollettino Meteorologico del 29/11/2015"
        result = self.parser.subject
        self.assertEqual(raw, result)

        result = self.parser.has_defects
        self.assertEqual(False, result)

        result = len(self.parser.attachments_list)
        self.assertEqual(3, result)

        raw = "Sun, 29 Nov 2015 09:45:18 +0100"
        raw_utc = datetime.datetime(2015, 11, 29, 8, 45, 18, 0).isoformat()
        result = self.parser.date_mail.isoformat()
        self.assertEqual(raw_utc, result)

    def test_types(self):
        self.parser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, self.parser.has_defects)

        result = self.parser.parsed_mail_obj
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
        self.assertNotIn("anomalies", result)
        self.assertIn("has_defects", result)
        self.assertIn("has_anomalies", result)

        result = self.parser.get_server_ipaddress(trust)
        self.assertIsInstance(result, six.text_type)

        result = self.parser.parsed_mail_json
        self.assertIsInstance(result, six.text_type)

        result = self.parser.headers
        self.assertIsInstance(result, six.text_type)

        result = self.parser.body
        self.assertIsInstance(result, six.text_type)

        result = self.parser.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = self.parser.from_
        self.assertIsInstance(result, six.text_type)

        result = self.parser.to_
        self.assertIsInstance(result, six.text_type)

        result = self.parser.subject
        self.assertIsInstance(result, six.text_type)

        result = self.parser.message_id
        self.assertIsInstance(result, six.text_type)

        result = self.parser.attachments_list
        self.assertIsInstance(result, list)

        result = self.parser.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = self.parser.defects
        self.assertIsInstance(result, list)

        result = self.parser.anomalies
        self.assertIsInstance(result, list)

    def test_defects_anomalies(self):
        self.parser.parse_from_file(mail_malformed_1)

        self.assertEqual(True, self.parser.has_defects)
        self.assertEqual(1, len(self.parser.defects))
        self.assertEqual(1, len(self.parser.defects_category))
        self.assertIn("defects", self.parser.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect",
                      self.parser.defects_category)
        self.assertIsInstance(self.parser.parsed_mail_json, six.text_type)

        result = len(self.parser.attachments_list)
        self.assertEqual(1, result)

        self.parser.parse_from_file(mail_test_1)
        if six.PY2:
            self.assertEqual(False, self.parser.has_defects)
            self.assertNotIn("defects", self.parser.parsed_mail_obj)
        elif six.PY3:
            self.assertEqual(True, self.parser.has_defects)
            self.assertEqual(1, len(self.parser.defects))
            self.assertEqual(1, len(self.parser.defects_category))
            self.assertIn("defects", self.parser.parsed_mail_obj)
            self.assertIn(
                "CloseBoundaryNotFoundDefect", self.parser.defects_category)

        self.assertEqual(True, self.parser.has_anomalies)
        self.assertEqual(2, len(self.parser.anomalies))
        self.assertIn("anomalies", self.parser.parsed_mail_obj)
        self.assertIn("has_anomalies", self.parser.parsed_mail_obj)

    def test_defects_bug(self):
        self.parser.parse_from_file(mail_malformed_2)

        self.assertEqual(True, self.parser.has_defects)
        self.assertEqual(1, len(self.parser.defects))
        self.assertEqual(1, len(self.parser.defects_category))
        self.assertIn("defects", self.parser.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect",
                      self.parser.defects_category)
        self.assertIsInstance(self.parser.parsed_mail_json, six.text_type)

        result = len(self.parser.attachments_list)
        self.assertEqual(0, result)

    def test_add_content_type(self):
        self.parser.parse_from_file(mail_test_3)

        self.assertEqual(False, self.parser.has_defects)

        result = self.parser.parsed_mail_obj

        self.assertEqual(len(result["attachments"]), 1)
        self.assertIsInstance(
            result["attachments"][0]["mail_content_type"], six.text_type)
        self.assertIsInstance(
            result["attachments"][0]["payload"], six.text_type)
        self.assertEqual(
            result["attachments"][0]["content_transfer_encoding"],
            "quoted-printable")


if __name__ == '__main__':
    unittest.main(verbosity=2)
