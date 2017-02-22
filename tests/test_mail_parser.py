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
mail_malformed_1 = os.path.join(base_path, 'mails', 'mail_malformed_1')
mail_malformed_2 = os.path.join(base_path, 'mails', 'mail_malformed_2')

sys.path.append(root)
from mailparser import MailParser
from mailparser.exceptions import InvalidMail


class TestMailParser(unittest.TestCase):

    def test_valid_mail(self):
        with self.assertRaises(InvalidMail):
            parser = MailParser()
            parser.parse_from_string("fake mail")

    def test_valid_date_mail(self):
        parser = MailParser()
        parser.parse_from_file(mail_test_1),
        self.assertIn("mail_without_date", parser.anomalies)

    def test_parsing_know_values(self):
        parser = MailParser()
        parser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, parser.has_defects)

        raw = "217.76.210.112"
        result = parser.get_server_ipaddress(trust)
        self.assertEqual(raw, result)

        raw = "<4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>"
        result = parser.message_id
        self.assertEqual(raw, result)

        raw = "mporcile@server_mail.it"
        result = parser.to_
        self.assertEqual(raw, result)

        raw = "<meteo@regione.vda.it>"
        result = parser.from_
        self.assertEqual(raw, result)

        raw = "Bollettino Meteorologico del 29/11/2015"
        result = parser.subject
        self.assertEqual(raw, result)

        result = parser.has_defects
        self.assertEqual(False, result)

        result = len(parser.attachments_list)
        self.assertEqual(3, result)

        raw = "Sun, 29 Nov 2015 09:45:18 +0100"
        raw_utc = datetime.datetime(2015, 11, 29, 8, 45, 18, 0).isoformat()
        result = parser.date_mail.isoformat()
        self.assertEqual(raw_utc, result)

    def test_types(self):
        parser = MailParser()
        parser.parse_from_file(mail_test_2)
        trust = "smtp.customers.net"

        self.assertEqual(False, parser.has_defects)

        result = parser.parsed_mail_obj
        self.assertIsInstance(result, dict)
        self.assertNotIn("defects", result)
        self.assertNotIn("anomalies", result)
        self.assertIn("has_defects", result)
        self.assertIn("has_anomalies", result)

        result = parser.get_server_ipaddress(trust)
        self.assertIsInstance(result, six.text_type)

        result = parser.parsed_mail_json
        self.assertIsInstance(result, six.text_type)

        result = parser.headers
        self.assertIsInstance(result, six.text_type)

        result = parser.body
        self.assertIsInstance(result, six.text_type)

        result = parser.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = parser.from_
        self.assertIsInstance(result, six.text_type)

        result = parser.to_
        self.assertIsInstance(result, six.text_type)

        result = parser.subject
        self.assertIsInstance(result, six.text_type)

        result = parser.message_id
        self.assertIsInstance(result, six.text_type)

        result = parser.attachments_list
        self.assertIsInstance(result, list)

        result = parser.date_mail
        self.assertIsInstance(result, datetime.datetime)

        result = parser.defects
        self.assertIsInstance(result, list)

        result = parser.anomalies
        self.assertIsInstance(result, list)

    def test_defects_anomalies(self):
        parser = MailParser()
        parser.parse_from_file(mail_malformed_1)

        self.assertEqual(True, parser.has_defects)
        self.assertEqual(1, len(parser.defects))
        self.assertEqual(1, len(parser.defects_category))
        self.assertIn("defects", parser.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect", parser.defects_category)
        self.assertIsInstance(parser.parsed_mail_json, six.text_type)

        result = len(parser.attachments_list)
        self.assertEqual(1, result)

        parser.parse_from_file(mail_test_1)
        if six.PY2:
            self.assertEqual(False, parser.has_defects)
            self.assertNotIn("defects", parser.parsed_mail_obj)
        elif six.PY3:
            self.assertEqual(True, parser.has_defects)
            self.assertEqual(1, len(parser.defects))
            self.assertEqual(1, len(parser.defects_category))
            self.assertIn("defects", parser.parsed_mail_obj)
            self.assertIn(
                "CloseBoundaryNotFoundDefect", parser.defects_category)

        self.assertEqual(True, parser.has_anomalies)
        self.assertEqual(2, len(parser.anomalies))
        self.assertIn("anomalies", parser.parsed_mail_obj)
        self.assertIn("has_anomalies", parser.parsed_mail_obj)

    def test_defects_bug(self):
        parser = MailParser()
        parser.parse_from_file(mail_malformed_2)

        self.assertEqual(True, parser.has_defects)
        self.assertEqual(1, len(parser.defects))
        self.assertEqual(1, len(parser.defects_category))
        self.assertIn("defects", parser.parsed_mail_obj)
        self.assertIn("StartBoundaryNotFoundDefect", parser.defects_category)
        self.assertIsInstance(parser.parsed_mail_json, six.text_type)

        result = len(parser.attachments_list)
        self.assertEqual(0, result)

    def test_add_content_type(self):
        parser = MailParser()
        parser.parse_from_file(mail_test_3)

        self.assertEqual(False, parser.has_defects)

        result = parser.parsed_mail_obj

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
