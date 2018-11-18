#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright 2017 Fedele Mantuano (https://twitter.com/fedelemantuano)

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

import logging
import os
import sys
import unittest

base_path = os.path.realpath(os.path.dirname(__file__))
root = os.path.join(base_path, '..')
sys.path.append(root)

logging.getLogger().addHandler(logging.NullHandler())

from mailparser.__main__ import get_args


class TestMain(unittest.TestCase):

    def setUp(self):
        self.parser = get_args()

    def test_required(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--file", "test", "--string", "test"])

        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--file", "test", "--stdin"])

        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--file"])

        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--string"])

    def test_options(self):
        parsed = self.parser.parse_args(["--file", "mail.eml"])
        self.assertEqual(parsed.file, "mail.eml")

        parsed = self.parser.parse_args(["--string", "mail.str"])
        self.assertEqual(parsed.string, "mail.str")

        parsed = self.parser.parse_args(["--file", "mail.eml", "--json"])
        self.assertTrue(parsed.json)

        parsed = self.parser.parse_args(["--file", "mail.eml", "--body"])
        self.assertTrue(parsed.body)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-a"])
        self.assertTrue(parsed.attachments)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-r"])
        self.assertTrue(parsed.headers)

        parsed = self.parser.parse_args(["--file", "mail.eml", "--to"])
        self.assertTrue(parsed.to)

        parsed = self.parser.parse_args(["--file", "mail.eml", "--from"])
        self.assertTrue(parsed.from_)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-u"])
        self.assertTrue(parsed.subject)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-d"])
        self.assertTrue(parsed.defects)

        parsed = self.parser.parse_args([
            "--file", "mail.eml", "--senderip", "trust"])
        self.assertTrue(parsed.senderip)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-p"])
        self.assertTrue(parsed.mail_hash)

        parsed = self.parser.parse_args([
            "--file", "mail.eml", "--attachments-hash"])
        self.assertTrue(parsed.attachments_hash)

        parsed = self.parser.parse_args(["--file", "mail.eml", "-c"])
        self.assertTrue(parsed.receiveds)


if __name__ == '__main__':
    unittest.main(verbosity=2)
