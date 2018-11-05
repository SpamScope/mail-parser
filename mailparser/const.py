#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright 2018 Fedele Mantuano (https://twitter.com/fedelemantuano)

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

import re


REGXIP = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# need to strip out the envelope apparently so that python email library can parse it...
# python [at least 2.7] email library silently skips emails with an envelope
# https://github.com/python/cpython/blob/2.7/Lib/email/feedparser.py#L226
EMAIL_ENVELOPE_PATTERN = re.compile(r'(?:MAIL FROM:|RCPT TO:).*\n', re.IGNORECASE)

JUNK_PATTERN = r'[ \(\)\[\]\t\n]+'

# Patterns for receiveds
RECEIVED_PATTERNS = [
    # each pattern handles matching a single clause

    # need to exclude withs followed by cipher (e.g., google); (?! cipher)
    # TODO: ideally would do negative matching for with in parens

    # need the beginning or space to differentiate from envelope-from
    r'(?:(?:^|\s)from\s+(?P<from>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+by|\s+with(?! cipher)|\s+id|\s+for|\s+via|;))',

    # need to make sure envelope-from comes before from to prevent mismatches
    # envelope-from and -sender seem to optionally have space and/or ( before them
    # other clauses must have whitespace before
    r'(?:by\s+(?P<by>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+from|\s+with(?! cipher)|\s+id|\s+for|\s+via|;))',
    r'(?:with(?! cipher)\s+(?P<with>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+from|\s+by|\s+id|\s+for|\s+via|;))',
    r'(?:id\s+(?P<id>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+from|\s+by|\s+with(?! cipher)|\s+for|\s+via|;))',
    r'(?:for\s+(?P<for>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+from|\s+by|\s+with(?! cipher)|\s+id|\s+via|;))',
    r'(?:via\s+(?P<via>.+?)(?:\s*[(]?envelope-from|\s*[(]?envelope-sender|\s+from|\s+by|\s+id|\s+for|\s+with(?! cipher)|;))',

    # assumes emails are always inside <>
    r'(?:envelope-from\s+<(?P<envelope_from>.+?)>)',
    r'(?:envelope-sender\s+<(?P<envelope_sender>.+?)>)',

    # datetime comes after ; at the end
    r';\s*(?P<date>.*)'
]

RECEIVED_COMPILED_LIST = [re.compile(i, re.I|re.DOTALL) for i in RECEIVED_PATTERNS]

EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}

ADDRESSES_HEADERS = set([
    "bcc",
    "cc",
    "delivered-to",
    "from",
    "reply-to",
    "to"])

# These parts have their property in mailparser
OTHERS_PARTS = set([
    "attachments",
    "body",
    "date",
    "received",
    "timezone",
    "to_domains",
])
