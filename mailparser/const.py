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

JUNK_PATTERN = r'[ \(\)\[\]\t\n]+'

# Patterns for receiveds
RECEIVED_PATTERNS = [
    # each pattern handles matching a single clause

    # need to exclude withs followed by cipher (e.g., google); (?! cipher)
    # TODO: ideally would do negative matching for with in parens

    # need the beginning or space to differentiate from envelope-from
    (
        r'(?:(?:^|\s)from\s+(?P<from>.+?)(?:\s*[(]?'
        r'envelope-from|\s*[(]?envelope-sender|\s+'
        r'by|\s+with(?! cipher)|\s+id|\s+for|\s+via|;))'
    ),

    # need to make sure envelope-from comes before from to prevent mismatches
    # envelope-from and -sender seem to optionally have space and/or
    # ( before them other clauses must have whitespace before
    (
        r'(?:by\s+(?P<by>.+?)(?:\s*[(]?envelope-from|\s*'
        r'[(]?envelope-sender|\s+from|\s+with'
        r'(?! cipher)|\s+id|\s+for|\s+via|;))'
    ),
    (
        r'(?:with(?! cipher)\s+(?P<with>.+?)(?:\s*[(]?envelope-from|\s*[(]?'
        r'envelope-sender|\s+from|\s+by|\s+id|\s+for|\s+via|;))'
    ),
    (
        r'(?:id\s+(?P<id>.+?)(?:\s*[(]?envelope-from|\s*'
        r'[(]?envelope-sender|\s+from|\s+by|\s+with'
        r'(?! cipher)|\s+for|\s+via|;))'
    ),
    (
        r'(?:for\s+(?P<for>.+?)(?:\s*[(]?envelope-from|\s*[(]?'
        r'envelope-sender|\s+from|\s+by|\s+with'
        r'(?! cipher)|\s+id|\s+via|;))'
    ),
    (
        r'(?:via\s+(?P<via>.+?)(?:\s*[(]?'
        r'envelope-from|\s*[(]?envelope-sender|\s+'
        r'from|\s+by|\s+id|\s+for|\s+with(?! cipher)|;))'
    ),

    # assumes emails are always inside <>
    r'(?:envelope-from\s+<(?P<envelope_from>.+?)>)',
    r'(?:envelope-sender\s+<(?P<envelope_sender>.+?)>)',

    # datetime comes after ; at the end
    r';\s*(?P<date>.*)'
]

RECEIVED_COMPILED_LIST = [
    re.compile(i, re.I | re.DOTALL) for i in RECEIVED_PATTERNS]

EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}

ADDRESSES_HEADERS = set([
    "bcc",
    "cc",
    "delivered-to",
    "from",
    "reply-to",
    "to"])

# These parts are always returned
OTHERS_PARTS = set([
    "attachments",
    "body",
    "date",
    "message-id",
    "received",
    "subject",
    "timezone",
    "to_domains",
    "user-agent",
    "x-mailer",
    "x-original-to",
])
