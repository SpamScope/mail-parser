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
RECEIVED_PATTERNS = (
    (
        r'from\s+(?P<from>(?:\b(?!by\b)\S+[ :]*)*)'
        r'(?:by\s+(?P<by>(?:\b(?!with\b)\S+[ :]*)*))?'
        r'(?:with\s+(?P<with>[^<]+)'
        r'(?:\sfor\s+<(?P<for>[^>]+)>))?(?:\s*;\s*(?P<date>.*))?'
    ),
    (
        r'from\s+(?P<from>.*)\s+envelope-sender\s+'
        r'<(?P<envelope_sender>[^>]+)>\s+by\s+(?P<by>.*)\s+'
        r'with\s+(?P<with>.*)\s+for\s+<(?P<for>[^>]+)>[,;]\s(?P<date>.*)*'
    ),
    (
        r'from\s+(?P<from>.*)\s+by\s+(?P<by>.*)\s+'
        r'with\s(?P<with>.*)\s+envelope-from\s+<(?P<envelope_from>[^>]+)>\s'
        r'(?P<others>.*);\s(?P<date>.*)*'
    ),
    (
        r'from\s+(?P<from>.*)\s+by\s+(?P<by>.*)\s+'
        r'envelope-from\s+<(?P<envelope_from>[^>]+)>[,;]\s'
        r'(?P<others>.*)\s+;\s+(?P<date>.*)*'
    ),
    (
        r'from\s+(?P<from>.*)\s+by\s+(?P<by>.*)\s+'
        r'for\s+<(?P<for>[^>]+)>;\s(?P<date>.*)\s+'
        r'envelope-from\s+<(?P<envelope_from>[^>]+)>'
    ),
    (
        r'from\s+(?P<from>(?:\b(?!by\b)\S+[ :]*)*)'
        r'(?:by\s+(?P<by>(?:\b(?!with\b)\S+[ :]*)*))?'
        r'(?:with\s+(?P<with>[^;]+))?(?:\s*;\s*(?P<date>.*))?'
    ),
    (
        r'qmail\s+.*\s+from\s+(?P<from>(?:\b(?!by\b)\S+[ :]*)*)'
        r'(?:\s*;\s*(?P<date>.*))?'
    ),
    (
        r'qmail\s+.*\sby\s+(?P<by>.*)\s*;\s*(?P<date>.*)*'
    ),
)

RECEIVED_COMPILED_LIST = [re.compile(i, re.I) for i in RECEIVED_PATTERNS]

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
