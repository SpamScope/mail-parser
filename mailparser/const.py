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
RECEIVED_PATTERN = (r'from\s+(?P<from>(?:\b(?!by\b)\S+[ :]*)*)'
                    r'(?:by\s+(?P<by>(?:\b(?!with\b)\S+[ :]*)*))?'
                    r'(?:with\s+(?P<with>[^;]+))?(?:\s*;\s*(?P<date>.*))?')
JUNK_PATTERN = r'[ \(\)\[\]\t\n]+'
RECEIVED_COMPILED = re.compile(RECEIVED_PATTERN, re.I)

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
    "to_domains"])
