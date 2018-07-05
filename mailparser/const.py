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
EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}

ADDRESSES_HEADERS = set([
    "bcc",
    "cc",
    "delivered_to",
    "from",
    "reply_to",
    "to"])
OTHERS_PARTS = set([
    "attachments",
    "body",
    "date",
    "received",
    "to_domains"])
