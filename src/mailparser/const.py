#!/usr/bin/env python

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

JUNK_PATTERN = r"[ \(\)\[\]\t\n]+"

# Patterns for receiveds
RECEIVED_PATTERNS = [
    # FIXED: More restrictive 'from' clause
    # Only matches 'from' at the beginning of the header (^) or after
    # newline/whitespace to avoid matching within "for <email> from <email>"
    # constructs which caused duplicate matches in IBM gateway headers
    (
        r"(?:(?:^|\n\s*)from\s+(?P<from>.+?)(?:\s*[(]?"
        r"envelope-from|\s*[(]?envelope-sender|\s+"
        r"by|\s+with(?! cipher)|\s+id|\s+via|;))"
    ),
    # IMPROVED: More precise 'by' clause
    # Modified to not consume 'with' clause, allowing proper separation
    # of 'by' (server name) and 'with' (protocol) fields
    (
        r"(?:(?:^|\s)by\s+(?P<by>[^\s]+(?:\s+[^\s]+)*?)"
        r"(?:\s+with(?! cipher)|\s*[(]?envelope-from|\s*"
        r"[(]?envelope-sender|\s+id|\s+for|\s+via|;))"
    ),
    # IMPROVED: 'with' clause with better boundary detection
    (
        r"(?:(?:^|\s)with(?! cipher)\s+(?P<with>.+?)"
        r"(?:\s*[(]?envelope-from|\s*[(]?"
        r"envelope-sender|\s+id|\s+for|\s+via|;))"
    ),
    # IMPROVED: 'id' clause with cleaner boundaries
    (
        r"(?:(?:^|\s)id\s+(?P<id>.+?)(?:\s*[(]?envelope-from|\s*"
        r"[(]?envelope-sender|\s+for|\s+via|;))"
    ),
    # IMPROVED: 'for' clause - handles "for <email> from <email>" pattern
    # Stops before 'from' keyword to prevent the 'from' pattern from
    # matching the sender email in this construct
    (
        r"(?:(?:^|\s)for\s+(?P<for><[^>]+>|[^\s]+)"
        r"(?:\s+from|\s*[(]?envelope-from|\s*[(]?"
        r"envelope-sender|\s+via|;))"
    ),
    # IMPROVED: 'via' clause with better termination
    (
        r"(?:(?:^|\s)via\s+(?P<via>.+?)(?:\s*[(]?"
        r"envelope-from|\s*[(]?envelope-sender|;))"
    ),
    # assumes emails are always inside <>
    r"(?:envelope-from\s+<(?P<envelope_from>.+?)>)",
    r"(?:envelope-sender\s+<(?P<envelope_sender>.+?)>)",
    # datetime comes after ; at the end
    r";\s*(?P<date>.*)",
    # sendgrid datetime
    (
        r"(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:"
        r"\d{2}\.\d{9} \+0000 UTC) m=\+\d+\.\d+"
    ),
]

RECEIVED_COMPILED_LIST = [re.compile(i, re.I | re.DOTALL) for i in RECEIVED_PATTERNS]

EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}

ADDRESSES_HEADERS = set(["bcc", "cc", "delivered-to", "from", "reply-to", "to"])

# These parts are always returned
OTHERS_PARTS = set(
    [
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
    ]
)
