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

# IPv4 pattern - validates octet range (0-255) per RFC 791
REGXIP = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)

# IPv6 pattern - matches standard and common compressed forms per RFC 5952
REGXIP6 = re.compile(
    r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # full form
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"  # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # :: with 1 group after
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"  # ::x:x...
    r"|::)"  # just ::
)

# Normalize whitespace: collapse tabs and newlines to single space.
# Parenthesized comments and bracketed IPs are preserved.
JUNK_PATTERN = r"[\t\n]+"

# ------------------------------------------------------------------ #
# Received header parsing — RFC 5321 §4.4 grammar:
#
#   Received     = "Received:" *( received-token / comment ) ";" date-time
#   received-token = "from" domain / "by" domain / "via" atom
#                  / "with" atom  / "id"  atom   / "for" addr-spec
#
# Strategy: tokenize on clause keywords, then extract values per clause.
# This eliminates the duplicated boundary lookaheads of the old
# per-clause pattern list and matches the RFC grammar directly.
# ------------------------------------------------------------------ #

# Pattern that splits a received header into clause tokens.
# Matches each RFC 5321 keyword at a word boundary followed by its value,
# which extends up to the next keyword or semicolon.
# The keywords are: from, by, via, with (not "with cipher"), id, for,
# plus the non-standard envelope-from and envelope-sender.
_CLAUSE_SPLITTER = re.compile(
    r"(?:^|\s+)"
    r"(from|by|via|with(?!\s+cipher)|id|for|envelope-from|envelope-sender)"
    r"\s+",
    re.I,
)

# Extracts envelope-from email: envelope-from <addr>
_ENVELOPE_FROM_RE = re.compile(r"<([^>]+)>")

# Date after semicolon (standard RFC 5321)
_DATE_RE = re.compile(r";\s*(.*)", re.DOTALL)

# SendGrid non-standard date format (no semicolon)
_SENDGRID_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{9}\s+\+0000\s+UTC)"
    r"\s+m=\+\d+\.\d+",
    re.I,
)

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
