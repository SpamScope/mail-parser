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

from __future__ import unicode_literals

from collections import namedtuple, Counter
from email.errors import HeaderParseError
from email.header import decode_header
from unicodedata import normalize

import datetime
import email
import functools
import hashlib
import logging
import os
import re
import simplejson as json
import subprocess
import sys
import tempfile

import six

from .const import (
    ADDRESSES_HEADERS,
    JUNK_PATTERN,
    OTHERS_PARTS,
    RECEIVED_COMPILED)

from .exceptions import MailParserOSError


log = logging.getLogger(__name__)


def custom_log(level="WARNING", name=None):
    if name:
        log = logging.getLogger(name)
    else:
        log = logging.getLogger()
    log.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(name)s | "
        "%(module)s | "
        "%(funcName)s | "
        "%(levelname)s | "
        "%(message)s")
    ch.setFormatter(formatter)
    log.addHandler(ch)
    return log


def sanitize(func):
    """ NFC is the normalization form recommended by W3C. """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return normalize('NFC', func(*args, **kwargs))
    return wrapper


@sanitize
def ported_string(raw_data, encoding='utf-8', errors='ignore'):
    """
    Give as input raw data and output a str in Python 3
    and unicode in Python 2.

    Args:
        raw_data: Python 2 str, Python 3 bytes or str to porting
        encoding: string giving the name of an encoding
        errors: his specifies the treatment of characters
            which are invalid in the input encoding

    Returns:
        str (Python 3) or unicode (Python 2)
    """

    if not raw_data:
        return six.text_type()

    if isinstance(raw_data, six.text_type):
        return raw_data.strip()

    if six.PY2:
        try:
            return six.text_type(raw_data, encoding, errors).strip()
        except LookupError:
            return six.text_type(raw_data, "utf-8", errors).strip()

    if six.PY3:
        try:
            return six.text_type(raw_data, encoding).strip()
        except (LookupError, UnicodeDecodeError):
            return six.text_type(raw_data, "utf-8", errors).strip()


def decode_header_part(header):
    """
    Given an raw header returns an decoded header

    Args:
        header (string): header to decode

    Returns:
        str (Python 3) or unicode (Python 2)
    """
    if not header:
        return six.text_type()

    output = six.text_type()

    try:
        for d, c in decode_header(header):
            c = c if c else 'utf-8'
            output += ported_string(d, c, 'ignore')

    # Header parsing failed, when header has charset Shift_JIS
    except (HeaderParseError, UnicodeError):
        log.error("Failed decoding header part: {}".format(header))
        output += header

    return output


def ported_open(file_):
    if six.PY2:
        return open(file_)
    elif six.PY3:
        return open(file_, encoding="utf-8", errors='ignore')


def find_between(text, first_token, last_token):
    try:
        start = text.index(first_token) + len(first_token)
        end = text.index(last_token, start)
        return text[start:end].strip()
    except ValueError:
        return


def fingerprints(data):
    """
    This function return the fingerprints of data.

    Args:
        data (string): raw data

    Returns:
        namedtuple: fingerprints md5, sha1, sha256, sha512
    """

    Hashes = namedtuple('Hashes', "md5 sha1 sha256 sha512")

    if six.PY2:
        if not isinstance(data, str):
            data = data.encode("utf-8")
    elif six.PY3:
        if not isinstance(data, bytes):
            data = data.encode("utf-8")

    # md5
    md5 = hashlib.md5()
    md5.update(data)
    md5 = md5.hexdigest()

    # sha1
    sha1 = hashlib.sha1()
    sha1.update(data)
    sha1 = sha1.hexdigest()

    # sha256
    sha256 = hashlib.sha256()
    sha256.update(data)
    sha256 = sha256.hexdigest()

    # sha512
    sha512 = hashlib.sha512()
    sha512.update(data)
    sha512 = sha512.hexdigest()

    return Hashes(md5, sha1, sha256, sha512)


def msgconvert(email):
    """
    Exec msgconvert tool, to convert msg Outlook
    mail in eml mail format

    Args:
        email (string): file path of Outlook msg mail

    Returns:
        tuple with file path of mail converted and
        standard output data (unicode Python 2, str Python 3)
    """
    log.debug("Started converting Outlook email")
    temp = tempfile.mkstemp(prefix="outlook_")[-1]
    command = ["msgconvert", "--mbox", temp, email]

    try:
        if six.PY2:
            with open(os.devnull, "w") as devnull:
                out = subprocess.Popen(
                    command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=devnull)
        elif six.PY3:
            out = subprocess.Popen(
                command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    except OSError:
        message = "To use this function you must install 'msgconvert' tool"
        log.exception(message)
        raise MailParserOSError(message)

    else:
        stdoutdata, _ = out.communicate()
        return temp, stdoutdata.decode("utf-8").strip()

def receiveds_parsing(receiveds):
    """
    This function parses the receiveds headers

    Args:
        receiveds (list): list of raw receiveds headers

    Returns:
        a list of parsed receiveds headers with first hop in first position
    """

    parsed = []

    try:
        for i in receiveds:
            cleaned = re.sub(JUNK_PATTERN, " ", i)
            for j in RECEIVED_COMPILED.finditer(cleaned):
                parsed.append(j.groupdict())

        if len(receiveds) != len(parsed):
            raise ValueError

    except (AttributeError, ValueError):
        return receiveds_not_parsed(receiveds)

    else:
        return receiveds_format(parsed)


def convert_mail_date(date):
    d = email.utils.parsedate_tz(date)
    t = email.utils.mktime_tz(d)
    return datetime.datetime.utcfromtimestamp(t)


def receiveds_not_parsed(receiveds):
    """
    If receiveds are not parsed, makes a new structure with raw
    field. It's useful to have the same structure of receiveds
    parsed.

    Args:
        receiveds (list): list of raw receiveds headers

    Returns:
        a list of not parsed receiveds headers with first hop in first position
    """
    log.debug("Receiveds for this email are not parsed")

    output = []
    counter = Counter()

    for i in receiveds[::-1]:
        j = {"raw": i.strip()}
        j["hop"] = counter["hop"] + 1
        counter["hop"] += 1
        output.append(j)
    else:
        return output


def receiveds_format(receiveds):
    """
    Given a list of receiveds hop, adds metadata and reformat
    field values

    Args:
        receiveds (list): list of receiveds hops already formatted

    Returns:
        list of receiveds reformated and with new fields
    """
    log.debug("Receiveds for this email are parsed")

    output = []
    counter = Counter()

    for i in receiveds[::-1]:
        # Clean strings
        j = {k: v.strip() for k, v in i.items() if v}

        # Add hop
        j["hop"] = counter["hop"] + 1

        # Add UTC date
        if i.get("date"):
            # Modify date to manage strange header like:
            # "for <eboktor@romolo.com>; Tue, 7 Mar 2017 14:29:24 -0800",
            i["date"] = i["date"].split(";")[-1]
            try:
                j["date_utc"] = convert_mail_date(i["date"])
            except TypeError:
                j["date_utc"] = None

        # Add delay
        size = len(output)
        now = j.get("date_utc")

        if size and now:
            before = output[counter["hop"] - 1].get("date_utc")
            if before:
                j["delay"] = (now - before).total_seconds()
            else:
                j["delay"] = 0
        else:
            j["delay"] = 0

        # append result
        output.append(j)

        # new hop
        counter["hop"] += 1
    else:
        for i in output:
            if i.get("date_utc"):
                i["date_utc"] = i["date_utc"].isoformat()
        else:
            return output


def get_to_domains(to=[], reply_to=[]):
    domains = set()
    for i in to + reply_to:
        try:
            domains.add(i[1].split("@")[-1].lower().strip())
        except KeyError:
            pass
    else:
        return list(domains)


def get_header(message, name):
    """
    Gets an email.message.Message and a header name and returns
    the mail header decoded with the correct charset.

    Args:
        message (email.message.Message): email message object
        name (string): header to get

    Returns:
        decoded header
    """
    header = message.get(name)
    log.debug("Getting header {!r}: {!r}".format(name, header))
    if header:
        return decode_header_part(header)
    return six.text_type()


def get_mail_keys(message):
    """
    Given an email.message.Message, return a set with all email parts to get

    Args:
        message (email.message.Message): email message object

    Returns:
        set with all email parts
    """
    all_headers_keys = {i.lower() for i in message.keys()}
    all_parts = ADDRESSES_HEADERS | OTHERS_PARTS | all_headers_keys
    log.debug("All parts to get: {}".format(", ".join(all_parts)))
    return all_parts


def safe_print(data):
    try:
        print(data)
    except UnicodeEncodeError:
        print(data.encode('utf-8'))


def print_mail_fingerprints(data):
    md5, sha1, sha256, sha512 = fingerprints(data)
    print("md5:\t{}".format(md5))
    print("sha1:\t{}".format(sha1))
    print("sha256:\t{}".format(sha256))
    print("sha512:\t{}".format(sha512))


def print_attachments(attachments, flag_hash):
    if flag_hash:
        for i in attachments:
            if i.get("content_transfer_encoding") == "base64":
                payload = i["payload"].decode("base64")
            else:
                payload = i["payload"]

            i["md5"], i["sha1"], i["sha256"], i["sha512"] = \
                fingerprints(payload)

    for i in attachments:
        safe_print(json.dumps(i, ensure_ascii=False, indent=4))
