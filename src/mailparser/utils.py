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

import base64
import datetime
import email
import functools
import hashlib
import logging
import os
import random
import re
import json
import string
import subprocess
import sys
import tempfile

import six

from mailparser.const import (
    ADDRESSES_HEADERS,
    JUNK_PATTERN,
    OTHERS_PARTS,
    RECEIVED_COMPILED_LIST,
)

from mailparser.exceptions import MailParserOSError, MailParserReceivedParsingError


log = logging.getLogger(__name__)


def custom_log(level="WARNING", name=None):  # pragma: no cover
    """
    This function returns a custom logger.
    :param level: logging level
    :type level: str
    :param name: logger name
    :type name: str
    :return: logger
    """
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
        "%(lineno)d | "
        "%(levelname)s | "
        "%(message)s"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)
    return log


def sanitize(func):
    """NFC is the normalization form recommended by W3C."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return normalize("NFC", func(*args, **kwargs))

    return wrapper


@sanitize
def ported_string(raw_data, encoding="utf-8", errors="ignore"):
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
        return raw_data

    if six.PY2:
        try:
            return six.text_type(raw_data, encoding, errors)
        except LookupError:
            return six.text_type(raw_data, "utf-8", errors)

    if six.PY3:
        try:
            return six.text_type(raw_data, encoding)
        except (LookupError, UnicodeDecodeError):
            return six.text_type(raw_data, "utf-8", errors)


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
            c = c if c else "utf-8"
            output += ported_string(d, c, "ignore")

    # Header parsing failed, when header has charset Shift_JIS
    except (HeaderParseError, UnicodeError):
        log.error("Failed decoding header part: {}".format(header))
        output += header

    return output.strip()


def ported_open(file_):
    if six.PY2:
        return open(file_)
    elif six.PY3:
        return open(file_, encoding="utf-8", errors="ignore")


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

    hashes = namedtuple("Hashes", "md5 sha1 sha256 sha512")

    if not isinstance(data, six.binary_type):
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

    return hashes(md5, sha1, sha256, sha512)


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
    temph, temp = tempfile.mkstemp(prefix="outlook_")
    command = ["msgconvert", "--outfile", temp, email]

    try:
        if six.PY2:
            with open(os.devnull, "w") as devnull:
                out = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                )
        elif six.PY3:
            out = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

    except OSError as e:
        message = "Check if 'msgconvert' tool is installed / {!r}".format(e)
        log.exception(message)
        raise MailParserOSError(message)

    else:
        stdoutdata, _ = out.communicate()
        return temp, stdoutdata.decode("utf-8").strip()

    finally:
        os.close(temph)


def parse_received(received):
    """
    Parse a single received header.
    Return a dictionary of values by clause.

    Arguments:
        received {str} -- single received header

    Raises:
        MailParserReceivedParsingError -- Raised when a
            received header cannot be parsed

    Returns:
        dict -- values by clause
    """

    values_by_clause = {}
    for pattern in RECEIVED_COMPILED_LIST:
        matches = [match for match in pattern.finditer(received)]

        if len(matches) == 0:
            # no matches for this clause, but it's ok! keep going!
            log.debug("No matches found for %s in %s" % (pattern.pattern, received))
        elif len(matches) > 1:
            # uh, can't have more than one of each clause in a received.
            # so either there's more than one or the current regex is wrong
            msg = "More than one match found for %s in %s" % (pattern.pattern, received)
            log.error(msg)
            raise MailParserReceivedParsingError(msg)
        else:
            # otherwise we have one matching clause!
            log.debug("Found one match for %s in %s" % (pattern.pattern, received))
            match = matches[0].groupdict()
            if six.PY2:
                values_by_clause[match.keys()[0]] = match.values()[0]
            elif six.PY3:
                key = list(match.keys())[0]
                value = list(match.values())[0]
                values_by_clause[key] = value

    if len(values_by_clause) == 0:
        # we weren't able to match anything...
        msg = "Unable to match any clauses in %s" % (received)

        # Modification #1: Commenting the following log as
        # this raised exception is caught above and then
        # raw header is updated in response
        # We dont want to get so many errors in our error
        # logger as we are not even trying to parse the
        # received headers
        # Wanted to make it configurable via settiings,
        # but this package does not depend on django and
        # making configurable setting
        # will make it django dependent,
        # so better to keep it working with only python
        # dependent and on any framework of python
        # commenting it just for our use

        # log.error(msg)

        raise MailParserReceivedParsingError(msg)
    return values_by_clause


def receiveds_parsing(receiveds):
    """
    This function parses the receiveds headers.

    Args:
        receiveds (list): list of raw receiveds headers

    Returns:
        a list of parsed receiveds headers with first hop in first position
    """

    parsed = []
    receiveds = [re.sub(JUNK_PATTERN, " ", i).strip() for i in receiveds]
    n = len(receiveds)
    log.debug("Nr. of receiveds. {}".format(n))

    for idx, received in enumerate(receiveds):
        log.debug("Parsing received {}/{}".format(idx + 1, n))
        log.debug("Try to parse {!r}".format(received))
        try:
            # try to parse the current received header...
            values_by_clause = parse_received(received)
        except MailParserReceivedParsingError:
            # if we can't, let's append the raw
            parsed.append({"raw": received})
        else:
            # otherwise append the full values_by_clause dict
            parsed.append(values_by_clause)

    log.debug("len(receiveds) %s, len(parsed) %s" % (len(receiveds), len(parsed)))

    if len(receiveds) != len(parsed):
        # something really bad happened,
        # so just return raw receiveds with hop indices
        log.error(
            "len(receiveds): %s, len(parsed): %s, receiveds: %s, \
            parsed: %s"
            % (len(receiveds), len(parsed), receiveds, parsed)
        )
        return receiveds_not_parsed(receiveds)

    else:
        # all's good! we have parsed or raw receiveds for each received header
        return receiveds_format(parsed)


def convert_mail_date(date):
    """
    Convert a mail date in a datetime object.
    """
    log.debug("Date to parse: {!r}".format(date))
    d = email.utils.parsedate_tz(date)
    log.debug("Date parsed: {!r}".format(d))
    t = email.utils.mktime_tz(d)
    log.debug("Date parsed in timestamp: {!r}".format(t))
    date_utc = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    timezone = d[9] / 3600.0 if d[9] else 0
    timezone = "{:+.1f}".format(timezone)
    log.debug("Calculated timezone: {!r}".format(timezone))
    return date_utc, timezone


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
                j["date_utc"], _ = convert_mail_date(i["date"])
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

    for i in output:
        if i.get("date_utc"):
            i["date_utc"] = i["date_utc"].isoformat()
    return output


def get_to_domains(to=[], reply_to=[]):
    domains = set()
    for i in to + reply_to:
        try:
            domains.add(i[1].split("@")[-1].lower().strip())
        except KeyError:
            pass

    return list(domains)


def get_header(message, name):
    """
    Gets an email.message.Message and a header name and returns
    the mail header decoded with the correct charset.

    Args:
        message (email.message.Message): email message object
        name (string): header to get

    Returns:
        str if there is an header
        list if there are more than one
    """

    headers = message.get_all(name)
    log.debug("Getting header {!r}: {!r}".format(name, headers))
    if headers:
        headers = [decode_header_part(i) for i in headers]
        if len(headers) == 1:
            # in this case return a string
            return headers[0].strip()
        # in this case return a list
        return headers
    return six.text_type()


def get_mail_keys(message, complete=True):
    """
    Given an email.message.Message, return a set with all email parts to get

    Args:
        message (email.message.Message): email message object
        complete (bool): if True returns all email headers

    Returns:
        set with all email parts
    """

    if complete:
        log.debug("Get all headers")
        all_headers_keys = {i.lower() for i in message.keys()}
        all_parts = ADDRESSES_HEADERS | OTHERS_PARTS | all_headers_keys
    else:
        log.debug("Get only mains headers")
        all_parts = ADDRESSES_HEADERS | OTHERS_PARTS

    log.debug("All parts to get: {}".format(", ".join(all_parts)))
    return all_parts


def safe_print(data):  # pragma: no cover
    try:
        print(data)
    except UnicodeEncodeError:
        print(data.encode("utf-8"))


def print_mail_fingerprints(data):  # pragma: no cover
    md5, sha1, sha256, sha512 = fingerprints(data)
    print("md5:\t{}".format(md5))
    print("sha1:\t{}".format(sha1))
    print("sha256:\t{}".format(sha256))
    print("sha512:\t{}".format(sha512))


def print_attachments(attachments, flag_hash):  # pragma: no cover
    if flag_hash:
        for i in attachments:
            if i.get("content_transfer_encoding") == "base64":
                payload = base64.b64decode(i["payload"])
            else:
                payload = i["payload"]

            i["md5"], i["sha1"], i["sha256"], i["sha512"] = fingerprints(payload)

    for i in attachments:
        safe_print(json.dumps(i, ensure_ascii=False, indent=4))


def write_attachments(attachments, base_path):  # pragma: no cover
    for a in attachments:
        write_sample(
            binary=a["binary"],
            payload=a["payload"],
            path=base_path,
            filename=a["filename"],
        )


def write_sample(binary, payload, path, filename):  # pragma: no cover
    """
    This function writes a sample on file system.

    Args:
        binary (bool): True if it's a binary file
        payload: payload of sample, in base64 if it's a binary
        path (string): path of file
        filename (string): name of file
        hash_ (string): file hash
    """
    if not os.path.exists(path):
        os.makedirs(path)
    sample = os.path.join(path, filename)

    if binary:
        with open(sample, "wb") as f:
            f.write(base64.b64decode(payload))
    else:
        with open(sample, "w") as f:
            f.write(payload)


def random_string(string_length=10):
    """Generate a random string of fixed length

    Keyword Arguments:
        string_length {int} -- String length (default: {10})

    Returns:
        str -- Random string
    """
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(string_length))
