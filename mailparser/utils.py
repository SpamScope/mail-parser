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

from collections import namedtuple
from email.errors import HeaderParseError
from email.header import decode_header
from unicodedata import normalize
import hashlib
import logging
import os
import subprocess
import tempfile

import six


log = logging.getLogger(__name__)


def sanitize(func):
    """ NFC is the normalization form recommended by W3C. """

    def wrapper(*args, **kwargs):
        return normalize('NFC', func(*args, **kwargs))
    return wrapper


@sanitize
def ported_string(raw_data, encoding='utf-8', errors='ignore'):
    """ Give as input raw data and output a str in Python 3
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
    output = six.text_type()

    try:
        for d, c in decode_header(header):
            c = c if c else 'utf-8'
            output += ported_string(d, c, 'ignore')

    # Header parsing failed, when header has charset Shift_JIS
    except HeaderParseError:
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
    """This function return the fingerprints of data.

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
    """Exec msgconvert tool, to convert msg Outlook
    mail in eml mail format

    Args:
        email (string): file path of Outlook msg mail

    Return:
        tuple with file path of mail converted and
        standard output data (unicode Python 2, str Python 3)
    """
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
        raise OSError(message)

    else:
        stdoutdata, _ = out.communicate()
        return temp, stdoutdata.decode("utf-8").strip()
