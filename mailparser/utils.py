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
from email.errors import HeaderParseError
from email.header import decode_header
from unicodedata import normalize
import logging
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

    if six.PY2:
        try:
            return six.text_type(raw_data, encoding, errors).strip()
        except LookupError:
            return six.text_type(raw_data, "utf-8", errors).strip()

    elif six.PY3:
        if isinstance(raw_data, str):
            return raw_data.strip()
        else:
            try:
                return six.text_type(raw_data, encoding).strip()
            except LookupError:
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
