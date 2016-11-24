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
from .exceptions import InvalidMail, NotUnicodeError
from email.errors import HeaderParseError
from email.header import decode_header
import datetime
import email
import ipaddress
import logging
import re
import time

try:
    import simplejson as json
except ImportError:
    import json

log = logging.getLogger(__name__)


class MailParser(object):
    """Tokenizer for raw mails. """

    def __init__(self):
        # With these defect bad payload is on epilogue
        self._epilogue_defects = set([
            "StartBoundaryNotFoundDefect"])

    def parse_from_file(self, fd):
        """Parsing mail from file. """

        with open(fd) as mail:
            self._message = email.message_from_file(mail)
            self._parse()

    def parse_from_string(self, s):
        """Parsing mail from string. """

        self._message = email.message_from_string(s)
        self._parse()

    def _decode_header_part(self, header):
        output = u''

        try:
            for i in decode_header(header):
                if i[1]:
                    output += unicode(i[0], i[1], errors='ignore').strip()
                else:
                    output += unicode(i[0], errors='ignore').strip()

        # Header parsing failed, when header has charset Shift_JIS
        except HeaderParseError:
            log.error("Failed decoding header part: {}".format(header))
            output += header

        if not isinstance(output, unicode):
            raise NotUnicodeError("Header part is not unicode")

        return output

    def _force_unicode(self, string, encoding):
        try:
            u = unicode(string, encoding=encoding, errors='ignore')
        except:
            u = unicode(string, errors='ignore',)

        if not isinstance(u, unicode):
            raise NotUnicodeError("Body part is not unicode")

        return u

    def _append_defects(self, part, part_content_type):
        part_defects = {}

        for e in part.defects:
            defects = "{}: {}".format(e.__class__.__name__, e.__doc__)
            self._defects_category.add(e.__class__.__name__)

            if part_defects:
                part_defects[part_content_type].append(defects)
            else:
                part_defects[part_content_type] = [defects]

        # Tag mail with defect
        if part_defects:
            self._has_defects = True

            # Save all defects
            self._defects.append(part_defects)

    def _reset(self):
        self._attachments = list()
        self._text_plain = list()
        self._defects = list()
        self._defects_category = set()
        self._has_defects = False
        self._has_anomalies = False
        self._anomalies = list()

    def _make_mail(self):
        self._mail = {
            "attachments": self.attachments_list,
            "body": self.body,
            "date": self.date_mail,
            "from": self.from_,
            "headers": self.headers,
            "message_id": self.message_id,
            "subject": self.subject,
            "to": self.to_,
            "has_defects": self._has_defects,
            "has_anomalies": self._has_anomalies,
        }

    def _parse(self):
        if not self._message.keys():
            raise InvalidMail("Mail without headers: {}".format(
                self._message.as_string()))

        # Reset for new mail
        self._reset()
        parts = list()  # Normal parts plus defects

        # walk all mail parts to search defects
        for p in self._message.walk():
            part_content_type = p.get_content_type()
            self._append_defects(p, part_content_type)
            parts.append(p)

        # If defects are in epilogue defects get epilogue
        if self._epilogue_defects & self._defects_category:
            epilogue = self.find_between(
                self._message.epilogue,
                "{}".format("--" + self._message.get_boundary()),
                "{}".format("--" + self._message.get_boundary() + "--"))

            try:
                p = email.message_from_string(epilogue)
                parts.append(p)
            except:
                log.error("Failed to get epilogue part")

        # walk all mail parts
        for p in parts:
            if not p.is_multipart():
                f = p.get_filename()
                charset = p.get_content_charset('utf-8')

                if f:
                    filename = self._decode_header_part(f)
                    mail_content_type = self._decode_header_part(
                        p.get_content_type())
                    transfer_encoding = \
                        unicode(p.get('content-transfer-encoding', '')).lower()

                    if transfer_encoding == "base64":
                        payload = p.get_payload(decode=False)
                    else:
                        payload = self._force_unicode(
                            string=p.get_payload(decode=True),
                            encoding=charset)

                    self._attachments.append(
                        {
                            "filename": filename,
                            "payload": payload,
                            "mail_content_type": mail_content_type,
                            "content_transfer_encoding": transfer_encoding,
                        }
                    )
                else:
                    payload = self._force_unicode(
                        string=p.get_payload(decode=True),
                        encoding=charset)
                    self._text_plain.append(payload)

        # Parsed object mail
        self._make_mail()

        # Add defects
        if self.has_defects:
            self._mail["defects"] = self.defects
            self._mail["defects_category"] = list(self._defects_category)

        # Add anomalies
        if self.has_anomalies:
            self._mail["anomalies"] = self.anomalies
            self._mail["has_anomalies"] = True

    def find_between(self, text, first_token, last_token):
        try:
            start = text.index(first_token) + len(first_token)
            end = text.index(last_token, start)
            return text[start:end].strip()
        except ValueError:
            return

    def get_server_ipaddress(self, trust):
        """ Return ip address  of sender

        Extract a reliable sender IP address heuristically for each message.
        Although the message format dictates a chain of relaying IP
        addresses in each message, a malicious relay can easily alter that.
        Therefore we cannot simply take the first IP in
        the chain. Instead, our method is as follows.
        First we trust the sender IP reported by our mail server in the
        Received headers, and if the previous relay IP address is on our trust
        list (e.g. other well-known mail services), we continue to
        follow the previous Received line, till we reach the first unrecognized
        IP address in the email header.

        From article Characterizing Botnets from Email Spam Records:
            Li Zhuang, J. D. Tygar

        In our case we trust only our mail server with the trust string.


        Keyword arguments:
            trust -- String that identify our mail server
        """

        received = self._message.get_all("received", [])
        r = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

        for i in received:
            if trust in i:
                check = r.findall(i[0:i.find("by")])
                if check:
                    try:
                        ip = ipaddress.ip_address(unicode(check[-1]))
                    except ValueError:
                        return

                    if not ip.is_private:
                        return unicode(check[-1])

    @property
    def body(self):
        return "\n".join(self.text_plain_list)

    @property
    def headers(self):
        s = ""
        for k, v in self._message.items():
            v_u = self._decode_header_part(v)
            s += k + " " + v_u + "\n"
        return s

    @property
    def message_id(self):
        message_id = self._message.get('message-id', None)
        if not message_id:
            self._anomalies.append('mail_without_message-id')
            return None
        else:
            return self._decode_header_part(message_id)

    @property
    def to_(self):
        return self._decode_header_part(
            self._message.get('to', self._message.get('delivered-to')))

    @property
    def from_(self):
        return self._decode_header_part(
            self._message.get('from'))

    @property
    def subject(self):
        return self._decode_header_part(
            self._message.get('subject'))

    @property
    def text_plain_list(self):
        return self._text_plain

    @property
    def attachments_list(self):
        return self._attachments

    @property
    def date_mail(self):
        date_ = self._message.get('date')

        if not date_:
            self._anomalies.append('mail_without_date')
            return None

        try:
            d = email.utils.parsedate(date_)
            t = time.mktime(d)
            return datetime.datetime.utcfromtimestamp(t)
        except:
            return None

    @property
    def parsed_mail_obj(self):
        return self._mail

    @property
    def parsed_mail_json(self):
        self._mail["date"] = self.date_mail.isoformat() \
            if self.date_mail else ""
        return json.dumps(
            self._mail,
            ensure_ascii=False,
            indent=None)

    @property
    def defects(self):
        """The defects property contains a list of
        all the problems found when parsing this message.
        """
        return self._defects

    @property
    def defects_category(self):
        """Return a list with only defects categories. """
        return self._defects_category

    @property
    def has_defects(self):
        """Boolean: True if mail has defects. """
        return self._has_defects

    @property
    def anomalies(self):
        """The anomalies property contains a list of
        all anomalies in mail:
            - mail_without_date
            - mail_without_message-id
        """
        return self._anomalies

    @property
    def has_anomalies(self):
        if self.anomalies:
            return True
        else:
            return False
