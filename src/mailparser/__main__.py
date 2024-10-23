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

import argparse
import os
import runpy
import sys

import mailparser
from .exceptions import MailParserOutlookError
from .utils import (
    custom_log,
    print_attachments,
    print_mail_fingerprints,
    safe_print,
    write_attachments,
)


current = os.path.realpath(os.path.dirname(__file__))

__version__ = runpy.run_path(
    os.path.join(current, "version.py"))["__version__"]


def get_args():
    parser = argparse.ArgumentParser(
        description="Wrapper for email Python Standard Library",
        epilog="It takes as input a raw mail and generates a parsed object.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parsing_group = parser.add_mutually_exclusive_group(required=True)
    parsing_group.add_argument(
        "-f",
        "--file",
        dest="file",
        help="Raw email file")
    parsing_group.add_argument(
        "-s",
        "--string",
        dest="string",
        help="Raw email string")
    parsing_group.add_argument(
        "-k",
        "--stdin",
        dest="stdin",
        action="store_true",
        help="Enable parsing from stdin")

    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="WARNING",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="Set log level")

    parser.add_argument(
        "-j",
        "--json",
        dest="json",
        action="store_true",
        help="Show the JSON of parsed mail")

    parser.add_argument(
        "-b",
        "--body",
        dest="body",
        action="store_true",
        help="Print the body of mail")

    parser.add_argument(
        "-a",
        "--attachments",
        dest="attachments",
        action="store_true",
        help="Print the attachments of mail")

    parser.add_argument(
        "-r",
        "--headers",
        dest="headers",
        action="store_true",
        help="Print the headers of mail")

    parser.add_argument(
        "-t",
        "--to",
        dest="to",
        action="store_true",
        help="Print the to of mail")

    parser.add_argument(
        "-dt",
        "--delivered-to",
        dest="delivered_to",
        action="store_true",
        help="Print the delivered-to of mail")

    parser.add_argument(
        "-m",
        "--from",
        dest="from_",
        action="store_true",
        help="Print the from of mail")

    parser.add_argument(
        "-u",
        "--subject",
        dest="subject",
        action="store_true",
        help="Print the subject of mail")

    parser.add_argument(
        "-c",
        "--receiveds",
        dest="receiveds",
        action="store_true",
        help="Print all receiveds of mail")

    parser.add_argument(
        "-d",
        "--defects",
        dest="defects",
        action="store_true",
        help="Print the defects of mail")

    parser.add_argument(
        "-o",
        "--outlook",
        dest="outlook",
        action="store_true",
        help="Analyze Outlook msg")

    parser.add_argument(
        "-i",
        "--senderip",
        dest="senderip",
        metavar="Trust mail server string",
        help="Extract a reliable sender IP address heuristically")

    parser.add_argument(
        "-p",
        "--mail-hash",
        dest="mail_hash",
        action="store_true",
        help="Print mail fingerprints without headers")

    parser.add_argument(
        "-z",
        "--attachments-hash",
        dest="attachments_hash",
        action="store_true",
        help="Print attachments with fingerprints")

    parser.add_argument(
        "-sa",
        "--store-attachments",
        dest="store_attachments",
        action="store_true",
        help="Store attachments on disk")

    parser.add_argument(
        "-ap",
        "--attachments-path",
        dest="attachments_path",
        default="/tmp",
        help="Path where store attachments")

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='%(prog)s {}'.format(__version__))

    return parser


def main():
    args = get_args().parse_args()
    log = custom_log(level=args.log_level)

    if args.file:
        if args.outlook:
            log.debug("Analysis Outlook mail")
            parser = mailparser.parse_from_file_msg(args.file)
        else:
            parser = mailparser.parse_from_file(args.file)
    elif args.string:
        parser = mailparser.parse_from_string(args.string)
    elif args.stdin:
        if args.outlook:
            raise MailParserOutlookError(
                "You can't use stdin with msg Outlook")
        parser = mailparser.parse_from_file_obj(sys.stdin)

    if args.json:
        safe_print(parser.mail_json)

    if args.body:
        safe_print(parser.body)

    if args.headers:
        safe_print(parser.headers_json)

    if args.to:
        safe_print(parser.to_json)

    if args.delivered_to:
        safe_print(parser.delivered_to_json)

    if args.from_:
        safe_print(parser.from_json)

    if args.subject:
        safe_print(parser.subject)

    if args.receiveds:
        safe_print(parser.received_json)

    if args.defects:
        log.debug("Printing defects")
        for i in parser.defects_categories:
            safe_print(i)

    if args.senderip:
        log.debug("Printing sender IP")
        r = parser.get_server_ipaddress(args.senderip)
        if r:
            safe_print(r)
        else:
            safe_print("Not Found")

    if args.attachments or args.attachments_hash:
        log.debug("Printing attachments details")
        print_attachments(parser.attachments, args.attachments_hash)

    if args.mail_hash:
        log.debug("Printing also mail fingerprints")
        print_mail_fingerprints(parser.body.encode("utf-8"))

    if args.store_attachments:
        log.debug("Store attachments on disk")
        write_attachments(parser.attachments, args.attachments_path)


if __name__ == '__main__':
    main()
