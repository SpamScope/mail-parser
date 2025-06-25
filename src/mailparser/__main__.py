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
import logging
import sys

import mailparser
from mailparser.exceptions import MailParserOutlookError
from mailparser.utils import (
    custom_log,
    print_attachments,
    print_mail_fingerprints,
    safe_print,
    write_attachments,
)
from mailparser.version import __version__


log = logging.getLogger("mailparser")


def get_args():
    """
    Get arguments from command line.
    :return: argparse.ArgumentParser
    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description="Wrapper for email Python Standard Library",
        epilog="It takes as input a raw mail and generates a parsed object.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parsing_group = parser.add_mutually_exclusive_group(required=True)
    parsing_group.add_argument("-f", "--file", dest="file", help="Raw email file")
    parsing_group.add_argument("-s", "--string", dest="string", help="Raw email string")
    parsing_group.add_argument(
        "-k",
        "--stdin",
        dest="stdin",
        action="store_true",
        help="Enable parsing from stdin",
    )

    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="WARNING",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        help="Set log level",
    )

    parser.add_argument(
        "-j",
        "--json",
        dest="json",
        action="store_true",
        help="Show the JSON of parsed mail",
    )

    parser.add_argument(
        "-b", "--body", dest="body", action="store_true", help="Print the body of mail"
    )

    parser.add_argument(
        "-a",
        "--attachments",
        dest="attachments",
        action="store_true",
        help="Print the attachments of mail",
    )

    parser.add_argument(
        "-r",
        "--headers",
        dest="headers",
        action="store_true",
        help="Print the headers of mail",
    )

    parser.add_argument(
        "-t", "--to", dest="to", action="store_true", help="Print the to of mail"
    )

    parser.add_argument(
        "-dt",
        "--delivered-to",
        dest="delivered_to",
        action="store_true",
        help="Print the delivered-to of mail",
    )

    parser.add_argument(
        "-m", "--from", dest="from_", action="store_true", help="Print the from of mail"
    )

    parser.add_argument(
        "-u",
        "--subject",
        dest="subject",
        action="store_true",
        help="Print the subject of mail",
    )

    parser.add_argument(
        "-c",
        "--receiveds",
        dest="receiveds",
        action="store_true",
        help="Print all receiveds of mail",
    )

    parser.add_argument(
        "-d",
        "--defects",
        dest="defects",
        action="store_true",
        help="Print the defects of mail",
    )

    parser.add_argument(
        "-o",
        "--outlook",
        dest="outlook",
        action="store_true",
        help="Analyze Outlook msg",
    )

    parser.add_argument(
        "-i",
        "--senderip",
        dest="senderip",
        metavar="Trust mail server string",
        help="Extract a reliable sender IP address heuristically",
    )

    parser.add_argument(
        "-p",
        "--mail-hash",
        dest="mail_hash",
        action="store_true",
        help="Print mail fingerprints without headers",
    )

    parser.add_argument(
        "-z",
        "--attachments-hash",
        dest="attachments_hash",
        action="store_true",
        help="Print attachments with fingerprints",
    )

    parser.add_argument(
        "-sa",
        "--store-attachments",
        dest="store_attachments",
        action="store_true",
        help="Store attachments on disk",
    )

    parser.add_argument(
        "-ap",
        "--attachments-path",
        dest="attachments_path",
        default="/tmp",
        help="Path where store attachments",
    )

    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s {}".format(__version__)
    )

    return parser


def main():
    """
    Main function.
    """
    args = get_args().parse_args()
    log = custom_log(level=args.log_level, name="mailparser")

    try:
        parser = get_parser(args)
        process_output(args, parser)
    except Exception as e:
        log.exception(f"An error occurred: {e}")
        sys.exit(1)


def get_parser(args):
    """
    Get the correct parser based on the input source.
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    :return: MailParser
    :rtype: mailparser.core.MailParser
    """
    if args.file:
        return parse_file(args)
    elif args.string:
        log.debug("Start analysis by string mail")
        return mailparser.parse_from_string(args.string)
    elif args.stdin:
        return parse_stdin(args)
    else:
        raise ValueError("No input source provided")


def parse_file(args):
    """
    Parse the file based on the arguments provided.
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    :return: MailParser
    :rtype: mailparser.core.MailParser
    """
    log.debug("Start analysis by file mail")
    if args.outlook:
        log.debug("Start analysis by Outlook msg")
        return mailparser.parse_from_file_msg(args.file)
    else:
        log.debug("Start analysis by raw mail")
        return mailparser.parse_from_file(args.file)


def parse_stdin(args):
    """
    Parse the stdin based on the arguments provided.
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    :return: MailParser
    :rtype: mailparser.core.MailParser
    """
    log.debug("Start analysis by stdin mail")
    if args.outlook:
        raise MailParserOutlookError("You can't use stdin with msg Outlook")
    return mailparser.parse_from_file_obj(sys.stdin)


def process_output(args, parser):
    """
    Process the output based on the arguments provided.
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    :param parser: MailParser
    :type parser: mailparser.core.MailParser
    :param log: logger
    :type log: logging.Logger
    """
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
        print_defects(parser)

    if args.senderip:
        print_sender_ip(parser, args)

    if args.attachments or args.attachments_hash:
        print_attachments_details(parser, args)

    if args.mail_hash:
        log.debug("Printing also mail fingerprints")
        print_mail_fingerprints(parser.body.encode("utf-8"))

    if args.store_attachments:
        log.debug("Store attachments on disk")
        write_attachments(parser.attachments, args.attachments_path)


def print_defects(parser):
    """
    Print email defects.
    :param parser: MailParser
    :type parser: mailparser.core.MailParser
    """
    log.debug("Printing defects")
    for defect in parser.defects_categories:
        safe_print(defect)


def print_sender_ip(parser, args):
    """
    Print sender IP address.
    :param parser: MailParser
    :type parser: mailparser.core.MailParser
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    """
    log.debug("Printing sender IP")
    sender_ip = parser.get_server_ipaddress(args.senderip)
    safe_print(sender_ip if sender_ip else "Not Found")


def print_attachments_details(parser, args):
    """
    Print attachments details.
    :param parser: MailParser
    :type parser: mailparser.core.MailParser
    :param args: argparse.Namespace
    :type args: argparse.Namespace
    """
    log.debug("Printing attachments details")
    print_attachments(parser.attachments, args.attachments_hash)


if __name__ == "__main__":  # pragma: no cover
    main()
