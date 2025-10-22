#!/usr/bin/env python
"""
Test cases for improved RECEIVED_PATTERNS regex.

This test module specifically validates the fixes made to RECEIVED_PATTERNS
to handle edge cases that were previously causing parsing failures.

Key improvements:
1. Fixed duplicate "from" matches in headers with "for <email> from <email>"
2. Better separation of 'by' and 'with' clauses
3. More precise boundary detection for all clauses
"""

import unittest

from mailparser.utils import parse_received


class TestImprovedReceivedPatterns(unittest.TestCase):
    """Test cases for improved received header parsing."""

    def test_ibm_gateway_header_with_for_from_pattern(self):
        """
        Test IBM gateway headers with 'for <email> from <email>' pattern.

        These headers previously caused "More than one match found for 'from'"
        errors because the regex matched both the actual 'from' clause and
        the 'from' keyword within the 'for <email> from <email>' construct.
        """
        # ruff: noqa: E501
        header = """from localhost
        by e06smtp10.uk.ibm.com with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted
        for <lina.vailati@dududu.it> from <nicoletta_bernasconi@it.ibm.com>;
        Wed, 8 Mar 2017 16:46:25 -0000"""

        # Should parse without raising MailParserReceivedParsingError
        parsed = parse_received(header)

        # Validate extracted fields
        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("for", parsed)
        self.assertIn("date", parsed)

        # Validate field values
        self.assertEqual(parsed["from"].strip(), "localhost")
        self.assertEqual(parsed["for"], "<lina.vailati@dududu.it>")
        self.assertIn("Wed, 8 Mar 2017 16:46:25 -0000", parsed["date"])

    def test_ibm_gateway_variant_with_esmtp_details(self):
        """
        Test another IBM gateway variant with detailed ESMTP information.
        """
        header = """from localhost
        by smtp.notes.na.collabserv.com with smtp.notes.na.collabserv.com ESMTP
        for <lina.vailati@dududu.it> from <nicoletta_bernasconi@it.ibm.com>;
        Wed, 8 Mar 2017 16:46:15 -0000"""

        parsed = parse_received(header)

        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("for", parsed)
        self.assertEqual(parsed["from"].strip(), "localhost")
        self.assertEqual(parsed["for"], "<lina.vailati@dududu.it>")

    def test_standard_header_with_helo(self):
        """
        Test standard received header with HELO information.

        This is a common, well-formed header that should continue to work.
        """
        # ruff: noqa: E501
        header = """from smtprelay0207.b.hostedemail.com (HELO smtprelay.b.hostedemail.com) (64.98.42.207)
  by smtp.server.net with SMTP; 22 Aug 2016 14:23:01 -0000"""

        parsed = parse_received(header)

        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("date", parsed)

        # Verify 'from' captures the full server information
        self.assertIn("smtprelay0207.b.hostedemail.com", parsed["from"])
        self.assertIn("HELO", parsed["from"])

        # Verify 'by' and 'with' are separate
        self.assertEqual(parsed["by"].strip(), "smtp.server.net")
        self.assertEqual(parsed["with"].strip(), "SMTP")

    def test_header_with_envelope_from(self):
        """
        Test header with envelope-from clause.
        """
        # ruff: noqa: E501
        header = """from host86-187-174-57.range86-187.btcentralplus.com ([86.187.174.57]:45321 helo=User)
        by localhost.localdomain (envelope-from <sender@example.com>)
        with ESMTP id ABC123; Mon, 21 Aug 2016 10:49:40 -0000"""

        parsed = parse_received(header)

        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("id", parsed)
        self.assertIn("envelope_from", parsed)
        self.assertEqual(parsed["envelope_from"], "sender@example.com")

    def test_header_with_via_clause(self):
        """
        Test header with via clause.
        """
        header = """from DM6PR06MB4475.namprd06.prod.outlook.com (2603:10b6:207:3d::31)
 by BL0PR06MB4465.namprd06.prod.outlook.com with HTTPS id 12345 via
 BL0PR02CA0054.NAMPRD02.PROD.OUTLOOK.COM; Mon, 1 Oct 2018 09:49:22 +0000"""

        parsed = parse_received(header)

        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("id", parsed)
        self.assertIn("via", parsed)

    def test_minimal_header_with_only_date(self):
        """
        Test minimal header with only date (qmail invoked headers).
        """
        header = "(qmail 11769 invoked from network); 22 Aug 2016 14:23:01 -0000"

        parsed = parse_received(header)

        # Should at least extract the date
        self.assertIn("date", parsed)
        self.assertIn("22 Aug 2016 14:23:01 -0000", parsed["date"])

    def test_header_with_multiple_spaces_and_newlines(self):
        """
        Test that headers with irregular whitespace are handled correctly.
        """
        # ruff: noqa: E501
        header = """from   filter.hostedemail.com  (10.5.19.248.rfc1918.com [10.5.19.248])
        by  smtprelay06.b.hostedemail.com  (Postfix)  with  ESMTP  id  2CC378D014
        for  <kinney@noth.com>;  Mon, 22 Aug 2016 14:22:58 +0000 (UTC)"""

        parsed = parse_received(header)

        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("id", parsed)
        self.assertIn("for", parsed)
        self.assertIn("date", parsed)

    def test_received_complex_edge_case(self):
        """Test complex received header with multiple patterns"""
        received = (
            "from mail-server.example.com (mail-server.example.com [192.0.2.1]) "
            "by mx.example.org (Postfix) with ESMTP id ABC123 "
            "for <user@example.org>; Mon, 1 Jan 2024 12:00:00 +0000"
        )
        parsed = parse_received(received)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed, dict)
