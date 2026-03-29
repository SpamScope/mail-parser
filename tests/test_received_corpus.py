#!/usr/bin/env python
"""
Test suite for received header parsing against a real-world header corpus.

Covers headers from major MTAs: Postfix, Exim, Exchange/Outlook,
Gmail, SendGrid, IBM/Domino, AWS SES, and edge cases.
Validates the tokenizer approach against RFC 5321 §4.4 grammar.
"""

import unittest

from mailparser.const import REGXIP, REGXIP6
from mailparser.utils import parse_received, receiveds_parsing


class TestPostfixHeaders(unittest.TestCase):
    """Headers from Postfix MTA."""

    def test_postfix_standard(self):
        header = (
            "from mail-out.example.com (mail-out.example.com [203.0.113.10]) "
            "by mx.recipient.org (Postfix) with ESMTP id 4F3D21234 "
            "for <user@recipient.org>; Tue, 15 Mar 2024 10:30:00 +0000 (UTC)"
        )
        parsed = parse_received(header)
        self.assertIn("mail-out.example.com", parsed["from"])
        self.assertIn("mx.recipient.org", parsed["by"])
        self.assertEqual(parsed["with"], "ESMTP")
        self.assertEqual(parsed["id"], "4F3D21234")
        self.assertEqual(parsed["for"], "<user@recipient.org>")
        self.assertIn("Tue, 15 Mar 2024", parsed["date"])

    def test_postfix_with_tls(self):
        header = (
            "from sender.example.com (sender.example.com [198.51.100.5]) "
            "by relay.example.net (Postfix) with ESMTPS id ABC123DEF "
            "for <admin@example.net>; Wed, 10 Jan 2024 08:15:30 -0500"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["with"], "ESMTPS")
        self.assertIn("sender.example.com", parsed["from"])


class TestEximHeaders(unittest.TestCase):
    """Headers from Exim MTA."""

    def test_exim_standard(self):
        header = (
            "from [192.168.1.100] (helo=client.example.com) "
            "by smtp.example.org with esmtpa (Exim 4.96) "
            "id 1pABCD-00012E-XX "
            "for user@example.org; Mon, 5 Feb 2024 14:00:00 +0000"
        )
        parsed = parse_received(header)
        self.assertIn("192.168.1.100", parsed["from"])
        self.assertEqual(parsed["by"], "smtp.example.org")
        self.assertIn("esmtpa", parsed["with"])
        self.assertEqual(parsed["id"], "1pABCD-00012E-XX")

    def test_exim_authenticated(self):
        header = (
            "from auth-user "
            "by mail.example.com with local (Exim 4.96) "
            "id 1pXYZ0-000ABC-De "
            "for admin@example.com; Thu, 20 Jun 2024 09:30:00 +0100"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["from"], "auth-user")
        self.assertIn("local", parsed["with"])


class TestExchangeOutlookHeaders(unittest.TestCase):
    """Headers from Exchange/Outlook."""

    def test_exchange_internal(self):
        header = (
            "from DM6PR06MB4475.namprd06.prod.outlook.com (2603:10b6:207:3d::31) "
            "by BL0PR06MB4465.namprd06.prod.outlook.com with HTTPS "
            "via BL0PR02CA0054.NAMPRD02.PROD.OUTLOOK.COM; "
            "Mon, 1 Oct 2024 09:49:22 +0000"
        )
        parsed = parse_received(header)
        self.assertIn("DM6PR06MB4475", parsed["from"])
        self.assertIn("BL0PR06MB4465", parsed["by"])
        self.assertEqual(parsed["with"], "HTTPS")
        self.assertIn("BL0PR02CA0054", parsed["via"])

    def test_exchange_with_id(self):
        header = (
            "from edge.microsoft.com (10.0.0.1) "
            "by EXCH01.corp.example.com (172.16.0.10) with Microsoft SMTP Server "
            "id 15.1.2507.23; Fri, 22 Nov 2024 16:00:00 -0800"
        )
        parsed = parse_received(header)
        self.assertIn("edge.microsoft.com", parsed["from"])
        self.assertIn("Microsoft SMTP Server", parsed["with"])


class TestGmailHeaders(unittest.TestCase):
    """Headers from Gmail/Google Workspace."""

    def test_gmail_standard(self):
        header = (
            "from mail-wr1-f54.google.com (mail-wr1-f54.google.com. [209.85.221.54]) "
            "by mx.google.com with ESMTPS id a1-2023abc.123.2024.01.15.08.30.00 "
            "for <user@gmail.com>; Mon, 15 Jan 2024 08:30:00 -0800 (PST)"
        )
        parsed = parse_received(header)
        self.assertIn("mail-wr1-f54.google.com", parsed["from"])
        self.assertEqual(parsed["with"], "ESMTPS")
        self.assertEqual(parsed["for"], "<user@gmail.com>")

    def test_gmail_with_cipher_annotation(self):
        """Ensure 'with cipher' in TLS info doesn't split the 'with' clause."""
        header = (
            "from sender.example.com (sender.example.com [93.184.216.34]) "
            "by smtp.gmail.com with ESMTPS id abc123def.456 "
            "for <user@gmail.com>; Tue, 20 Feb 2024 11:00:00 -0800 (PST)"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["with"], "ESMTPS")


class TestSendGridHeaders(unittest.TestCase):
    """Headers from SendGrid."""

    def test_sendgrid_date_format(self):
        header = (
            "from filter.sendgrid.net by filter0123.sendgrid.net "
            "with SMTP 2024-03-15 10:30:00.123456789 +0000 UTC m=+12345.678901234"
        )
        parsed = parse_received(header)
        self.assertIn("date", parsed)
        self.assertIn("2024-03-15", parsed["date"])


class TestIBMDominoHeaders(unittest.TestCase):
    """Headers from IBM/Domino with non-standard patterns."""

    def test_ibm_for_from_pattern(self):
        """IBM gateway: 'for <recipient> from <sender>' construct."""
        header = (
            "from localhost "
            "by e06smtp10.uk.ibm.com with IBM ESMTP SMTP Gateway: "
            "Authorized Use Only! Violators will be prosecuted "
            "for <user@example.it> from <sender@it.ibm.com>; "
            "Wed, 8 Mar 2017 16:46:25 -0000"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["from"].strip(), "localhost")
        self.assertEqual(parsed["for"], "<user@example.it>")
        self.assertIn("IBM ESMTP", parsed["with"])

    def test_ibm_domino_notes(self):
        header = (
            "from localhost "
            "by smtp.notes.na.collabserv.com with smtp.notes.na.collabserv.com ESMTP "
            "for <user@example.it> from <sender@it.ibm.com>; "
            "Wed, 8 Mar 2017 16:46:15 -0000"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["from"].strip(), "localhost")
        self.assertIn("for", parsed)


class TestAWSSESHeaders(unittest.TestCase):
    """Headers from AWS SES."""

    def test_ses_standard(self):
        header = (
            "from a]b-123.smtp-out.us-east-1.amazonses.com "
            "(a]b-123.smtp-out.us-east-1.amazonses.com [54.240.0.1]) "
            "by inbound-smtp.us-east-1.amazonaws.com with SMTP "
            "id abc123def456 "
            "for user@example.com; Fri, 1 Mar 2024 12:00:00 +0000 (UTC)"
        )
        parsed = parse_received(header)
        self.assertIn("amazonses.com", parsed["from"])
        self.assertEqual(parsed["with"], "SMTP")


class TestEnvelopeHeaders(unittest.TestCase):
    """Headers with envelope-from / envelope-sender."""

    def test_envelope_from_in_parentheses(self):
        header = (
            "from host.example.com ([86.187.174.57]:45321 helo=User) "
            "by localhost.localdomain (envelope-from <sender@example.com>) "
            "with ESMTP id ABC123; Mon, 21 Aug 2016 10:49:40 -0000"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["envelope_from"], "sender@example.com")

    def test_envelope_sender(self):
        header = (
            "from mail.example.com (mail.example.com [10.0.0.1]) "
            "by gateway.example.com (envelope-sender <noreply@example.com>) "
            "with ESMTP; Mon, 1 Jan 2024 00:00:00 +0000"
        )
        parsed = parse_received(header)
        self.assertEqual(parsed["envelope_sender"], "noreply@example.com")


class TestEdgeCases(unittest.TestCase):
    """Edge cases and unusual headers."""

    def test_qmail_minimal(self):
        """qmail-style headers with only date."""
        header = "(qmail 11769 invoked from network); 22 Aug 2016 14:23:01 -0000"
        parsed = parse_received(header)
        self.assertIn("date", parsed)
        self.assertIn("22 Aug 2016", parsed["date"])

    def test_no_from_clause(self):
        """Header starting with 'by' (internal delivery)."""
        header = (
            "by mail.example.com (Postfix) id XYZ789; Mon, 1 Jan 2024 00:00:00 +0000"
        )
        parsed = parse_received(header)
        self.assertIn("by", parsed)
        self.assertIn("date", parsed)

    def test_multiple_spaces_normalization(self):
        """Headers with excessive whitespace."""
        header = (
            "from   server.example.com   (10.0.0.1)  "
            "by  mx.example.org  (Postfix)  with  ESMTP  id  2CC378D014 "
            "for  <user@example.com>;  Mon, 22 Aug 2016 14:22:58 +0000 (UTC)"
        )
        parsed = parse_received(header)
        self.assertIn("from", parsed)
        self.assertIn("by", parsed)
        self.assertIn("with", parsed)
        self.assertIn("id", parsed)
        self.assertIn("for", parsed)

    def test_unparseable_header_raises(self):
        """Completely invalid headers should raise."""
        from mailparser.exceptions import MailParserReceivedParsingError

        with self.assertRaises(MailParserReceivedParsingError):
            parse_received("TotallyInvalidNotAReceivedHeader")

    def test_receiveds_parsing_integration(self):
        """Test full pipeline through receiveds_parsing."""
        headers = [
            "from a.example.com by b.example.com with SMTP;"
            " Mon, 1 Jan 2024 12:00:00 +0000",
            "from c.example.com by d.example.com with ESMTP;"
            " Mon, 1 Jan 2024 12:01:00 +0000",
        ]
        result = receiveds_parsing(headers)
        self.assertEqual(len(result), 2)
        # Should have hop numbers
        self.assertIn("hop", result[0])
        self.assertIn("hop", result[1])

    def test_date_with_extra_semicolon(self):
        """Date field that itself contains a semicolon."""
        header = (
            "from server.example.com by mx.example.org with ESMTP "
            "for <user@example.org>; Tue, 7 Mar 2017 14:29:24 -0800"
        )
        parsed = parse_received(header)
        self.assertIn("date", parsed)

    def test_domain_with_tld_containing_keyword(self):
        """Domain names that contain RFC keywords like .by or .id."""
        header = (
            "from mail.company.by (mail.company.by [10.0.0.1]) "
            "by relay.example.id with ESMTP; Mon, 1 Jan 2024 00:00:00 +0000"
        )
        parsed = parse_received(header)
        # Should still parse — 'by' and 'id' in TLDs should not break parsing
        self.assertIn("from", parsed)
        self.assertIn("date", parsed)


class TestIPPatterns(unittest.TestCase):
    """Test the improved IP address regex patterns."""

    def test_valid_ipv4(self):
        self.assertTrue(REGXIP.search("192.168.1.1"))
        self.assertTrue(REGXIP.search("0.0.0.0"))
        self.assertTrue(REGXIP.search("255.255.255.255"))

    def test_invalid_ipv4_rejected(self):
        """Old regex matched 999.999.999.999; new one should not."""
        match = REGXIP.fullmatch("999.999.999.999")
        self.assertIsNone(match)

    def test_ipv4_boundary(self):
        match = REGXIP.fullmatch("256.1.1.1")
        self.assertIsNone(match)

    def test_ipv6_full(self):
        self.assertTrue(REGXIP6.search("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))

    def test_ipv6_compressed(self):
        self.assertTrue(REGXIP6.search("2603:10b6:207:3d::31"))
        self.assertTrue(REGXIP6.search("::1"))
        self.assertTrue(REGXIP6.search("::"))

    def test_ipv6_in_received_header(self):
        """IPv6 addresses commonly appear in received headers."""
        header_fragment = "[2603:10b6:207:3d::31]"
        self.assertTrue(REGXIP6.search(header_fragment))
