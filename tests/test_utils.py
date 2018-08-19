import unittest

from mailparser.utils import receiveds_parsing


class TestMain(unittest.TestCase):
    def test_parse_receiveds(self):
        receiveds = [
            'from mail4.zenbox.pl ([178.216.200.157])\r\n\tby storage-s7.zenbox.pl with LMTP id yCnCFLTtY1ttfAAAAFecNw\r\n\t; Fri, 03 Aug 2018 07:52:52 +0200',
            'from mail4.zenbox.pl\r\n\tby mail4.zenbox.pl with LMTP id gOI9FLTtY1t/dgAAhAUF9A\r\n\t; Fri, 03 Aug 2018 07:52:52 +0200',
            'from mail4.zenbox.pl (ip-178-216-200-157.e24cloud.com [127.0.0.1])\r\n\tby mail4.zenbox.pl (Postfix) with ESMTP id DCF081800BA9;\r\n\tFri,  3 Aug 2018 07:52:51 +0200 (CEST)',
            'from mail4.zenbox.pl ([127.0.0.1])\r\n\tby mail4.zenbox.pl (mail4.zenbox.pl [127.0.0.1]) (amavisd-new, port 10024)\r\n\twith ESMTP id 2SHK402wv_BW; Fri,  3 Aug 2018 07:52:27 +0200 (CEST)',
            'from email10.um.zabrze.pl (email10.um.zabrze.pl [91.237.171.5])\r\n\tby mail4.zenbox.pl (Postfix) with ESMTPS id 95175180012E\r\n\tfor <9288@fedrowanie.siecobywatelska.pl>; Fri,  3 Aug 2018 07:52:22 +0200 (CEST)',
            'from EMAIL10.um.zabrze.pl ([::1]) by email10.um.zabrze.pl ([::1])\r\n with mapi id 14.03.0123.003; Fri, 3 Aug 2018 07:52:17 +0200'
        ]
        expected_result = [
            {'by': 'email10.um.zabrze.pl ::1', 'delay': 0, 'from': 'EMAIL10.um.zabrze.pl ::1', 'hop': 1},
            {'delay': 0, 'from': 'email10.um.zabrze.pl email10.um.zabrze.pl 91.237.171.5', 'hop': 2},
            {'delay': 0, 'from': 'mail4.zenbox.pl 127.0.0.1', 'hop': 3},
            {'delay': 0, 'from': 'mail4.zenbox.pl ip-178-216-200-157.e24cloud.com 127.0.0.1', 'hop': 4},
            {'delay': 0, 'from': 'mail4.zenbox.pl', 'hop': 5, 'for': '<9288@fedrowanie.siecobywatelska.pl>'},
            {'delay': 0, 'from': 'mail4.zenbox.pl 178.216.200.157', 'hop': 6}
        ]

        result = receiveds_parsing(receiveds)

        self.assertListEqual(expected_result, result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
