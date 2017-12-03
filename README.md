[![PyPI version](https://badge.fury.io/py/mail-parser.svg)](https://badge.fury.io/py/mail-parser)
[![Build Status](https://travis-ci.org/SpamScope/mail-parser.svg?branch=develop)](https://travis-ci.org/SpamScope/mail-parser)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![BCH compliance](https://bettercodehub.com/edge/badge/SpamScope/mail-parser?branch=develop)](https://bettercodehub.com/)

# mail-parser

## Overview

mail-parser is not only a wrapper for [email](https://docs.python.org/2/library/email.message.html) Python Standard Library.
It give you an easy way to pass from raw mail to Python object that you can use in your code.
It's the key module of [SpamScope](https://github.com/SpamScope/spamscope).

mail-parser can parse Outlook email format (.msg). To use this feature, you need to install `libemail-outlook-message-perl` package. For Debian based systems:

```
$ apt-get install libemail-outlook-message-perl
```

For more details:

```
$ apt-cache show libemail-outlook-message-perl
```

mail-parser supports Python 3.


## Description

mail-parser takes as input a raw email and generates a parsed object. The properties of this object have the same name of 
[RFC headers](https://www.iana.org/assignments/message-headers/message-headers.xhtml):

  - bcc
  - cc
  - date
  - delivered_to
  - from\_ (not `from` because is a keyword of Python)
  - message_id
  - received
  - reply_to
  - subject
  - to

There are other properties to get:
  - body
  - headers
  - attachments
  - sender IP address

mail-parser can detect defect in mail:
  - [defects](https://docs.python.org/2/library/email.message.html#email.message.Message.defects): mail with some not compliance RFC part

All properties have a JSON and raw property that you can get with:
 - name_json
 - name_raw

Example:

```
$ mail.to (Python object)
$ mail.to_json (JSON)
$ mail.to_raw (raw header)
```

The command line tool use the JSON format.

### Defects
These defects can be used to evade the antispam filter. An example are the mails with a malformed boundary that can hide a not legitimate epilogue (often malware).
This library can take these epilogues.


### Apache 2 Open Source License
mail-parser can be downloaded, used, and modified free of charge. It is available under the Apache 2 license.
[![Donate](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif "Donate")](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VEPXYP745KJF2)


## Authors

### Main Author
**Fedele Mantuano**: [LinkedIn](https://www.linkedin.com/in/fmantuano/)


## Installation

Clone repository

```
git clone https://github.com/SpamScope/mail-parser.git
```

and install mail-parser with `setup.py`:

```
$ cd mail-parser

$ python setup.py install
```

or use `pip`:

```
$ pip install mail-parser
```

## Usage in a project

Import `mailparser` module:

```
import mailparser

mail = mailparser.parse_from_file(f)
mail = mailparser.parse_from_file_obj(fp)
mail = mailparser.parse_from_string(raw_mail)
mail = mailparser.parse_from_bytes(byte_mail)
```

Then you can get all parts

```
mail.attachments: list of all attachments
mail.body
mail.date: datetime object in UTC
mail.defects: defect RFC not compliance
mail.defects_categories: only defects categories
mail.delivered_to
mail.from_
mail.get_server_ipaddress(trust="my_server_mail_trust")
mail.has_defects
mail.headers
mail.headers
mail.mail: tokenized mail in a object
mail.message: email.message.Message object
mail.message_as_string: message as string
mail.message_id
mail.received
mail.subject
mail.text_plain: only text plain mail parts in a list
mail.to
```

## Usage from command-line

If you installed mailparser with `pip` or `setup.py` you can use it with command-line.

These are all swithes:

```
usage: mailparser.py [-h] (-f FILE | -s STRING | -k) [-j] [-b] [-a] [-r] [-t] [-dt] [-m]
                   [-u] [-c] [-d] [-n] [-i Trust mail server string] [-p] [-z] 
                   [-v]

Wrapper for email Python Standard Library

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Raw email file (default: None)
  -s STRING, --string STRING
                        Raw email string (default: None)
  -k, --stdin           Enable parsing from stdin (default: False)
  -j, --json            Show the JSON of parsed mail (default: False)
  -b, --body            Print the body of mail (default: False)
  -a, --attachments     Print the attachments of mail (default: False)
  -r, --headers         Print the headers of mail (default: False)
  -t, --to              Print the to of mail (default: False)
  -dt, --delivered-to   Print the delivered-to of mail (default: False)
  -m, --from            Print the from of mail (default: False)
  -u, --subject         Print the subject of mail (default: False)
  -c, --receiveds       Print all receiveds of mail (default: False)
  -d, --defects         Print the defects of mail (default: False)
  -n, --anomalies       Print the anomalies of mail (default: False)
  -o, --outlook         Analyze Outlook msg (default: False)
  -i Trust mail server string, --senderip Trust mail server string
                        Extract a reliable sender IP address heuristically
                        (default: None)
  -p, --mail-hash       Print mail fingerprints without headers (default:
                        False)
  -z, --attachments-hash
                        Print attachments with fingerprints (default: False)
  -v, --version         show program's version number and exit

It takes as input a raw mail and generates a parsed object.
```

Example:

```shell
$ mailparser -f example_mail -j
```

This example will show you the tokenized mail in a JSON pretty format.
