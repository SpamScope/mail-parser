[![PyPI version](https://badge.fury.io/py/mail-parser.svg)](https://badge.fury.io/py/mail-parser)
[![Build Status](https://travis-ci.org/SpamScope/mail-parser.svg?branch=develop)](https://travis-ci.org/SpamScope/mail-parser)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![BCH compliance](https://bettercodehub.com/edge/badge/SpamScope/mail-parser?branch=develop)](https://bettercodehub.com/)

# mail-parser

## Overview

mail-parser is a wrapper for [email](https://docs.python.org/2/library/email.message.html) Python Standard Library. 
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

mail-parser takes as input a raw email and generates a parsed object. This object is a tokenized email with some indicator:
  - body
  - headers
  - subject
  - from
  - to
  - attachments
  - message id
  - date
  - charset mail
  - sender IP address
  - receiveds

We have also two types of indicator:
  - anomalies: mail without message id or date
  - [defects](https://docs.python.org/2/library/email.message.html#email.message.Message.defects): mail with some not compliance RFC part

### Defects
These defects can be used to evade the antispam filter. An example are the mails with a malformed boundary that can hide a not legitimate epilogue (often malware).
This library can take these epilogues.


### Apache 2 Open Source License
mail-parser can be downloaded, used, and modified free of charge. It is available under the Apache 2 license.
[![Donate](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif "Donate")](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VEPXYP745KJF2)


## Authors

### Main Author
Fedele Mantuano (**Twitter**: [@fedelemantuano](https://twitter.com/fedelemantuano))


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

### Building with Docker
Complete working Docker workflow is possible allowing you to start hacking and building without any other requirements or dependencies. All the required libs and build tools are handled by Docker build process.
Using the provided Dockerfile you can build a complete working image with all the required dependencies. If you're not familiar with Docker, better use Docker Compose to both build and run your source easy and effortlessly.

From the ```docker-compose.yml``` directory, run:
```
$ docker-compose up --build
```
Skip the ```--build``` switch to launch the last built container image without rebuilding again.

The provided ```docker-compose.yml``` file is configured to:

* Mount your host's ```tests/mails/``` dir from your source tree inside the container at ```/data/``` (read-only).
* A command line test example.

See the ```docker-compose.yml``` to view and tweak the launch parameters.

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
mail.body
mail.headers
mail.message_id
mail.to_
mail.from_
mail.subject
mail.text_plain_list: only text plain mail parts in a list
mail.attachments_list: list of all attachments
mail.date_mail
mail.parsed_mail_obj: tokenized mail in a object
mail.parsed_mail_json: tokenized mail in a JSON
mail.defects: defect RFC not compliance
mail.defects_category: only defects categories
mail.has_defects
mail.anomalies
mail.has_anomalies
mail.get_server_ipaddress(trust="my_server_mail_trust")
mail.receiveds
```

## Usage from command-line

If you installed mailparser with `pip` or `setup.py` you can use it with command-line.

These are all swithes:

```
usage: mailparser.py [-h] (-f FILE | -s STRING | -k) [-j] [-b] [-a] [-r] [-t] [-m]
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
