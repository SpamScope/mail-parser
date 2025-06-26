[![PyPI - Version](https://img.shields.io/pypi/v/mail-parser)](https://pypi.org/project/mail-parser/)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mail-parser?color=blue)](https://pypistats.org/packages/mail-parser)


![SpamScope](https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png)

# mail-parser
mail-parser goes beyond being just a simple wrapper for the Python Standard Library's [email module](https://docs.python.org/2/library/email.message.html). It seamlessly transforms raw emails into versatile Python objects that you can integrate effortlessly into your projects. As the cornerstone of [SpamScope](https://github.com/SpamScope/spamscope), mail-parser empowers you to handle emails with ease and efficiency.

Additionally, mail-parser supports the parsing of Outlook email formats (.msg). To enable this functionality on Debian-based systems, simply install the necessary package:

```
$ apt-get install libemail-outlook-message-perl
```

For further details about the package, you can run:

```
$ apt-cache show libemail-outlook-message-perl
```

mail-parser is fully compatible with Python 3, ensuring modern performance and reliability.


# Apache 2 Open Source License
mail-parser can be downloaded, used, and modified free of charge. It is available under the Apache 2 license.


# Support the Future of mail-parser
Every contribution fuels innovation! If you believe in a powerful and reliable email parsing tool, consider investing in mail-parser. Your donation directly supports ongoing development, ensuring that we continue providing a robust, cutting-edge solution for developers everywhere.

**Invest in Innovation**
By donating, you help us:
- Enhance and expand features.
- Maintain a secure and reliable project.
- Continue offering a valuable tool to the community.

[![Donate](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif "Donate")](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VEPXYP745KJF2)

Or contribute with Bitcoin:

<a href="bitcoin:bc1qxhz3tghztpjqdt7atey68s344wvmugtl55tm32">
  <img src="https://github.com/SpamScope/mail-parser/blob/develop/docs/images/Bitcoin%20SpamScope.jpg?raw=true" alt="Bitcoin" width="200">
</a>

**Bitcoin Address:** `bc1qxhz3tghztpjqdt7atey68s344wvmugtl55tm32`

Thank you for supporting the evolution of mail-parser!


# mail-parser on Web
Explore mail-parser on these platforms:

- **[FreeBSD port](https://www.freshports.org/mail/py-mail-parser/)**
- **[Arch User Repository](https://aur.archlinux.org/packages/mailparser/)**
- **[REMnux](https://docs.remnux.org/discover-the-tools/analyze+documents/email+messages#mail-parser)**


# Description
mail-parser takes a raw email as input and converts it into a comprehensive Python object that mirrors the structure of an email as defined by the relevant RFCs. Each property of this object directly maps to standard [RFC headers](https://www.iana.org/assignments/message-headers/message-headers.xhtml) such as "From", "To", "Cc", "Bcc", "Subject", and more.

In addition, the parser extracts supplementary components including:
- Plain text and HTML bodies for versatile processing.
- Attachments along with their metadata (e.g., filename, content type, encoding, and more).
- Detailed diagnostics like timestamp conversions, defects indicating non-compliant header formats, and custom header management (using underscore substitutions for hyphenated header names).

Moreover, each header and property is accessible in multiple formats:
- A native Python value for immediate use.
- A raw string to retain original formatting.
- A JSON representation for simplified integration with other tools or services.

This rich parsing capability makes mail-parser a robust tool for email processing, enabling developers to handle, analyze, and even troubleshoot raw email data with comprehensive detail.

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
  - body html
  - body plain
  - headers
  - attachments
  - sender IP address
  - to domains
  - timezone

The `attachments` property is a list of objects. Every object has the following keys:
  - binary: it's true if the attachment is a binary
  - charset
  - content_transfer_encoding
  - content-disposition
  - content-id
  - filename
  - mail_content_type
  - payload: attachment payload in base64

To get custom headers you should replace "-" with "\_".
Example for header `X-MSMail-Priority`:

```
$ mail.X_MSMail_Priority
```

The `received` header is parsed and splitted in hop. The fields supported are:
 - by
 - date
 - date_utc
 - delay (between two hop)
 - envelope_from
 - envelope_sender
 - for
 - from
 - hop
 - with


> **Important:** mail-parser can detect defects in mail.
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


## Defects and Their Impact on Email Security
Email defects, such as malformed boundaries, can be exploited by malicious actors to bypass antispam filters. For instance, a poorly formatted boundary in an email might conceal an illegitimate epilogue that contains hidden malicious content, such as malware payloads or phishing links.

mail-parser is built to detect these structural irregularities, ensuring that even subtle anomalies are captured and analyzed. By identifying these defects, the library provides an early warning system, allowing you to:

- Uncover hidden parts of an email that may be deliberately obfuscated.
- Diagnose potential security threats stemming from non-standard email formatting.
- Facilitate deeper forensic analysis of suspicious emails where the epilogue might carry harmful code or deceitful information.

This robust defect detection mechanism is essential for maintaining the integrity of your email processing systems and enhancing overall cybersecurity.


# Authors

## Main Author
**Fedele Mantuano**: [LinkedIn](https://www.linkedin.com/in/fmantuano/)


# Installation
To install mail-parser, follow these simple steps:

1. Make sure you have Python 3 installed on your system.
2. Open your terminal or command prompt.
3. Run the following command to install mail-parser from PyPI:

```bash
$ pip install mail-parser
```

4. (Optional) To verify the installation, you can run:

```bash
$ pip show mail-parser
```

If you plan to contribute or develop further, consider setting up a `uv` environment and syncing all development dependencies:

```bash
$ git clone https://github.com/SpamScope/mail-parser.git
$ cd mail-parser
$ uv sync
```

With these commands, you’ll have all dependencies installed inside your virtual environment.

For more detailed instructions about `uv`, please refer to the [uv documentation](https://docs.astral.sh/uv/).


# Usage in a project
Import `mailparser` module:

```
import mailparser

mail = mailparser.parse_from_bytes(byte_mail)
mail = mailparser.parse_from_file(f)
mail = mailparser.parse_from_file_msg(outlook_mail)
mail = mailparser.parse_from_file_obj(fp)
mail = mailparser.parse_from_string(raw_mail)
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
mail.headers
mail.mail: tokenized mail in a object
mail.message: email.message.Message object
mail.message_as_string: message as string
mail.message_id
mail.received
mail.subject
mail.text_plain: only text plain mail parts in a list
mail.text_html: only text html mail parts in a list
mail.text_not_managed: all not managed text (check the warning logs to find content subtype)
mail.to
mail.to_domains
mail.timezone: returns the timezone, offset from UTC
mail.mail_partial: returns only the mains parts of emails
```

It's possible to write the attachments on disk with the method:

```
mail.write_attachments(base_path)
```

# Usage from command-line
If you installed mailparser with `pip` or `setup.py` you can use it with command-line.

These are all swithes:

```
usage: mailparser [-h] (-f FILE | -s STRING | -k)
                   [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}] [-j] [-b]
                   [-a] [-r] [-t] [-dt] [-m] [-u] [-c] [-d] [-o]
                   [-i Trust mail server string] [-p] [-z] [-v]

Wrapper for email Python Standard Library

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Raw email file (default: None)
  -s STRING, --string STRING
                        Raw email string (default: None)
  -k, --stdin           Enable parsing from stdin (default: False)
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}
                        Set log level (default: WARNING)
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
  -o, --outlook         Analyze Outlook msg (default: False)
  -i Trust mail server string, --senderip Trust mail server string
                        Extract a reliable sender IP address heuristically
                        (default: None)
  -p, --mail-hash       Print mail fingerprints without headers (default:
                        False)
  -z, --attachments-hash
                        Print attachments with fingerprints (default: False)
  -sa, --store-attachments
                        Store attachments on disk (default: False)
  -ap ATTACHMENTS_PATH, --attachments-path ATTACHMENTS_PATH
                        Path where store attachments (default: /tmp)
  -v, --version         show program's version number and exit

It takes as input a raw mail and generates a parsed object.
```

Example:

```shell
$ mailparser -f example_mail -j
```

This example will show you the tokenized mail in a JSON pretty format.

From [raw mail](https://gist.github.com/fedelemantuano/5dd702004c25a46b2bd60de21e67458e) to
[parsed mail](https://gist.github.com/fedelemantuano/e958aa2813c898db9d2d09469db8e6f6).


# Exceptions
Exceptions hierarchy of mail-parser:

```
MailParserError: Base MailParser Exception
|
\── MailParserOutlookError: Raised with Outlook integration errors
|
\── MailParserEnvironmentError: Raised when the environment is not correct
|
\── MailParserOSError: Raised when there is an OS error
|
\── MailParserReceivedParsingError: Raised when a received header cannot be parsed
```

# fmantuano/spamscope-mail-parser
This Docker image encapsulates the functionality of `mail-parser`. You can find the [official image on Docker Hub](https://hub.docker.com/r/fmantuano/spamscope-mail-parser/).

## Running the Docker Image

After installing Docker, you can run the container with the following command:

```shell
sudo docker run -it --rm -v ~/mails:/mails fmantuano/spamscope-mail-parser
```

This command mounts your local `~/mails` directory into the container at `/mails`. The image runs `mail-parser` in its default mode, but you can pass any additional options as needed.

## Using docker-compose

A `docker-compose.yml` file is also provided. From the directory containing the file, run:

```shell
sudo docker-compose up
```

The configuration in the `docker-compose.yml` file includes:
- Mounting your local `~/mails` directory (read-only) into the container at `/mails`.
- Running a command-line test example to verify functionality.

Review the `docker-compose.yml` file to customize the launch parameters to suit your needs.
