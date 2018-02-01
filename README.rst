|PyPI version| |Build Status| |Coverage Status| |BCH compliance|
|image4|

.. figure:: https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png
   :alt: SpamScope

   SpamScope

mail-parser
===========

Overview
--------

mail-parser is not only a wrapper for
`email <https://docs.python.org/2/library/email.message.html>`__ Python
Standard Library. It give you an easy way to pass from raw mail to
Python object that you can use in your code. It's the key module of
`SpamScope <https://github.com/SpamScope/spamscope>`__.

mail-parser can parse Outlook email format (.msg). To use this feature,
you need to install ``libemail-outlook-message-perl`` package. For
Debian based systems:

::

    $ apt-get install libemail-outlook-message-perl

For more details:

::

    $ apt-cache show libemail-outlook-message-perl

mail-parser supports Python 3.

Description
-----------

mail-parser takes as input a raw email and generates a parsed object.
The properties of this object have the same name of `RFC
headers <https://www.iana.org/assignments/message-headers/message-headers.xhtml>`__:

-  bcc
-  cc
-  date
-  delivered\_to
-  from\_ (not ``from`` because is a keyword of Python)
-  message\_id
-  received
-  reply\_to
-  subject
-  to

There are other properties to get: - body - headers - attachments -
sender IP address - to domains

mail-parser can detect defect in mail: -
`defects <https://docs.python.org/2/library/email.message.html#email.message.Message.defects>`__:
mail with some not compliance RFC part

All properties have a JSON and raw property that you can get with: -
name\_json - name\_raw

Example:

::

    $ mail.to (Python object)
    $ mail.to_json (JSON)
    $ mail.to_raw (raw header)

The command line tool use the JSON format.

Defects
~~~~~~~

These defects can be used to evade the antispam filter. An example are
the mails with a malformed boundary that can hide a not legitimate
epilogue (often malware). This library can take these epilogues.

Apache 2 Open Source License
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mail-parser can be downloaded, used, and modified free of charge. It is
available under the Apache 2 license. |Donate|

Authors
-------

Main Author
~~~~~~~~~~~

**Fedele Mantuano**:
`LinkedIn <https://www.linkedin.com/in/fmantuano/>`__

Installation
------------

Clone repository

::

    git clone https://github.com/SpamScope/mail-parser.git

and install mail-parser with ``setup.py``:

::

    $ cd mail-parser

    $ python setup.py install

or use ``pip``:

::

    $ pip install mail-parser

Usage in a project
------------------

Import ``mailparser`` module:

::

    import mailparser

    mail = mailparser.parse_from_file(f)
    mail = mailparser.parse_from_file_obj(fp)
    mail = mailparser.parse_from_string(raw_mail)
    mail = mailparser.parse_from_bytes(byte_mail)

Then you can get all parts

::

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
    mail.to
    mail.to_domains

Usage from command-line
-----------------------

If you installed mailparser with ``pip`` or ``setup.py`` you can use it
with command-line.

These are all swithes:

::

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

Example:

.. code:: shell

    $ mailparser -f example_mail -j

This example will show you the tokenized mail in a JSON pretty format.

From `raw
mail <https://gist.github.com/fedelemantuano/5dd702004c25a46b2bd60de21e67458e>`__
to `parsed
mail <https://gist.github.com/fedelemantuano/e958aa2813c898db9d2d09469db8e6f6>`__.

.. |PyPI version| image:: https://badge.fury.io/py/mail-parser.svg
   :target: https://badge.fury.io/py/mail-parser
.. |Build Status| image:: https://travis-ci.org/SpamScope/mail-parser.svg?branch=develop
   :target: https://travis-ci.org/SpamScope/mail-parser
.. |Coverage Status| image:: https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop
   :target: https://coveralls.io/github/SpamScope/mail-parser?branch=develop
.. |BCH compliance| image:: https://bettercodehub.com/edge/badge/SpamScope/mail-parser?branch=develop
   :target: https://bettercodehub.com/
.. |image4| image:: https://images.microbadger.com/badges/image/fmantuano/spamscope-mail-parser.svg
   :target: https://microbadger.com/images/fmantuano/spamscope-mail-parser
.. |Donate| image:: https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif
   :target: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VEPXYP745KJF2
