[![PyPI - Version](https://img.shields.io/pypi/v/mail-parser)](https://pypi.org/project/mail-parser/)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mail-parser?color=blue)](https://pypistats.org/packages/mail-parser)

![SpamScope](https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png)

# fmantuano/spamscope-mail-parser
This Dockerfile represents a Docker image that encapsulates `mail-parser`. The [official image](https://hub.docker.com/r/fmantuano/spamscope-mail-parser/) is on Docker Hub.

To run this image after installing Docker, use a command like this:

```shell
sudo docker run -i -t --rm -v ~/mails:/mails fmantuano/spamscope-mail-parser
```

This command runs `mail-parser` help as default, but you can use all others options.

To share the "mails" directory between your host and the container, create a "mails" directory on your host.

There also is an example of `docker-compose`

From the `docker-compose.yml` directory, run:

```shell
$ sudo docker-compose up
```

The provided `docker-compose.yml` file is configured to:

 - Mount your host's `~/mails/` folder from your source tree inside the container at `/mails/` (read-only).
 - A command line test example.

See the `docker-compose.yml` to view and tweak the launch parameters.
