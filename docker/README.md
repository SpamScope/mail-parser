[![Build Status](https://travis-ci.org/SpamScope/mail-parser.svg?branch=develop)](https://travis-ci.org/SpamScope/mail-parser)
[![](https://images.microbadger.com/badges/image/fmantuano/spamscope-mail-parser.svg)](https://microbadger.com/images/fmantuano/spamscope-mail-parser "Get your own image badge on microbadger.com")

![SpamScope](https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png)

# fmantuano/spamscope-mail-parser

This Dockerfile represents a Docker image that encapsulates mail-parser. The [official image](https://hub.docker.com/r/fmantuano/spamscope-mail-parser/) is on Docker Hub.

To run this image after installing Docker, use a command like this:

```
sudo docker run -i -t --rm -v ~/mails:/mails fmantuano/spamscope-mail-parser
```

This command runs mail-parser help as default, but you can use all others options.

To share the "mails" directory between your host and the container, create a "mails" directory on your host.

There also is an example of `docker-compose` 

From the `docker-compose.yml` directory, run:

```
$ sudo docker-compose up
```

The provided ```docker-compose.yml``` file is configured to:

 - Mount your host's `~/mails/` folder from your source tree inside the container at `/mails/` (read-only).
 - A command line test example.

See the ```docker-compose.yml``` to view and tweak the launch parameters.
