FROM python
ENV MAIL_PARSER_PATH=/tmp/mailparser
ARG BRANCH=develop
RUN apt-get -yqq update; \
    apt-get -yqq --no-install-recommends install libemail-outlook-message-perl; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    git clone -b $BRANCH --single-branch https://github.com/SpamScope/mail-parser.git $MAIL_PARSER_PATH; \ 
    cd $MAIL_PARSER_PATH && python setup.py install
ENTRYPOINT ["mailparser"]
CMD ["-h"]
