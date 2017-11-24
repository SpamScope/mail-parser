FROM python
ENV MAIL_PARSER_PATH=/tmp/mailparser
ARG BRANCH=develop
RUN git clone -b $BRANCH --single-branch https://github.com/SpamScope/mail-parser.git $MAIL_PARSER_PATH && \ 
    cd $MAIL_PARSER_PATH && python setup.py install
ENTRYPOINT ["mailparser"]
CMD ["-h"]
