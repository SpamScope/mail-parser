FROM python:3.10-slim-bookworm

# Set environment variables

# Don’t buffer stdout/stderr, don’t write .pyc files
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV MAIL_PARSER_PATH=/app
ENV BINARY_NAME="mail_parser-latest.tar.gz"

# Copy the mail-parser binary from the build context
COPY ./dist/*.tar.gz ${MAIL_PARSER_PATH}/${BINARY_NAME}

# Install dependencies
RUN apt-get -yqq update && \
    apt-get -yqq --no-install-recommends install libemail-outlook-message-perl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install the mail-parser package
RUN useradd -m mailparser \
    && chown mailparser:mailparser ${MAIL_PARSER_PATH} \
    && pip install "${MAIL_PARSER_PATH}/${BINARY_NAME}"

USER mailparser

ENTRYPOINT ["mail-parser"]
CMD ["-h"]
