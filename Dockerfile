FROM python:onbuild

RUN python setup.py install

ENTRYPOINT [ "mailparser" ]
