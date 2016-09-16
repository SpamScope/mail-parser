#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os.path import join, dirname
from setuptools import setup


VERSION = (0, 2, 2)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))

f = open(join(dirname(__file__), 'README'))
long_description = f.read().strip()
f.close()

requires = ['simplejson']


setup(
    name='mail-parser',
    description="Wrapper for email standard library",
    license="Apache License, Version 2.0",
    url="https://github.com/SpamScope/mail-parser",
    long_description=long_description,
    version=__versionstr__,
    author="Fedele Mantuano",
    author_email="mantuano.fedele@gmail.com",
    maintainer="Fedele Mantuano",
    maintainer_email='mantuano.fedele@gmail.com',
    packages=["mailparser"],
    keywords=['mail', 'email', 'parser', 'wrapper'],
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
    ],
    requires=requires,
)
