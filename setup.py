#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os.path import join, dirname
from setuptools import setup
from mailparser import __versionstr__


long_description = open(join(dirname(__file__), 'README')).read().strip()
requires = open(join(dirname(__file__),
                     'requirements.txt')).read().splitlines()


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
    platforms=["Linux", ],
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
    install_requires=requires,
    entry_points={'console_scripts': [
        'mailparser = mailparser.__main__:main']},
)
