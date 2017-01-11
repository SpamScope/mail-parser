#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright 2016 Fedele Mantuano (https://twitter.com/fedelemantuano)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from os.path import join, dirname
from setuptools import setup
from mailparser_version import __version__

long_description = open(join(dirname(__file__), 'README')).read().strip()
requires = open(join(
    dirname(__file__), 'requirements.txt')).read().splitlines()


setup(
    name='mail-parser',
    description="Wrapper for email standard library",
    license="Apache License, Version 2.0",
    url="https://github.com/SpamScope/mail-parser",
    long_description=long_description,
    version=__version__,
    author="Fedele Mantuano",
    author_email="mantuano.fedele@gmail.com",
    maintainer="Fedele Mantuano",
    maintainer_email='mantuano.fedele@gmail.com',
    packages=["mailparser", "mailparser_version"],
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
        "Programming Language :: Python :: 3.0",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
    ],
    install_requires=requires,
    entry_points={'console_scripts': [
        'mailparser = mailparser.__main__:main']},
)
