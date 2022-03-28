#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_packages

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

setup(
    name='wodles',
    version='4.4.0',
    description="Wazuh external modules integrations",
    author_email="hello@wazuh.com",
    author="Wazuh",
    url="https://github.com/wazuh",
    keywords=["Wazuh External Modules Integrations"],
    install_requires=[],
    packages=find_packages(exclude=["*.test", "*.test.*", "test.*", "test"]),
    zip_safe=False,
    license='GPLv2'
)
