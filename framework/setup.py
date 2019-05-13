#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_packages

# Install the package locally: python setup.py install
# Install the package dev: python setup.py develop

REQUIRES = ["cryptography==2.4.2",
            "setuptools>=21.0.0",
            "uvloop==0.11.3"
            ]

setup(name='wazuh',
      version='3.9.1',
      description='Wazuh control with Python',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      install_requires=REQUIRES,
      zip_safe=False)
