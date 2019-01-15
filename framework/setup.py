#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_packages

# Install the package locally: python setup.py install
# Install the package dev: python setup.py develop

setup(name='wazuh',
      version='3.8.0',
      description='Wazuh control with Python',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_packages(),
      install_requires=[],
      zip_safe=False)
