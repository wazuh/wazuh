#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup

# Install the package locally: python setup.py install
# Install the package dev: python setup.py develop

setup(name='wazuh',
      version='3.0.0-beta9',
      description='Wazuh control with Python',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=['wazuh'],
      install_requires=[],
      zip_safe=False)
