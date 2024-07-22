#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_namespace_packages

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

setup(
    name='comms_api',
    version='5.0.0',
    description='Agent communications API',
    author_email='hello@wazuh.com',
    author='Wazuh',
    url='https://github.com/wazuh',
    keywords=['Agent communications API', 'Agent comms API'],
    install_requires=[],
    packages=find_namespace_packages(exclude=['*.test', '*.test.*', 'test.*', 'test']),
    package_data={},
    include_package_data=True,
    zip_safe=False,
    license='GPLv2',
    long_description="""
    The Agent communications API is an open source RESTful API that allows for interaction with the Wazuh agents.
    """
)
