#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import find_namespace_packages, setup
from wazuh import __version__

setup(
    name='wazuh',
    version=__version__,
    description='Wazuh control with Python',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=find_namespace_packages(exclude=['*.tests', '*.tests.*', 'tests.*', 'tests']),
    package_data={'wazuh': ['core/wazuh.json', 'core/cluster/cluster.json', 'rbac/default/*.yaml']},
    include_package_data=True,
    install_requires=[],
    zip_safe=False,
)
