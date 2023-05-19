# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from setuptools import setup, find_namespace_packages
import shutil
import glob


setup(
    name='wazuh_testing',
    version='4.5.0',
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    package_dir={'': 'wazuh_testing'},
    packages=find_namespace_packages(where='wazuh_testing'),
    zip_safe=False
)


# # Clean build files
shutil.rmtree('dist', ignore_errors=True)
shutil.rmtree('build', ignore_errors=True)