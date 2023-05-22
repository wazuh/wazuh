# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import shutil

from setuptools import setup, find_packages


package_data_list = []
scripts_list = []

setup(
    name='wazuh_testing',
    version='4.5.0',
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=find_packages(),
    package_data={'wazuh_testing': package_data_list},
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)

# Clean build files
shutil.rmtree('dist', ignore_errors=True)
shutil.rmtree('build', ignore_errors=True)
shutil.rmtree('wazuh_testing.egg-info', ignore_errors=True)
