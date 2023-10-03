#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
# Install the package locally: python setup.py install
# Install the package dev: python setup.py develop
import os
from datetime import datetime, timezone

from setuptools import setup, find_namespace_packages
from setuptools.command.install import install

WAZUH_VERSION='4.8.0'


class InstallCommand(install):
    """Inherited class. Overrides the run method to generate the wazuh.json file."""

    def run(self):
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(here, 'wazuh', 'core', 'wazuh.json'), 
                  encoding='utf-8', mode='w') as file:
            json.dump({'install_type': 'server',
                       'wazuh_version': f'v{WAZUH_VERSION}',
                       'installation_date': datetime.utcnow().replace(tzinfo=timezone.utc).strftime(
                           '%a %b %d %H:%M:%S UTC %Y')
                       }, file)
        install.run(self)


setup(name='wazuh',
      version=WAZUH_VERSION,
      description='Wazuh control with Python',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_namespace_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      package_data={'wazuh': ['core/wazuh.json',
                              'core/cluster/cluster.json', 'rbac/default/*.yaml']},
      include_package_data=True,
      install_requires=[],
      zip_safe=False,
      cmdclass={
          'install': InstallCommand
      }
      )
