#!/usr/bin/env python

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
# Install the package locally: python setup.py install
# Install the package dev: python setup.py develop
import os
from datetime import datetime

from setuptools import setup, find_packages
from setuptools.command.install import install


class InstallCommand(install):
    user_options = install.user_options + [
        ('wazuh-version=', None, 'Wazuh Version'),
        ('install-type=', None, 'Installation type: server, local, hybrid')
    ]

    def initialize_options(self):
        install.initialize_options(self)
        self.wazuh_version = None
        self.install_type = None

    def finalize_options(self):
        install.finalize_options(self)

    def run(self):
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(here, 'wazuh', 'core', 'wazuh.json'), 'w') as f:
            json.dump({'install_type': self.install_type,
                       'wazuh_version': self.wazuh_version,
                       'installation_date': datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')
                       }, f)
        # install.run(self)  # OR: install.do_egg_install(self)
        install.do_egg_install(self)


setup(name='wazuh',
      version='4.1.0',
      description='Wazuh control with Python',
      url='https://github.com/wazuh',
      author='Wazuh',
      author_email='hello@wazuh.com',
      license='GPLv2',
      packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      package_data={'wazuh': ['core/wazuh.json', 'core/cluster/cluster.json', 'rbac/default/*.yaml']},
      include_package_data=True,
      install_requires=[],
      zip_safe=False,
      cmdclass={
          'install': InstallCommand
      }
      )
