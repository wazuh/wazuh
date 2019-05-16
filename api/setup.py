#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from setuptools import setup, find_packages

NAME = "api"
VERSION = "3.9.0"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = ["connexion[swagger-ui]==2.2.0",
            "Flask-Cors==3.0.7",
            "Flask-Caching==1.7.0",
            "Flask==1.0.2",
            "python_dateutil==2.6.0",
            "PyYAML==3.13",
            "python-jose[cryptography]==3.0.1",
            "setuptools>=21.0.0",
            "sqlalchemy==1.3.0",
            "uWSGI==2.0.18",
            "defusedxml>=0.6.0"
            ]

setup(
    name=NAME,
    version=VERSION,
    description="Wazuh API",
    author_email="hello@wazuh.com",
    author="Wazuh",
    url="https://github.com/wazuh",
    keywords=["Wazuh API"],
    install_requires=REQUIRES,
    packages=find_packages(exclude=["*.test", "*.test.*", "test.*", "test"]),
    package_data={'': ['spec/spec.yaml']},
    include_package_data=True,
    zip_safe=False,
    license='GPLv2',
    long_description="""\
    The Wazuh API is an open source RESTful API that allows for interaction with the Wazuh manager from a web browser, command line tool like cURL or any script or program that can make web requests. The Wazuh Kibana app relies on this heavily and Wazuh’s goal is to accommodate complete remote management of the Wazuh infrastructure via the Wazuh Kibana app. Use the API to easily perform everyday actions like adding an agent, restarting the manager(s) or agent(s) or looking up syscheck details. 
    """
)
