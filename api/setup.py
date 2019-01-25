# coding: utf-8

import sys
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
            "python_dateutil==2.6.0",
            "setuptools>=21.0.0"
            ]

setup(
    name=NAME,
    version=VERSION,
    description="Wazuh API",
    author_email="",
    url="",
    keywords=["Wazuh API"],
    install_requires=REQUIRES,
    packages=find_packages(),
    package_data={'': ['spec/spec.yaml']},
    include_package_data=True,
    long_description="""\
    The Wazuh API is an open source RESTful API that allows for interaction with the Wazuh manager from a web browser, command line tool like cURL or any script or program that can make web requests. The Wazuh Kibana app relies on this heavily and Wazuh’s goal is to accommodate complete remote management of the Wazuh infrastructure via the Wazuh Kibana app. Use the API to easily perform everyday actions like adding an agent, restarting the manager(s) or agent(s) or looking up syscheck details. 
    """
)

