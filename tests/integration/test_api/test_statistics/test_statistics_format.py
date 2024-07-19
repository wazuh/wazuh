"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the stats can be obtained from the API and if they follow the expected schema.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager from
       a web browser, command line tool like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/api/reference.html (Get Wazuh daemon stats)
    - https://documentation.wazuh.com/current/user-manual/api/reference.html (Get Wazuh daemon stats from an agent)

tags:
    - api
"""
import pytest
import requests
from pathlib import Path

from . import CONFIGURATION_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing import DATA_PATH
from wazuh_testing.constants.api import DAEMONS_STATS_ROUTE
from wazuh_testing.modules.api.utils import get_base_url, login, validate_statistics
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]


# Variables
STATISTICS_TEMPLATE_PATH = Path(DATA_PATH, 'statistics_template')
daemons_handler_configuration = {'all_daemons': True}

# Paths
test1_configurations_path = Path(CONFIGURATION_FOLDER_PATH, 'configuration_manager_statistics_format.yaml')
test1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'manager_statistics_format_test_module',
                        'cases_manager_statistics_format.yaml')
test1_statistics_template_path = Path(STATISTICS_TEMPLATE_PATH, 'manager_statistics_format_test_module')
test2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'agent_statistics_format_test_module',
                        'cases_agent_statistics_format.yaml')
test2_statistics_template_path = Path(STATISTICS_TEMPLATE_PATH, 'agent_statistics_format_test_module')

# Configurations
test1_configuration, test1_metadata, test1_cases_ids = get_test_cases_data(test1_cases_path)
test1_configuration = load_configuration_template(test1_configurations_path, test1_configuration, test1_metadata)
test2_configuration, test2_metadata, test2_cases_ids = get_test_cases_data(test2_cases_path)


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test1_configuration, test1_metadata),
                         ids=test1_cases_ids)
def test_manager_statistics_format(test_configuration, test_metadata, load_wazuh_basic_configuration,
                                   set_wazuh_configuration, daemons_handler):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Load Wazuh light configuration
            - Apply ossec.conf configuration changes according to the configuration template and use case
            - Restart wazuh-manager service to apply configuration changes
        - test:
            - Request the statistics of a particular daemon from the API
            - Compare the obtained statistics with the json schema
        - teardown:
            - Restore initial configuration
            - Stop wazuh-manager

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.

    assertions:
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `configuration_manager_statistics_format` file provides the module configuration for this test.
        - The `cases_manager_statistics_format` file provides the test cases.
    """
    endpoint = test_metadata['endpoint']
    statistics_schema_path = Path(test1_statistics_template_path, f"{endpoint}_template.json")
    params = f"?daemons_list={endpoint}"
    url = get_base_url() + DAEMONS_STATS_ROUTE + params
    authentication_headers, _ = login()

    # Get daemon statistics
    response = requests.get(url, headers=authentication_headers, verify=False)

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    validate_statistics(response, statistics_schema_path)


@pytest.mark.parametrize('test_metadata', test2_metadata, ids=test2_cases_ids)
def test_agent_statistics_format(test_metadata, daemons_handler, simulate_agent):
    """
    description: Check if the statistics returned by the API have the expected format.

    test_phases:
        - setup:
            - Restart wazuh-manager service to apply configuration changes
        - test:
            - Simulate and connect an agent
            - Request the statistics of a particular daemon and agent from the API
            - Compare the obtained statistics with the json schema
            - Stop and delete the simulated agent
        - teardown:
            - Stop wazuh-manager

    wazuh_min_version: 4.4.0

    parameters:
        - test_metadata:
            type: dict
            brief: Get metadata from the module.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - simulate_agent:
            type: fixture
            brief: Simulate an agent

    assertions:
        - Check if the statistics returned by the API have the expected format.

    input_description:
        - The `cases_agent_statistics_format` file provides the test cases.
    """
    endpoint = test_metadata['endpoint']
    statistics_schema_path = Path(test2_statistics_template_path, f"{endpoint}_template.json")
    agent = simulate_agent

    route = f"/agents/{agent.id}/daemons/stats"
    params = f"?daemons_list={endpoint}"
    url = get_base_url() + route + params
    authentication_headers, _ = login()

    # Get Agent's daemon stats
    response = requests.get(url, headers=authentication_headers, verify=False)

    # Check if the API statistics response data meets the expected schema. Raise an exception if not.
    validate_statistics(response, statistics_schema_path)
