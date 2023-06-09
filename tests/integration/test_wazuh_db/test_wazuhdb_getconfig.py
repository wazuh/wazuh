'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the wazuhdb getconfig command used to get the current configuration
tier: 0
modules:
    - wazuh_db
components:
    - manager
daemons:
    - wazuh-db
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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html
tags:
    - wazuh_db
'''
import os
import pytest

from pathlib import Path

from wazuh_testing.constants.paths import WAZUH_PATH,WAZUH_DB_PATH
from wazuh_testing.utils.database import query_wdb
from wazuh_testing.constants.markers import TIER0, LINUX, SERVER
from wazuh_testing.utils import config
from . import CONFIGS_PATH,TEST_CASES_PATH


# Marks
pytestmark =  [TIER0, LINUX, SERVER]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'config_wazuh_db_getconfig.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_wazuh_db_getconfig.yaml')

# Test configurations.
config_parameters, metadata, cases_ids = config.get_test_cases_data(cases_path)
configuration = config.load_configuration_template(configs_path, config_parameters, metadata)

# Configurations
log_monitor_paths = []
receiver_sockets_params = [(WAZUH_DB_PATH, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets = None  # Set in the fixtures


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(configuration, metadata), ids=cases_ids)
def test_sync_agent_groups(configure_sockets_environment, connect_to_sockets_module):
    '''
    description: Check that commands about wazuhdb getconfig works properly.
    wazuh_min_version: 4.4.0
    parameters:
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
    assertions:
        - Verify that the socket response matches the expected output.
    input_description:
        - Test cases are defined in the wazuhdb_getconfig.yaml file.
    expected_output:
        - an array with the configuration of DB.
    tags:
        - wazuh_db
        - wdb_socket
    '''
    # Set each case
    case_data = cases_ids[0]
    output = metadata["output"]

    response = query_wdb(config_parameters["INPUT"])

    # Validate response
    assert output in str(response), f"The expected output: {output} was not found in response: {response}"
