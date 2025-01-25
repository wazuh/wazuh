'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives a message that must be parsed to extract different fields of interest.

components:
    - analysisd
    - remoted

suite: message parsing

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - events
'''
import os

import pytest
import time
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.utils.file import truncate_file
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools import mitm
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.paths.sockets import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, REMOTE_DAEMON

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1), pytest.mark.server]

# Configurations

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases', 'test_message_parsing.yaml')
TEST_CONFIGURATION_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template', 'configuration.yaml')

test_configuration, test_metadata, cases_ids = get_test_cases_data(TEST_CASES_PATH)
test_configuration = load_configuration_template(TEST_CONFIGURATION_PATH, test_configuration, test_metadata)

daemons_handler_configuration = {'daemons': [ANALYSISD_DAEMON, REMOTE_DAEMON]}

# Variables
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]
mitm_analysisd = mitm.ManInTheMiddle(address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol='UDP')
monitored_sockets_params = [(ANALYSISD_DAEMON, mitm_analysisd, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

log_monitor_paths = ['/var/ossec/logs/archives/archives.json']
# Tests

@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_colons(test_configuration, test_metadata, set_wazuh_configuration, daemons_handler, configure_sockets_environment_module, connect_to_sockets_module, wait_for_analysisd_startup):
    '''
    description: The 'wazuh-analysisd' daemon receives a message that must be parsed to extract different fields of interest.

    wazuh_min_version: 4.8.0

    tier: 1

    assertions:
        - Verify that the location is correctly parsed.

    input_description:
        - Different test cases that includes some special characters on different parts of the remoted messages.

    expected_location_description:
        - The Expected parsed location.

    tags:
        - analysisd
        - man_in_the_middle
        - analisysd_socket
        - ossec_messages_parsing
    '''
    archives_json='/var/ossec/logs/archives/archives.json'
    truncate_file(archives_json)
    archives_monitor = FileMonitor(archives_json)

    matching = fr'.*"location":"{test_metadata["expected_location"]}".*'
    callback=callbacks.generate_callback(regex=matching)

    receiver_sockets[0].send(test_metadata['input'])

    archives_monitor.start(timeout=20, callback=callback)
    assert archives_monitor.callback_result
