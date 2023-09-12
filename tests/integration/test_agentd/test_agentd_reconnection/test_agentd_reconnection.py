'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       The objective is to check that, with different states in the 'clients.keys' file,
       the agent successfully enrolls after losing connection with the 'wazuh-remoted' daemon.
       The wazuh-remoted program is the server side daemon that communicates with the agents.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
import pytest
from pathlib import Path
import sys
from time import sleep

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.modules.agentd.patterns import * 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template, change_internal_options
from wazuh_testing.utils import file, callbacks
from wazuh_testing.utils.services import check_if_process_is_running, control_service

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_reconnection_protocol.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}
local_internal_options.update({AGENTD_TIMEOUT: '5'})

def wait_notify(line):
    """Callback function to wait for agent checkins to the manager."""
    if 'Sending keep alive:' in line:
        return line
    return None

def wait_enrollment(line):
    """Callback function to wait for enrollment."""
    if 'Valid key received' in line:
        return line
    return None

def wait_enrollment_try(line):
    """Callback function to wait for enrollment attempt."""
    if 'Requesting a key' in line:
        return line
    return None

def search_error_messages():
    """Retrieve the line of the log file where first error is found.

    Returns:
          str: String where the error is found or None if errors are not found.
    """
    with open(LOG_FILE_PATH, 'r') as log_file:
        lines = log_file.readlines()
        for line in lines:
            if f"ERROR:" in line:
                return line
    return None

# Tests
"""
This test covers the scenario of Agent starting with keys,
when misses communication with Remoted and a new enrollment is sent to Authd.
"""

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_reconection_enrollment_with_keys(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check how the agent behaves when losing communication with
                 the 'wazuh-remoted' daemon and a new enrollment is sent to
                 the 'wazuh-authd' daemon.
                 In this case, the agent starts with keys.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated wazuh-authd connection.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    # Stop target Agent
    control_service('stop')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator()
    remoted_server.start()

    # Prepare test
    start_authd()
    set_authd_id()
    set_keys()

    # Start target Agent
    control_service('start')

    log_monitor = FileMonitor(LOG_FILE_PATH)

    # hearing on enrollment server
    authd_server.clear()

    # Wait until Agent is notifying Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")

    # Start rejecting Agent
    remoted_server.set_mode('REJECT')
    # hearing on enrollment server
    authd_server.clear()
    # Wait until Agent asks a new key to enrollment
    log_monitor.start(timeout=180, callback=wait_enrollment,
                      error_message="Agent never enrolled after rejecting connection!")

    # Start responding to Agent
    remoted_server.set_mode('CONTROLLED_ACK')
    # Wait until Agent is notifying Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"


"""
This test covers the scenario of Agent starting without client.keys file
and an enrollment is sent to Authd to start communicating with Remoted
"""


def test_agentd_reconection_enrollment_no_keys_file(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check how the agent behaves when losing communication with
                 the 'wazuh-remoted' daemon and a new enrollment is sent to
                 the 'wazuh-authd' daemon.
                 In this case, the agent doesn't have the 'client.keys' file.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    # Stop target Agent
    control_service('stop')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator()
    remoted_server.start()

    # Prepare test
    start_authd()
    set_authd_id()
    delete_keys()
    # Start target Agent
    control_service('start')

    # start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    # hearing on enrollment server
    authd_server.clear()

    # Wait until Agent asks keys for the first time
    log_monitor.start(timeout=50, callback=wait_enrollment,
                      error_message="Agent never enrolled for the first time.")

    # Wait until Agent is notifing Manager
    log_monitor.start(timeout=50, callback=wait_notify, error_message="Notify message from agent was never sent!")

    # Start rejecting Agent
    remoted_server.set_mode('REJECT')
    # hearing on enrollment server
    authd_server.clear()
    # Wait until Agent asks a new key to enrollment
    log_monitor.start(timeout=180, callback=wait_enrollment,
                      error_message="Agent never enrolled after rejecting connection!")

    # Start responding to Agent
    remoted_server.set_mode('CONTROLLED_ACK')
    # Wait until Agent is notifing Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"


"""
This test covers the scenario of Agent starting without keys in client.keys file
and an enrollment is sent to Authd to start communicating with Remoted
"""


def test_agentd_reconection_enrollment_no_keys(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check how the agent behaves when losing communication with
                 the 'wazuh-remoted' daemon and a new enrollment is sent to
                 the 'wazuh-authd' daemon.
                 In this case, the agent has its 'client.keys' file empty.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Valid key received'
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    # Stop target Agent
    control_service('stop')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator()
    remoted_server.start()

    # Prepare test
    start_authd()
    set_authd_id()
    clean_keys()
    # Start target Agent
    control_service('start')

    # start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    # hearing on enrollment server
    authd_server.clear()

    # Wait until Agent asks keys for the first time
    log_monitor.start(timeout=120, callback=wait_enrollment,
                      error_message="Agent never enrolled for the first time rejecting connection!")

    # Wait until Agent is notifying Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"

    # Start rejecting Agent
    remoted_server.set_mode('REJECT')
    # hearing on enrollment server
    authd_server.clear()
    # Wait until Agent asks a new key to enrollment
    log_monitor.start(timeout=180, callback=wait_enrollment,
                      error_message="Agent never enrolled after rejecting connection!")

    # Start responding to Agent
    remoted_server.set_mode('CONTROLLED_ACK')
    # Wait until Agent is notifying Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")
    assert "aes" in remoted_server.last_message_ctx, "Incorrect Secure Message"


"""
This test covers and check the scenario of Agent starting without keys
and multiple retries are required until the new key is obtained to start communicating with Remoted
"""


def test_agentd_initial_enrollment_retries(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check how the agent behaves when it makes multiple enrollment attempts
                 before getting its key. For this, the agent starts without keys and
                 performs multiple enrollment requests to the 'wazuh-authd' daemon before
                 getting the new key to communicate with the 'wazuh-remoted' daemon.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the 'TCP' and 'UDP' protocols.

    expected_output:
        - r'Requesting a key'
        - r'Valid key received'
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    # Stop target Agent
    control_service('stop')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator()
    remoted_server.start()

    # Preapre test
    stop_authd()
    set_authd_id()
    clean_keys()
    # Start whole Agent service to check other daemons status after initialization
    control_service('start')

    # Start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)

    start_time = datetime.now()
    # Check for unsuccessful enrollment retries in Agentd initialization
    retries = 0
    while retries < 4:
        retries += 1
        log_monitor.start(timeout=retries * 5 + 20, callback=wait_enrollment_try,
                          error_message="Enrollment retry was not sent!")
    stop_time = datetime.now()
    expected_time = start_time + timedelta(seconds=retries * 5 - 2)
    # Check if delay was applied
    assert stop_time > expected_time, "Retries too quick"

    # Enable authd
    authd_server.clear()
    authd_server.set_mode("ACCEPT")
    # Wait successfully enrollment
    # Wait succesfull enrollment
    log_monitor.start(timeout=70, callback=wait_enrollment, error_message="No succesful enrollment after reties!")

    # Wait until Agent is notifying Manager
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")

    # Check if no Wazuh module stopped due to Agentd Initialization
    with open(LOG_FILE_PATH) as log_file:
        log_lines = log_file.read().splitlines()
        for line in log_lines:
            if "Unable to access queue:" in line:
                raise AssertionError("A Wazuh module stopped because of Agentd initialization!")


"""
This test covers and check the scenario of Agent starting with keys but Remoted is not reachable during some seconds
and multiple connection retries are required prior to requesting a new enrollment
"""


def test_agentd_connection_retries_pre_enrollment(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check how the agent behaves when the 'wazuh-remoted' daemon is not available
                 and performs multiple connection attempts to it. For this, the agent starts
                 with keys but the 'wazuh-remoted' daemon is not available for several seconds,
                 then the agent performs multiple connection retries before requesting a new enrollment.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - teardown:
            type: fixture
            brief: Stop the Remoted server

    assertions:
        - Verify that the agent enrollment is successful.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Two test cases are found in the test module and include parameters
                       for the environment setup using the TCP and UDP protocols.

    expected_output:
        - r'Sending keep alive'

    tags:
        - simulator
        - ssl
        - keys
    '''
    REMOTED_KEYS_SYNC_TIME = 10

    # Stop target Agent
    control_service('stop')

    # Start RemotedSimulator
    remoted_server = RemotedSimulator()
    remoted_server.start()

    # Prepare test
    stop_authd()
    set_keys()
    # Start hearing logs
    log_monitor = FileMonitor(LOG_FILE_PATH)
    # Start whole Agent service to check other daemons status after initialization
    control_service('start')

    # Check Agentd is finally communicating
    log_monitor.start(timeout=120, callback=wait_notify, error_message="Notify message from agent was never sent!")