'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logtest' tool allows the testing and verification of rules and decoders against provided log examples
       remotely inside a sandbox in 'wazuh-analysisd'. This functionality is provided by the manager, whose work
       parameters are configured in the ossec.conf file in the XML rule_test section. Test logs can be evaluated through
       the 'wazuh-logtest' tool or by making requests via RESTful API. These tests will check if the logtest
       configuration is valid. Also checks rules, decoders, decoders, alerts matching logs correctly.

components:
    - logtest

suite: remove_old_sessions

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
    - https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - logtest_configuration
'''
import pytest
from pathlib import Path
from json import dumps

from logtest import callback_remove_session, callback_session_initialized
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.global_parameters import GlobalParameters
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.configuration import ANALYSISD_DEBUG
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import configuration

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
t_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_old_sessions.yaml')
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_old_sessions.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)
t_configurations = configuration.load_configuration_template(t_config_path, t_config_parameters, t_config_metadata)

# Variables
local_internal_options = {ANALYSISD_DEBUG: '1'}
create_session_data = {'version': 1, 'command': 'log_processing',
                       'parameters': {'event': 'Oct 15 21:07:56 linux-agent sshd[29205]: Invalid user blimey '
                                      'from 18.18.18.18 port 48928',
                                      'log_format': 'syslog',
                                      'location': 'master->/var/log/syslog'}}
msg_create_session = dumps(create_session_data)
global_parameters = GlobalParameters()
wazuh_log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Test
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t_configurations, t_config_metadata), ids=t_case_ids)
def test_remove_old_session(configure_local_internal_options, test_configuration,
                            test_metadata, set_wazuh_configuration, daemons_handler,
                            wait_for_logtest_startup):
    '''
    description: Check if 'wazuh-logtest' correctly detects and handles the situation where trying to use more
                 sessions than allowed. To do this, it creates more sessions than allowed and wait for the message which
                 informs that 'wazuh-logtest' has removed the oldest session.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
        - restart_required_logtest_daemons:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.

    assertions:
        - Verify that the session will exceed the allowed sessions with the last one to verify that the first(oldest)
         session is correctly removed.
        - Verify that every session is correctly created.
        - Verify that the first session is valid.
        - Verify that the 'removal session' is created.
        - Verify that the removed session is the first one.
        - Verify that the session that exceeds the limit is created.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'wazuh_conf.yaml' and the session creation data from the module.

    expected_output:
        - 'Session initialization event not found'
        - 'Session removal event not found'
        - 'Incorrect session removed'
        - r'Error when executing .* in daemon .*. Exit status: .*'

    tags:
        - session_limit
        - analysisd
    '''
    max_sessions = int(test_metadata['max_sessions'])

    first_session_token = None

    for i in range(0, max_sessions):

        receiver_socket = SocketController(address=LOGTEST_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
        receiver_socket.send(msg_create_session, True)
        msg_recived = receiver_socket.receive()[4:]
        msg_recived = msg_recived.decode()
        receiver_socket.close()
        del receiver_socket

        if i == 0:
            first_session_token = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                    callback=callback_session_initialized)
            assert wazuh_log_monitor.callback_result, 'Session initialization event not found'
        else:
            wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                              callback=callback_session_initialized)
            assert wazuh_log_monitor.callback_result,'Session initialization event not found'

    # This session should do Wazuh-logtest to remove the oldest session
    receiver_socket = SocketController(address=LOGTEST_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
    receiver_socket.send(msg_create_session, True)
    msg_recived = receiver_socket.receive()[4:]
    msg_recived = msg_recived.decode()
    receiver_socket.close()
    del receiver_socket

    remove_session_token = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                             callback=callback_remove_session)
    assert wazuh_log_monitor.callback_result, 'Session removal event not found'

    assert first_session_token == remove_session_token, "Incorrect session removed"

    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                      callback=callback_session_initialized)
    assert wazuh_log_monitor.callback_result, 'Session initialization event not found'
