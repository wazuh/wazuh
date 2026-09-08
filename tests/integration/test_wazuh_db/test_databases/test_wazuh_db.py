'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The daemon manages the global, mitre and task databases; this
       suite exercises the `global` and `task` actors.

components:
    - wazuh_db

targets:
    - manager

daemons:
    - wazuh-manager-db

os_platform:
    - linux

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-manager-db.html

tags:
    - wazuh_db
'''
from pathlib import Path
import re
import pytest

from wazuh_testing.utils import configuration
from wazuh_testing.utils.database import query_wdb

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
t_global_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_global_messages.yaml')
t_global_config_parameters, t_global_config_metadata, t_global_case_ids = configuration.get_test_cases_data(t_global_cases_path)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# The task manager runs a periodic disconnection sweep that marks every agent whose last keepalive
# predates <agents_disconnection_time> as disconnected. The cases below set ancient keepalives on
# purpose and then assert the connection status, so a sweep landing between two stages rewrites rows
# the test owns. Turn the sweep off: these cases drive `disconnect-agents` through the socket
# themselves and never rely on the scheduled one.
local_internal_options = {'wazuh_modules.manager_task_monitor_agents': '0'}


@pytest.fixture(scope='module', autouse=True)
def disable_agent_disconnection_sweep():
    """Write `local_internal_options` before the daemons are restarted, and restore them afterwards.

    The module-scoped `configure_local_internal_options_module` fixture cannot be used here: it
    requests `test_metadata`, which this module parametrizes at function scope. Being autouse is
    what orders this fixture ahead of `daemons_handler_module`, so wazuh-modulesd reads the option
    on its restart.
    """
    backup_local_internal_options = configuration.get_local_internal_options_dict()

    configuration.set_local_internal_options_dict(local_internal_options)

    yield

    configuration.set_local_internal_options_dict(backup_local_internal_options)


def regex_match(regex, string):
    regex = regex.replace('*', '.*')
    regex = regex.replace('[', '')
    regex = regex.replace(']', '')
    regex = regex.replace('(', '')
    regex = regex.replace(')', '')
    string = string.replace('[', '')
    string = string.replace(']', '')
    string = string.replace('(', '')
    string = string.replace(')', '')
    return re.match(regex, string)


def validate_wazuh_db_response(expected_output, response):
    """Compare an expected output (str or list) against the actual socket response."""
    if isinstance(response, list):
        if len(expected_output) != len(response):
            return False
        return all(expected_output[i] == item for i, item in enumerate(response))
    return expected_output == response


def _run_stages(test_metadata):
    """Iterate over `test_case` stages, send each input to wazuh-db and assert the output."""
    for index, stage in enumerate(test_metadata['test_case']):
        if stage.get('ignore') == 'yes':
            continue

        command = stage['input']
        expected_output = stage['output']
        response = query_wdb(command, False, True)

        if stage.get('use_regex') == 'yes':
            match = bool(regex_match(expected_output, response))
        else:
            match = validate_wazuh_db_response(expected_output, response)

        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}'.format(
            index + 1, stage['stage'], expected_output, response,
        )


@pytest.mark.parametrize('test_metadata', t_global_config_metadata, ids=t_global_case_ids)
def test_wazuh_db_messages_global(test_metadata, daemons_handler_module,
                                  clean_databases, clean_registered_agents):
    '''
    description: Verify every `global ...` message sent to the wazuh-manager-db socket returns the expected response.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - disable_agent_disconnection_sweep:
            type: fixture
            brief: Autouse fixture that disables the task manager's scheduled agent disconnection sweep.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents from wazuh-db.

    assertions:
        - Verify that the socket response matches the expected output of the yaml input file.

    input_description:
        - cases_global_messages.yaml - covers insert, update, select, sync, group, connection-status and delete
          commands targeting the global database.

    tags:
        - wazuh_db
        - wdb_socket
    '''
    _run_stages(test_metadata)
