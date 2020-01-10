#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from functools import wraps
from unittest.mock import patch, MagicMock

from wazuh.exception import WazuhError

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', 'api'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        def RBAC_bypasser(**kwargs):
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapper
            return decorator
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.active_response import run_command

# All necessary params
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Functions

def agent_info(expected_exception):
    """Returns dict to cause or not a exception code 1651 on active_response.send_command()."""
    if expected_exception == 1651:
        return {'status': 'random'}
    else:
        return {'status': 'active'}


def agent_config(expected_exception):
    """Returns dict to cause or not an exception code 1750 on active_response.send_command()."""
    if expected_exception == 1750:
        return {'active-response': {'disabled': 'yes'}}
    else:
        return {'active-response': {'disabled': 'no'}}


# Tests

@pytest.mark.parametrize('message_exception, send_exception, agent_id, command, arguments, custom', [
    (1650, None, [0], None, [], False),
    (1652, None, [0], 'random', [], False),
    (None, 1651, [1], 'restart-ossec0', [], False),
    (None, 1750, [1], 'restart-ossec0', [], False),
    (None, None, [1], 'restart-ossec0', [], False),
    (None, None, [1], 'restart-ossec0', [], True),
    (None, None, [1], 'restart-ossec0', ["arg1", "arg2"], False),
    (None, None, [0], 'restart-ossec0', [], False),
    (None, None, [0, 1, 2, 3, 4, 5, 6], 'restart-ossec0', [], False),
])
@patch("wazuh.ossec_queue.OssecQueue._connect")
@patch("wazuh.syscheck.OssecQueue._send", return_value='1')
@patch("wazuh.ossec_queue.OssecQueue.close")
@patch('wazuh.common.ossec_path', new='wazuh/tests/data')
def test_run_command(mock_conn,  mock_send, mock_close, message_exception, send_exception, agent_id, command,
                     arguments, custom):
    """Verify the proper operation of active_response module.

    Parameters
    ----------
    message_exception : int
        Exception code expected when calling create_message.
    send_exception : int
        Exception code expected when calling send_command.
    agent_id : list
        Agents on which to execute the Active response command.
    command : string
        Command to be executed on the agent.
    arguments : list, optional
        Arguments of the command.
    custom : boolean
        True if command is a script.
    """
    with patch('wazuh.core.core_agent.Agent.get_basic_information', return_value=agent_info(send_exception)):
        with patch('wazuh.core.core_agent.Agent.getconfig', return_value=agent_config(send_exception)):
            if message_exception:
                with pytest.raises(WazuhError, match=f'.* {message_exception} .*'):
                    run_command(agent_list=agent_id, command=command, arguments=arguments, custom=custom)
            else:
                ret = run_command(agent_list=agent_id, command=command, arguments=arguments, custom=custom)
                if send_exception:
                    assert ret.render()['message'] == 'Could not send command to any agent'
                else:
                    assert ret.render()['message'] == 'Command sent to all agents'
