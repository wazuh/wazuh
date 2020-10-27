#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

from wazuh.core.tests.test_active_response import agent_config, agent_info
from wazuh.core.exception import WazuhError

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.active_response import run_command


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


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
@patch("wazuh.core.ossec_queue.OssecQueue._connect")
@patch("wazuh.syscheck.OssecQueue._send", return_value='1')
@patch("wazuh.core.ossec_queue.OssecQueue.close")
@patch('wazuh.common.ossec_path', new=test_data_path)
def test_run_command(mock_close,  mock_send, mock_conn, message_exception, send_exception, agent_id, command,
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
    with patch('wazuh.core.agent.Agent.get_basic_information', return_value=agent_info(send_exception)):
        with patch('wazuh.core.agent.Agent.getconfig', return_value=agent_config(send_exception)):
            if message_exception:
                with pytest.raises(WazuhError, match=f'.* {message_exception} .*'):
                    run_command(agent_list=agent_id, command=command, arguments=arguments, custom=custom)
            else:
                ret = run_command(agent_list=agent_id, command=command, arguments=arguments, custom=custom)
                if send_exception:
                    assert ret.render()['message'] == 'AR command was not sent to any agent'
                else:
                    assert ret.render()['message'] == 'AR command was sent to all agents'
