#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.exception import WazuhError
        from wazuh.core import active_response


# Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Functions

def agent_info(expected_exception):
    """Returns dict to cause or not a exception code 1651 on active_response.send_command()."""
    if expected_exception == 1651:
        return {'status': 'random'}
    else:
        return {'status': 'active'}


def agent_config(expected_exception):
    """Returns dict to cause or not a exception code 1750 on active_response.send_command()."""
    if expected_exception == 1750:
        return {'active-response': {'disabled': 'yes'}}
    else:
        return {'active-response': {'disabled': 'no'}}


# Tests

@pytest.mark.parametrize('expected_exception, command, arguments, custom', [
    (1650, None, [], False),
    (1652, 'random', [], False),
    (1652, 'invalid_cmd', [], False),
    (None, 'restart-ossec0', [], False),
    (None, 'restart-ossec0', [], True),
    (None, 'restart-ossec0', ["arg1", "arg2"], False)
])
@patch('wazuh.core.common.ossec_path', new=test_data_path)
def test_create_message(expected_exception, command, arguments, custom):
    """Checks message returned is correct

    Checks if message returned by create_message(...) contains the command, arguments and '!' symbol
    when it is needed.

    Parameters
    ----------
    expected_exception : str
        Exception code expected when calling create_message.
    command : str
        Command to be introduced in the message.
    arguments : list
        Arguments for the command/script.
    custom : boolean
        True if command is a script.
    """
    if expected_exception:
        with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
            active_response.create_message(command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.create_message(command=command, arguments=arguments, custom=custom)
        assert command in ret, f'Command not being returned'
        if arguments:
            assert (arg in ret for arg in arguments), f'Arguments not being added'
        if custom:
            assert '!' in ret, f'! symbol not being added when custom command'


@patch('wazuh.core.common.ossec_path', new=test_data_path)
def test_get_commands():
    """
    Checks if get_commands method returns a list
    """
    ret = active_response.get_commands()
    assert type(ret) is list, f'Expected type not match'


@pytest.mark.parametrize('command, expected_escape', [
    ('random <arg1> {arg2}', 4),
    ('" \' \t ; ` > < | # * [ ] { } & $ ! : ( )', 20)
])
def test_shell_escape(command, expected_escape):
    """Checks if shell_escape method is escaping every symbol

    Parameters
    ----------
    command : str
        Symbols to be escaped
    expected_escape : int
        Expected number of escaped symbols
    """
    ret = active_response.shell_escape(command)
    assert ret.count('\\') == expected_escape, f'Number of escaped symbols do not match'


@pytest.mark.parametrize('expected_exception, command, agent_id', [
    (1651, 'random', 0),
    (1750, 'random', 0),
    (None, 'random', 5)
])
def test_send_command(expected_exception, command, agent_id):
    """Checks if send_command method is correct

    Verify that send_command raise specific exceptions in some cases and that arguments are correct.

    Parameters
    ----------
    expected_exception : int
        Exception code expected when calling send_command.
    command : str
        Command to be introduced in the message.
    agent_id : int
        ID number to be set on the agent.
    """
    with patch('wazuh.core.agent.Agent.get_basic_information', return_value=agent_info(expected_exception)):
        with patch('wazuh.core.agent.Agent.getconfig', return_value=agent_config(expected_exception)):
            if expected_exception:
                with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
                    active_response.send_command(command, MagicMock(), agent_id)
            else:
                mock_oq = MagicMock()
                active_response.send_command(command, mock_oq, agent_id)
                mock_oq.send_msg_to_agent.assert_called_with(agent_id=agent_id, msg=command, msg_type='ar-message')
