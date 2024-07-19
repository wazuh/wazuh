#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.exception import WazuhError
        from wazuh.core import active_response
        from wazuh.core.agent import Agent

# Variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'etc', 'shared', 'ar.conf')


# Functions

def agent_info(expected_exception: int = None) -> dict:
    """Return dict to cause or not a exception code 1707 on active_response.send_command().

    Parameters
    ----------
    expected_exception : int
        Test expected exception with the parameters given.

    Returns
    -------
    dict
        Agent basic information with status depending on the expected_exception.
    """
    if expected_exception == 1707:
        return {'status': 'random'}
    else:
        return {'status': 'active'}


def agent_info_exception_and_version(expected_exception: int = None, version: str = '') -> dict:
    """Return dict with status and version to cause or not a exception code 1707 on active_response.send_command().

    Parameters
    ----------
    expected_exception : int
        Test expected exception with the parameters given.
    version : str
        Agent version to return in the agent basic information dictionary.

    Returns
    -------
    dict
        Agent basic information with status depending on the expected_exception.
    """
    if expected_exception == 1707:
        return {'status': 'random', 'version': version} if version else {'status': 'random'}
    else:
        return {'status': 'active', 'version': version} if version else {'status': 'active'}


def agent_config(expected_exception):
    """Return dict to cause or not a exception code 1750 on active_response.send_command()."""
    if expected_exception == 1750:
        return {'active-response': {'disabled': 'yes'}}
    else:
        return {'active-response': {'disabled': 'no'}}


# Tests

@pytest.mark.parametrize('agent_version, builder_type', [
    ('Wazuh v4.2.0', active_response.ARJsonMessage),
    ('Wazuh v4.3.0', active_response.ARJsonMessage),
    ('Wazuh v4.1.0', active_response.ARStrMessage)
])
def test_correct_builder_is_used(agent_version, builder_type):
    """Test if the correct builder is used based on the agent version.

    Parameters
    ----------
    agent_version : str
        The version of the agent.
    builder_type : Type[active_response.ARMessageBuilder]
        The expected type of the builder based on the agent version.
    """
    builder = active_response.ARMessageBuilder.choose_builder(agent_version)
    assert isinstance(builder, builder_type)


@pytest.mark.parametrize('expected_exception, command, arguments', [
    (1650, None, []),
    (1652, 'random', []),
    (1652, 'invalid_cmd', []),
    (None, 'restart-wazuh0', []),
    (None, '!restart-wazuh0', []),
    (None, 'restart-wazuh0', ["arg1", "arg2"])
])
@patch('wazuh.core.common.AR_CONF', new=test_data_path)
def test_create_message(expected_exception, command, arguments):
    """Check if the returned message is correct.

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
            active_response.ARStrMessage().create_message(command=command, arguments=arguments)
    else:
        ret = active_response.ARStrMessage().create_message(command=command, arguments=arguments)
        assert command in ret, f'Command not being returned'
        if arguments:
            assert (arg in ret for arg in arguments), f'Arguments not being added'


@pytest.mark.parametrize('expected_exception, command, arguments, alert', [
    (1650, None, [], None),
    (None, 'restart-wazuh0', [], None),
    (None, 'restart-wazuh0', [], None),
    (None, 'restart-wazuh0', ["arg1", "arg2"], None),
    (1652, 'custom-ar', ["arg1", "arg2"], {"data": {"srcip": "1.1.1.1"}})
])
@patch('wazuh.core.common.AR_CONF', new=test_data_path)
def test_create_json_message(expected_exception, command, arguments, alert):
    """Check if the returned json message is correct.

    Checks if the json message returned by create_json_message(...) contains the
    appropriate json ar message structure.

    Parameters
    ----------
    expected_exception : str
        Exception code expected when calling create_message.
    command : str
        Command to be introduced in the message.
    arguments : list
        Arguments for the command/script.
    alert : dict
        Alert data for the AR message.
    """
    if expected_exception:
        with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
            active_response.ARJsonMessage().create_message(command=command, arguments=arguments, alert=alert)
    else:
        ret = json.loads(
            active_response.ARJsonMessage().create_message(command=command, arguments=arguments, alert=alert))
        assert ret["version"] == 1, f'Wrong message version'
        assert command in ret["command"], f'Command not being returned'
        if arguments:
            assert (arg in ret["parameters"]["extra_args"] for arg in arguments), f'Arguments not being added'
        if alert:
            assert alert == ret["parameters"]["alert"], f'Alert information not being added'


@patch('wazuh.core.common.AR_CONF', new=test_data_path)
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


@pytest.mark.parametrize('agent_id, command, arguments, alert',
                         [
                             ('agent001', 'ls', ['arg1', 'arg2'], {'type': 'Firewall', 'src_ip': '192.168.1.1'})
                         ])
def test_send_ar_message(agent_id, command, arguments, alert):
    """ Checks if the functions behaves as expected

    Parameters
    ----------
    agent_id : str
        Agent id
    command : str
        Command to be used
    arguments : List[str]
        List of arguments for the command
    alert : Dict[str, str]
        Alert information
    """
    mock_agent_info = {'status': 'active', 'version': '3.0'}
    mock_agent_conf = {'active-response': {'disabled': 'no'}}

    mock_wq = MagicMock()

    with patch.object(Agent, 'get_basic_information', return_value=mock_agent_info) as mock_get_basic_info, \
            patch.object(Agent, 'get_config', return_value=mock_agent_conf) as mock_get_config, \
            patch.object(active_response.ARMessageBuilder, 'choose_builder') as mock_choose_builder:
        mock_message_builder = MagicMock()
        mock_message_builder_instance = mock_message_builder.return_value
        mock_choose_builder.return_value = mock_message_builder_instance

        active_response.send_ar_message(agent_id=agent_id, wq=mock_wq, command=command, arguments=arguments,
                                        alert=alert)

        mock_get_basic_info.assert_called_once_with()
        mock_get_config.assert_called_once_with('com', 'active-response', '3.0')
        mock_choose_builder.assert_called_once_with('3.0')
        mock_message_builder_instance.create_message.assert_called_once_with(command=command, arguments=arguments,
                                                                             alert=alert)
        mock_wq.send_msg_to_agent.assert_called_once_with(msg=mock_message_builder_instance.create_message.return_value,
                                                          agent_id=agent_id,
                                                          msg_type=active_response.WazuhQueue.AR_TYPE)


@pytest.mark.parametrize('mock_agent_info, mock_agent_conf, expected_error_code',
                         [
                             ({'status': 'not-active', 'version': '3.0'}, {'active-response': {'disabled': 'no'}}, 1707),
                             ({'status': 'active', 'version': '3.0'}, {'active-response': {'disabled': 'yes'}}, 1750),
                         ])
def test_send_ar_message_nok(mock_agent_info, mock_agent_conf, expected_error_code):
    """ Checks if the function raises the expected exceptions

    Parameters
    ----------
    mock_agent_info : Dict[str, Any]
        Agent information
    mock_agent_conf : Dict[str, Any]
        Agent configuration
    expected_error_code : int
        Expected error code

    """
    agent_id = 'agent001'
    command = 'ls'
    arguments = ['arg1', 'arg2']
    alert = {'type': 'Firewall', 'src_ip': '192.168.1.1'}

    mock_wq = MagicMock()

    with patch.object(Agent, 'get_basic_information', return_value=mock_agent_info) as mock_get_basic_info, \
            patch.object(Agent, 'get_config', return_value=mock_agent_conf) as mock_get_config, \
            patch.object(active_response.ARMessageBuilder, 'choose_builder') as mock_choose_builder:
        mock_message_builder = MagicMock()
        mock_message_builder_instance = mock_message_builder.return_value
        mock_choose_builder.return_value = mock_message_builder_instance

        with pytest.raises(Exception) as e:
            active_response.send_ar_message(agent_id=agent_id, wq=mock_wq, command=command, arguments=arguments,
                                            alert=alert)
        assert e.value.code == expected_error_code
