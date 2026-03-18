#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.exception import WazuhError
        from wazuh.core import active_response
        from wazuh.core.agent import Agent




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
    (None, 'random', []),
    (None, 'invalid_cmd', []),
    (None, 'restart-wazuh0', []),
    (None, '!restart-wazuh0', []),
    (None, 'restart-wazuh0', ["arg1", "arg2"])
])

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
    """
    if expected_exception:
        with pytest.raises(WazuhError, match=f'.* {expected_exception} .*'):
            active_response.ARStrMessage().create_message(command=command, arguments=arguments)
    else:
        ret = active_response.ARStrMessage().create_message(command=command, arguments=arguments)
        assert command in ret, f'Command not being returned'
        if arguments:
            assert all(arg in ret for arg in arguments), 'Arguments not being added'


@pytest.mark.parametrize('expected_exception, command, arguments, alert, command_config', [
    (1650, None, [], None, None),
    (None, 'restart-wazuh0', [], None, None),
    (None, 'restart-wazuh0', ["arg1", "arg2"], None, None),
    (None, 'custom-ar', ["arg1", "arg2"], {"data": {"srcip": "1.1.1.1"}}, None),
    (None, 'restart-wazuh0', [], None, {
        'name': 'restart-wazuh0',
        'executable': 'restart-wazuh',
        'timeout': 0,
        'extra_params': []
    })
])
@patch('wazuh.core.active_response.read_cluster_config', return_value={'disabled': False})
@patch('wazuh.core.active_response.get_node', return_value={'node': 'master'})
def test_create_json_message(mock_get_node, mock_read_cluster_config, expected_exception, command, arguments, alert, command_config):
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
            active_response.ARJsonMessage().create_message(
                command=command,
                arguments=arguments,
                alert=alert,
                command_config=command_config
            )
    else:
        ret = json.loads(
            active_response.ARJsonMessage().create_message(
                command=command,
                arguments=arguments,
                alert=alert,
                command_config=command_config
            ))
        assert ret["version"] == 1, f'Wrong message version'
        assert ret["command"] == command, 'Command not being returned'
        if arguments:
            assert all(arg in ret["parameters"]["extra_args"] for arg in arguments), 'Arguments not being added'
        if alert:
            assert alert == ret["parameters"]["alert"], f'Alert information not being added'
        if command_config:
            assert ret["parameters"]["command"] == command_config, 'Command config not being added'


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


@pytest.mark.parametrize('agent_id, agent_version, command, arguments, alert', [
    ('agent001', 'Wazuh v4.14.0', 'ls', ['arg1', 'arg2'], 
    {'type': 'Firewall', 'src_ip': '192.168.1.1'})
])
def test_send_ar_message(agent_id, agent_version, command, arguments, alert):
    """Checks if the `send_ar_message` function behaves as expected."""
    mock_agent_conf = {'active-response': {'disabled': 'no'}}

    mock_wq = MagicMock()

    with patch.object(Agent, 'get_config', return_value=mock_agent_conf) as mock_get_config, \
            patch.object(active_response.ARMessageBuilder, 'choose_builder') as mock_choose_builder:
        mock_message_builder_instance = MagicMock()
        mock_choose_builder.return_value = mock_message_builder_instance

        active_response.send_ar_message(
            agent_id=agent_id,
            agent_version=agent_version,
            wq=mock_wq, command=command,
            arguments=arguments,
            alert=alert
        )

        mock_get_config.assert_called_once_with('com', 'active-response', agent_version)
        mock_choose_builder.assert_called_once_with(agent_version)
        mock_message_builder_instance.create_message.assert_called_once_with(
            command=command,
            arguments=arguments,
            alert=alert,
            command_config=None
        )
        mock_wq.send_msg_to_agent.assert_called_once_with(msg=mock_message_builder_instance.create_message.return_value,
                                                          agent_id=agent_id,
                                                          msg_type=active_response.WazuhQueue.AR_TYPE)


def test_send_ar_message_with_command_config():
    """Checks if send_ar_message forwards the command_config field to the message builder."""
    agent_id = 'agent001'
    agent_version = 'Wazuh v4.14.0'
    command = 'restart-wazuh0'
    arguments = ['arg1']
    alert = {'type': 'Firewall', 'src_ip': '192.168.1.1'}
    command_config = {
        'name': 'restart-wazuh0',
        'executable': 'restart-wazuh',
        'timeout': 0,
        'extra_params': []
    }

    mock_agent_conf = {'active-response': {'disabled': 'no'}}
    mock_wq = MagicMock()

    with patch.object(Agent, 'get_config', return_value=mock_agent_conf) as mock_get_config, \
            patch.object(active_response.ARMessageBuilder, 'choose_builder') as mock_choose_builder:
        mock_message_builder_instance = MagicMock()
        mock_choose_builder.return_value = mock_message_builder_instance

        active_response.send_ar_message(
            agent_id=agent_id,
            agent_version=agent_version,
            wq=mock_wq,
            command=command,
            arguments=arguments,
            alert=alert,
            command_config=command_config
        )

        mock_get_config.assert_called_once_with('com', 'active-response', agent_version)
        mock_choose_builder.assert_called_once_with(agent_version)
        mock_message_builder_instance.create_message.assert_called_once_with(
            command=command,
            arguments=arguments,
            alert=alert,
            command_config=command_config
        )
        mock_wq.send_msg_to_agent.assert_called_once_with(
            msg=mock_message_builder_instance.create_message.return_value,
            agent_id=agent_id,
            msg_type=active_response.WazuhQueue.AR_TYPE
        )


@pytest.mark.parametrize('agent_version, mock_agent_conf, expected_error_code', [
    ('Wazuh v4.14.0', {'active-response': {'disabled': 'yes'}}, 1750),
])
def test_send_ar_message_nok(agent_version, mock_agent_conf, expected_error_code):
    """Checks if the function raises the expected exceptions."""
    agent_id = 'agent001'
    command = 'ls'
    arguments = ['arg1', 'arg2']
    alert = {'type': 'Firewall', 'src_ip': '192.168.1.1'}

    mock_wq = MagicMock()

    with patch.object(Agent, 'get_config', return_value=mock_agent_conf) as mock_get_config, \
            patch.object(active_response.ARMessageBuilder, 'choose_builder') as mock_choose_builder:
        mock_message_builder_instance = MagicMock()
        mock_choose_builder.return_value = mock_message_builder_instance

        with pytest.raises(WazuhError) as e:
            active_response.send_ar_message(
                agent_id=agent_id,
                agent_version=agent_version,
                wq=mock_wq,
                command=command,
                arguments=arguments,
                alert=alert
            )
        assert e.value.code == expected_error_code

@patch('wazuh.core.active_response.read_cluster_config', return_value={'disabled': False})
@patch('wazuh.core.active_response.get_node', return_value={'node': 'master'})
def test_create_json_message_includes_command_config(mock_get_node, mock_read_cluster_config):
    command_config = {
        'name': 'restart-wazuh0',
        'executable': 'restart-wazuh',
        'timeout': 0,
        'extra_params': []
    }

    ret = json.loads(
        active_response.ARJsonMessage().create_message(
            command='restart-wazuh0',
            arguments=['arg1'],
            alert={'rule': {'id': '100001'}},
            command_config=command_config
        )
    )

    assert ret['command'] == 'restart-wazuh0'
    assert ret['parameters']['extra_args'] == ['arg1']
    assert ret['parameters']['alert'] == {'rule': {'id': '100001'}}
    assert ret['parameters']['command'] == command_config

@patch('wazuh.core.active_response.read_cluster_config', return_value={'disabled': False})
@patch('wazuh.core.active_response.get_node', return_value={'node': 'master'})
def test_create_json_message_omits_empty_command_config(mock_get_node, mock_read_cluster_config):
    """Check that an empty command_config is not added to the JSON AR payload."""
    ret = json.loads(
        active_response.ARJsonMessage().create_message(
            command='restart-wazuh0',
            arguments=['arg1'],
            alert={'rule': {'id': '100001'}},
            command_config={}
        )
    )

    assert ret['command'] == 'restart-wazuh0'
    assert ret['parameters']['extra_args'] == ['arg1']
    assert ret['parameters']['alert'] == {'rule': {'id': '100001'}}
    assert 'command' not in ret['parameters']
