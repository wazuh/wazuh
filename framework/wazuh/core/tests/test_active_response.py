#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.exception import WazuhError
        from wazuh.core import active_response

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

@pytest.mark.parametrize('expected_exception, command, arguments, custom', [
    (1650, None, [], False),
    (1652, 'random', [], False),
    (1652, 'invalid_cmd', [], False),
    (None, 'restart-wazuh0', [], False),
    (None, 'restart-wazuh0', [], True),
    (None, 'restart-wazuh0', ["arg1", "arg2"], False)
])
@patch('wazuh.core.common.AR_CONF', new=test_data_path)
def test_create_message(expected_exception, command, arguments, custom):
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
            active_response.create_message(command=command, arguments=arguments, custom=custom)
    else:
        ret = active_response.create_message(command=command, arguments=arguments, custom=custom)
        assert command in ret, f'Command not being returned'
        if arguments:
            assert (arg in ret for arg in arguments), f'Arguments not being added'
        if custom:
            assert '!' in ret, f'! symbol not being added when custom command'


@pytest.mark.parametrize('expected_exception, command, arguments, alert', [
    (1650, None, [], None),
    (None, 'restart-wazuh0', [], None),
    (None, 'restart-wazuh0', [], None),
    (None, 'restart-wazuh0', ["arg1", "arg2"], None),
    (None, 'custom-ar', ["arg1", "arg2"], {"data": {"srcip": "1.1.1.1"}})
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
            active_response.create_json_message(command=command, arguments=arguments, alert=alert)
    else:
        ret = json.loads(active_response.create_json_message(command=command, arguments=arguments, alert=alert))
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
