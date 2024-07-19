# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for pagerduty.py integration."""

import json
import os
import sys
from unittest.mock import mock_open, patch

import pagerduty as pagerduty
import pytest
import requests

# Exit error codes
ERR_NO_APIKEY = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))  # Necessary to run PyTest

apikey_pagerduty = ''

"""
    Mockup messages for testing
"""

alert_template = {
    'timestamp': '2023-02-23T00:00:00+00:00',
    'rule': {'level': 0, 'description': 'alert description', 'id': '', 'firedtimes': 1},
    'id': 'alert_id',
    'full_log': 'full log.',
    'decoder': {'name': 'decoder-name'},
    'location': 'wazuh-X',
}

options_template = {'client': 'Wazuh-X -- Alert generated'}

msg_template = {
    'payload': {
        'summary': 'alert description',
        'timestamp': '2023-02-23T00:00:00+00:00',
        'source': 'v',
        'severity': 'info',
    },
    'routing_key': f'{apikey_pagerduty}',
    'event_action': 'trigger',
    'client': 'Wazuh-X -- Alert generated',
    'client_url': 'https://monitoring.example.com',
}

sys_args_template = [
    '/var/ossec/integrations/pagerduty.py',
    '/tmp/pagerduty-XXXXXX-XXXXXXX.alert',
    f'{apikey_pagerduty}',
    '',
    '>/dev/null 2>&1',
    '/tmp/pagerduty-XXXXXX-XXXXXXX.options',
]


def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch('pagerduty.open', mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        pagerduty.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == ERR_BAD_ARGUMENTS


def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch('pagerduty.open', mock_open()), pytest.raises(Exception), patch('pagerduty.process_args') as process:
        process.side_effect = Exception
        pagerduty.main(sys_args_template)


def test_main():
    """Test the correct execution of the main function."""
    with patch('pagerduty.open', mock_open()), patch('json.load', return_value=alert_template), patch(
        'json.load', return_value=options_template
    ), patch('requests.post', return_value=requests.Response), patch('pagerduty.process_args') as process:
        pagerduty.main(sys_args_template)
        process.assert_called_once_with(sys_args_template)


@pytest.mark.parametrize(
    'side_effect, return_value',
    [
        (FileNotFoundError, ERR_FILE_NOT_FOUND),
        (json.decoder.JSONDecodeError('Expecting value', '', 0), ERR_INVALID_JSON),
    ],
)
def test_process_args_exit(side_effect, return_value):
    """Test the process_args function exit codes.

    Parameters
    ----------
    side_effect : Exception
        Exception to be raised when there is a failure inside the Load alert section try.
    return_value : int
        Value to be returned when sys.exit() is invoked.
    """
    with patch('pagerduty.open', mock_open()), patch('json.load') as json_load, pytest.raises(
        SystemExit
    ) as pytest_wrapped_e:
        json_load.side_effect = side_effect
        pagerduty.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == return_value


def test_process_args():
    """Test the correct execution of the process_args function."""
    with patch('pagerduty.open', mock_open()), patch('pagerduty.get_json_alert') as alert_load, patch(
        'pagerduty.get_json_options'
    ) as options_load, patch('pagerduty.send_msg') as send_msg, patch(
        'pagerduty.generate_msg', return_value=msg_template
    ) as generate_msg, patch('requests.post', return_value=requests.Response):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        pagerduty.process_args(sys_args_template)
        generate_msg.assert_called_once_with(alert_template, options_template, sys_args_template[2])
        generated_msg = pagerduty.generate_msg(alert_template, options_template, sys_args_template[2])
        assert generated_msg == msg_template
        send_msg.assert_called_once_with(msg_template)


def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch('pagerduty.open', mock_open()), patch('pagerduty.get_json_alert') as alert_load, patch(
        'pagerduty.get_json_options'
    ) as options_load, patch('pagerduty.send_msg') as send_msg, patch(
        'pagerduty.generate_msg', return_value=''
    ), pytest.raises(Exception):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        pagerduty.process_args(sys_args_template)
        send_msg.assert_not_called()


def test_debug():
    """Test the correct execution of the debug function, writing the expected log when debug mode enabled."""
    with patch('pagerduty.debug_enabled', return_value=True), patch('pagerduty.open', mock_open()) as open_mock, patch(
        'pagerduty.LOG_FILE', return_value='integrations.log'
    ) as log_file:
        pagerduty.debug(str(msg_template))
        open_mock.assert_called_with(log_file, 'a')
        open_mock().write.assert_called_with(str(msg_template) + '\n')


def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post') as request_post, pytest.raises(requests.exceptions.ConnectionError):
        request_post.side_effect = requests.exceptions.ConnectionError
        pagerduty.send_msg(msg_template)


def test_send_msg():
    """Test that the send_msg function works as expected."""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    with patch('requests.post', return_value=requests.Response) as request_post:
        pagerduty.send_msg(msg_template)
        url = 'https://events.pagerduty.com/v2/enqueue'
        request_post.assert_called_once_with(url, data=msg_template, headers=headers, timeout=10)
