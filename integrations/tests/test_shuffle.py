# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for shuffle.py integration."""

import json
import os
import sys
from unittest.mock import mock_open, patch

import pytest
import requests
import shuffle as shuffle

# Exit error codes
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))

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

options_template = {'pretext': 'Wazuh-X -- Alert generated'}

msg_template = (
    '{"severity": 1, "pretext": "Wazuh-X -- Alert generated", "title": "alert description", "text": "full log.", '
    '"rule_id": "rule-id", "timestamp": "2023-02-23T00:00:00+00:00", "id": "alert_id", '
    '"all_fields": {"timestamp": "2023-02-23T00:00:00+00:00", "rule": {"level": 0, '
    '"description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": '
    '"full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X"}}'
)

sys_args_template = [
    '/var/ossec/integrations/shuffle.py',
    '/tmp/shuffle-XXXXXX-XXXXXXX.alert',
    '',
    'http://<IP>:3001/api/v1/hooks/<HOOK_ID>',
    ' > /dev/null 2>&1',
    '/tmp/virustotal-XXXXXX-XXXXXXX.options',
]


def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch('shuffle.open', mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        shuffle.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == ERR_BAD_ARGUMENTS


def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch('shuffle.open', mock_open()), patch('shuffle.process_args') as process, pytest.raises(Exception):
        process.side_effect = Exception
        shuffle.main(sys_args_template)


def test_main():
    """Test the correct execution of the main function."""
    with patch('shuffle.open', mock_open()), patch('json.load', return_value=alert_template), patch(
        'requests.post', return_value=requests.Response
    ), patch('shuffle.process_args') as process:
        shuffle.main(sys_args_template)
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
    with patch('shuffle.open', mock_open()), patch('json.load') as json_load, pytest.raises(
        SystemExit
    ) as pytest_wrapped_e:
        json_load.side_effect = side_effect
        shuffle.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == return_value


def test_process_args():
    """Test the correct execution of the process_args function."""
    with patch('shuffle.open', mock_open()), patch('shuffle.get_json_alert') as alert_load, patch(
        'shuffle.get_json_options'
    ) as options_load, patch('shuffle.send_msg') as send_msg, patch(
        'shuffle.generate_msg', return_value=msg_template
    ) as generate_msg, patch('requests.post', return_value=requests.Response):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        shuffle.process_args(sys_args_template)
        generate_msg.assert_called_once_with(alert_template, options_template)
        generated_msg = shuffle.generate_msg(alert_template, options_template)
        assert generated_msg == msg_template
        send_msg.assert_called_once_with(msg_template, sys_args_template[3])


def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch('shuffle.open', mock_open()), patch('json.load', return_value=alert_template), patch(
        'shuffle.send_msg'
    ) as send_msg, patch('shuffle.generate_msg', return_value=''):
        shuffle.process_args(sys_args_template)
        send_msg.assert_not_called()


def test_debug():
    """Test the correct execution of the debug function, writing the expected log when debug mode enabled."""
    with patch('shuffle.debug_enabled', return_value=True), patch('shuffle.open', mock_open()) as open_mock, patch(
        'shuffle.LOG_FILE', return_value='integrations.log'
    ) as log_file:
        shuffle.debug(msg_template)
        open_mock.assert_called_with(log_file, 'a')
        open_mock().write.assert_called_with(f'{msg_template}\n')


@pytest.mark.parametrize('rule_id, expected_msg', [(shuffle.SKIP_RULE_IDS[0], ''), ('rule-id', msg_template)])
def test_generate_msg(expected_msg, rule_id):
    """Test that the expected message is generated when json_alert received.

    Parameters
    ----------
    expected_msg : str
        Message that should be returned by the generate_msg function.
    rule_id : str
        ID of the rule to be processed.
    """
    alert_template['rule']['id'] = rule_id
    assert shuffle.generate_msg(alert_template, options_template) == expected_msg


@pytest.mark.parametrize('rule_level, severity', [(3, 1), (5, 2), (7, 2), (8, 3)])
def test_generate_msg_severity(rule_level, severity):
    """Test that the different rule levels generate different severities in the message delivered by generate_msg.

    Parameters
    ----------
    rule_level: int
        Integer that represents the rule level.
    severity: int
        Expected severity level for the corresponding rule level.
    """
    alert_template['rule']['level'] = rule_level
    assert json.loads(shuffle.generate_msg(alert_template, options_template))['severity'] == severity


@pytest.mark.parametrize('rule_id, result', [(shuffle.SKIP_RULE_IDS[0], False), ('rule-id', True)])
def test_filter_msg(rule_id, result):
    """Test the filter_msg function.

    Parameters
    ----------
    rule_id: str
        String that represents the alert rule ID to be checked.
    result: bool
        Expected result of the filter_msg function for the given alert.
    """
    alert_template['rule']['id'] = rule_id
    assert result == shuffle.filter_msg(alert_template)


def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post') as request_post, pytest.raises(requests.exceptions.ConnectionError):
        request_post.side_effect = requests.exceptions.ConnectionError
        shuffle.send_msg(msg_template, 'http://webhook-url')


def test_send_msg():
    """Test that the send_msg function works as expected."""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    with patch('requests.post', return_value=requests.Response) as request_post:
        shuffle.send_msg(msg_template, sys_args_template[3])
        request_post.assert_called_once_with(sys_args_template[3], data=msg_template, headers=headers, timeout=10)
