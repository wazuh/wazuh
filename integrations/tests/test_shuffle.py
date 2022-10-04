# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for shuffle.py integration."""

import sys
import os
import json
import pytest
import requests
import shuffle
from unittest.mock import patch, mock_open

sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), '..', '..'))

alert_template = {'timestamp': 'year-month-dayThours:minuts:seconds+0000',
                  'rule': {'level': 0, 'description': 'alert description',
                           'id': '',
                           'firedtimes': 1},
                  'id': 'alert_id',
                  'full_log': 'full log.', 'decoder': {'name': 'decoder-name'},
                  'location': 'wazuh-X'}

msg_template = '{"severity": 1, "pretext": "WAZUH Alert", "title": "alert description", "text": "full log.", ' \
               '"rule_id": "rule-id", "timestamp": "year-month-dayThours:minuts:seconds+0000", "id": "alert_id", ' \
               '"all_fields": {"timestamp": "year-month-dayThours:minuts:seconds+0000", "rule": {"level": 0, ' \
               '"description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": ' \
               '"full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X"}}'

sys_args_template = ['/var/ossec/integrations/shuffle.py', '/tmp/shuffle-XXXXXX-XXXXXXX.alert', '',
                     'http://<IP>:3001/api/v1/hooks/<HOOK_ID>', ' > /dev/null 2>&1']


def test_main_bad_arguments_exits():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch("builtins.open", mock_open()), \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        shuffle.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == 2


def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch('shuffle.process_args') as process, \
            patch("builtins.open", mock_open()), \
            pytest.raises(Exception):
        process.side_effect = Exception
        shuffle.main(sys_args_template)


def test_main_correct_execution():
    """Test the correct execution of the main function."""
    with patch("builtins.open", mock_open()), \
            patch('json.load', return_value=alert_template), \
            patch('requests.post', return_value=requests.Response):
        shuffle.main(sys_args_template)


def test_process_args_alert_file_exit():
    """Test that process_args function exits when alert file is not found."""
    with patch("builtins.open") as open_mock, \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        open_mock.side_effect = FileNotFoundError
        shuffle.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == 3


def test_process_args():
    """Test the correct execution of the process_args function."""
    with patch("builtins.open", mock_open()) as alert_file, \
            patch('json.load', return_value=alert_template), \
            patch('shuffle.send_msg') as send_msg, \
            patch('shuffle.generate_msg', return_value=msg_template) as generate_msg, \
            patch('requests.post', return_value=requests.Response):
        shuffle.process_args(sys_args_template)
        alert_file.assert_called_once_with(sys_args_template[1])
        generate_msg.assert_called_once_with(alert_template)
        send_msg.assert_called_once_with(msg_template, sys_args_template[3])


def test_process_args_json_exit(tmpdir):
    """Test that the process_args function exits when json exception is raised.

    Parameters
    ----------
    tmpdir: py.path.local
        Path to a temporary directory generated for the tests logs.
    """
    log_file = tmpdir.join('test.log')
    with patch('shuffle.debug_enabled', return_value=True), \
            patch('shuffle.LOG_FILE', str(log_file)), \
            patch("builtins.open", mock_open()), \
            patch('json.load') as json_load, \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        json_load.side_effect = json.decoder.JSONDecodeError("Expecting value", "", 0)
        shuffle.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == 4


def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch("builtins.open", mock_open()), \
            patch('json.load', return_value=alert_template), \
            patch('shuffle.send_msg') as send_msg, \
            patch('shuffle.generate_msg', return_value=''):
        shuffle.process_args(sys_args_template)
        send_msg.assert_not_called()


def test_debug(tmpdir):
    """Test the correct execution of the debug function, writing the expected log when debug mode enabled.

    Parameters
    ----------
    tmpdir: py.path.local
        Path to a temporary directory generated for the tests logs.
    """
    log_file = tmpdir.join('test.log')
    with patch('shuffle.debug_enabled', return_value=True), \
            patch('shuffle.LOG_FILE', str(log_file)):
        shuffle.debug(msg_template)

    assert log_file.read() == f"{shuffle.now}: {msg_template}\n"


@pytest.mark.parametrize('expected_msg, rule_id', [
    ("", shuffle.SKIP_RULE_IDS[0]),
    (msg_template, 'rule-id')
])
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
    assert shuffle.generate_msg(alert_template) == expected_msg


@pytest.mark.parametrize('rule_level, severity', [
    (3, 1),
    (6, 2),
    (8, 3)
])
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
    assert json.loads(shuffle.generate_msg(alert_template))['severity'] == severity


def test_filtered_msg():
    """Test that the alerts with certain rule ids are filtered."""
    for skip_id in shuffle.SKIP_RULE_IDS:
        alert_template['rule']['id'] = skip_id
        assert not shuffle.filter_msg(alert_template)


def test_not_filtered_msg():
    """Test that the alerts that not contain certain rule ids are not filtered."""
    alert_template['rule']['id'] = 'rule-id'
    assert shuffle.filter_msg(alert_template)


def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post') as request_post, \
            pytest.raises(requests.exceptions.ConnectionError):
        request_post.side_effect = requests.exceptions.ConnectionError
        shuffle.send_msg(msg_template, 'http://webhook-url')


def test_send_msg():
    """Test that the send_msg function works as expected"""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    with patch('requests.post', return_value=requests.Response) as request_post:
        shuffle.send_msg(msg_template, sys_args_template[3])
        request_post.assert_called_once_with(sys_args_template[3], data=msg_template, headers=headers, verify=False)
