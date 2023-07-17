# Copyright (C) 2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for slack.py integration."""

import json
import os
import pytest
import requests
import slack as slack
import sys
import logging
from unittest.mock import patch, mock_open, MagicMock

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')) #Necessary to run PyTest

"""
    Mockup messages for testing
"""

alert_template = {
    'timestamp': '2023-02-23T00:00:00+00:00',
    'rule': {
        'level': 0,
        'description': 'alert description',
        'id': '',
        'firedtimes': 1
    },
    'id': 'alert_id',
    'full_log': 'full log.',
    'decoder': {
        'name': 'decoder-name'
    },
    'location': 'wazuh-X'
}

options_template = {
    'pretext': 'Wazuh-X -- Alert generated',
    'author_name': 'The amazing Wazuh',
    'footer': 'Slack API'
}

msg_template = '{"severity": 1, "pretext": "Wazuh-X -- Alert generated", "title": "alert description", "text": "full log.", ' \
               '"rule_id": "rule-id", "timestamp": "year-month-dayThours:minuts:seconds+0000", "id": "alert_id", ' \
               '"all_fields": {"timestamp": "2023-02-23T00:00:00+00:00", "rule": {"level": 0, ' \
               '"description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": ' \
               '"full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X", "author_name": "The amazing Wazuh",'\
               '"footer": "Slack API"}'
slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

alerts_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/alerts.json')
sys_args_template = ['/var/ossec/integrations/slack.py', alerts_file, '', slack_webhook]


def test_main_bad_arguments_exit():
    """Test that main function exits when wrong number of arguments are passed."""
    with patch("slack.open", mock_open()), pytest.raises(SystemExit) as pytest_wrapped_e:
        slack.main(sys_args_template[0:2])
    assert pytest_wrapped_e.value.code == slack.ERR_INVALID_ARGUMENTS

def test_main_exception():
    """Test exception handling in main when process_args raises an exception."""
    with patch("slack.open", mock_open()), pytest.raises(Exception),patch('slack.process_args') as process:
        process.side_effect = Exception
        slack.main(sys_args_template)

def test_main():
    """Test the correct execution of the main function."""
    with patch("slack.open", mock_open()), patch('json.load', return_value=alert_template),\
        patch('json.load', return_value=options_template),\
        patch('requests.post', return_value=requests.Response), patch('slack.process_args') as process:
        slack.main(sys_args_template)
        process.assert_called_once_with(sys_args_template)

@pytest.mark.parametrize('side_effect, return_value', [
    (FileNotFoundError, slack.ERR_FILE_NOT_FOUND),
    (json.decoder.JSONDecodeError("Expecting value", "", 0), slack.ERR_INVALID_JSON)
])
def test_process_args_exit(side_effect, return_value):
    """Test the process_args function exit codes.

    Parameters
    ----------
    side_effect : Exception
        Exception to be raised when there is a failure inside the Load alert section try.
    return_value : int
        Value to be returned when sys.exit() is invoked.
    """
    with patch("slack.open", mock_open()), \
            patch('json.load') as json_load, \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        json_load.side_effect = side_effect
        slack.process_args(sys_args_template)
    assert pytest_wrapped_e.value.code == return_value

def test_process_args():
    """Test the correct execution of the process_args function."""
    with patch("slack.open", mock_open()), \
            patch('slack.get_json_alert') as alert_load,\
            patch('slack.get_json_options') as options_load,\
            patch('slack.send_msg') as send_msg, \
            patch('slack.generate_msg', return_value=msg_template) as generate_msg, \
            patch('requests.post', return_value=requests.Response):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        slack.process_args(sys_args_template)
        generate_msg.assert_called_once_with(alert_template,options_template)
        generated_msg = slack.generate_msg(alert_template,options_template)
        assert generated_msg==msg_template
        send_msg.assert_called_once_with(msg_template, sys_args_template[3])

def test_process_args_not_sending_message():
    """Test that the send_msg function is not executed due to empty message after generate_msg."""
    with patch("slack.open", mock_open()), \
            patch('slack.get_json_alert') as alert_load,\
            patch('slack.get_json_options') as options_load,\
            patch('slack.send_msg') as send_msg, \
            patch('slack.generate_msg', return_value=''), \
            pytest.raises(Exception):
        alert_load.return_value = alert_template
        options_load.return_value = options_template
        slack.process_args(sys_args_template)
        send_msg.assert_not_called()

def test_send_msg_raise_exception():
    """Test that the send_msg function will raise an exception when passed the wrong webhook url."""
    with patch('requests.post') as request_post, \
            pytest.raises(requests.exceptions.ConnectionError):
        request_post.side_effect = requests.exceptions.ConnectionError
        slack.send_msg(msg_template, 'http://webhook-url')

def test_send_msg():
    """Test that the send_msg function works as expected."""
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch('requests.post', return_value=mock_response) as request_post:
        with patch('json.dumps', return_value=''):
            slack.send_msg(msg_template, sys_args_template[3])
            request_post.assert_called_once_with(sys_args_template[3], data=msg_template, headers=headers, timeout=5)

def test_logger(caplog):
    """Test the correct execution of the logger."""
    with patch('slack.send_msg'):
        with caplog.at_level(logging.DEBUG, logger='slack'):
            args = sys_args_template[:]
            args.append('info')
            slack.main(args)

    # Assert console log correctness
    assert caplog.records[0].message == 'Running Slack script'
    assert caplog.records[1].message == f'Alerts file location: {sys_args_template[1]}'
    assert caplog.records[-1].levelname == 'INFO'
    assert "DEBUG" not in caplog.text
    # Assert the log file is created and is not empty
    assert os.path.exists(slack.LOG_FILE)
    assert os.path.getsize(slack.LOG_FILE) > 0
