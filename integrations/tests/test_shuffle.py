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

msg_template = '{"severity": 1, "pretext": "WAZUH Alert", "title": "alert description", "text": "full log.", "rule_id": "rule-id", "timestamp": "year-month-dayThours:minuts:seconds+0000", "id": "alert_id", "all_fields": {"timestamp": "year-month-dayThours:minuts:seconds+0000", "rule": {"level": 0, "description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": "full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X"}}'

sys_args_template = ['/var/ossec/integrations/shuffle.py', '/tmp/shuffle-XXXXXX-XXXXXXX.alert', '',
                     'http://<IP>:3001/api/v1/hooks/<HOOK_ID>', ' > /dev/null 2>&1']


@pytest.mark.parametrize('args', [sys_args_template])
def test_main_alert_file_exit(args):
    """
    Test that main function exits when alert file is not found

    Parameters
    ----------
    args: list[str]
       list of the arguments passed to the main function

    -------

    """
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        shuffle.main(args)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 3


@pytest.mark.parametrize('args, alert', [(sys_args_template, alert_template)])
def test_main(args, alert):
    """
    Test the correct execution of the main function

    Parameters
    ----------
    args: list[str]
       list of the arguments passed to the main function

    alert: json
       template alert read from the alert file


    """
    with patch("builtins.open", mock_open()), \
            patch('json.load', return_value=alert), \
            patch('requests.post', return_value=requests.Response):
        shuffle.main(args)

@pytest.mark.parametrize('debug_enabled,args', [(True, sys_args_template)])
def test_main_json_exit(tmpdir, debug_enabled, args):
    """
    Test the correct execution of the main function

    Parameters
    ----------
    tmpdir: py.path.local
        Path to a temporary directory generated for the tests logs

    debug_enabled: bool
        determines if debug mode is enabled or not

    args: list[str]
       list of the arguments passed to the main function


    """
    log_file = tmpdir.join('test.log')
    with patch('shuffle.debug_enabled', return_value=debug_enabled), \
            patch('shuffle.LOG_FILE', str(log_file)), \
            patch("builtins.open", mock_open()), \
            pytest.raises(SystemExit) as pytest_wrapped_e:
        shuffle.main(args)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 4

@pytest.mark.parametrize('args, alert', [(sys_args_template, alert_template)])
def test_main_not_sending_message(args, alert):
    """
    Test that the send_msg function is not executed due to empty message after generate_msg

    Parameters
    ----------
    args: list[str]
       list of the arguments passed to the main function

    alert: json
       template alert read from the alert file
    """
    with patch("builtins.open", mock_open()), \
            patch('json.load', return_value=alert), \
            patch('shuffle.generate_msg', return_value=''):
        shuffle.main(args)


@pytest.mark.parametrize('debug_enabled, msg, expected_result', [
    (True, msg_template, f"{shuffle.now}: {msg_template}\n")
])
def test_debug(tmpdir, debug_enabled, msg, expected_result):
    """
    Test the correct execution of the debug function, writing the expected log when debug mode enabled

    Parameters
    ----------
    tmpdir: py.path.local
        Path to a temporary directory generated for the tests logs

    debug_enabled: bool
        determines if debug mode is enabled or not

    msg: str
        message to be logged by the debug function

    expected_result: str
        expected log to be obtained after the execution of the debug function


    """
    log_file = tmpdir.join('test.log')
    with patch('shuffle.debug_enabled', return_value=debug_enabled), \
            patch('shuffle.LOG_FILE', str(log_file)):
        shuffle.debug(msg)

    assert log_file.read() == expected_result


@pytest.mark.parametrize('alert, expected_msg, rule_id', [
    (alert_template, "", shuffle.SKIP_RULE_IDS[0]),
    (alert_template, msg_template, 'rule-id')
])
def test_generate_msg(alert, expected_msg, rule_id):
    """
    Test that the expected message is generated when json_alert received.

    Parameters
    ----------
    alert : json
        json data that simulates the values that could have been obtained from alert_file_location.

    expected_msg : str
        message that should be returned by the generate_msg function
    """
    alert['rule']['id'] = rule_id
    assert shuffle.generate_msg(alert) == expected_msg


@pytest.mark.parametrize('alert, rule_level, severity', [
    (alert_template, 3, 1),
    (alert_template, 6, 2),
    (alert_template, 8, 3)
])
def test_generate_msg_severity(alert, rule_level, severity):
    """
    Test that the different rule levels generate different severities in the message delivered by generate_msg

    Parameters
    ----------
    alert: json
        json that that simulates the values that could have been obtained from alert_file_location

    rule_level: int
        integer that represents the rule level

    severity: int
        expected severity level for the corresponding rule level

    """

    alert['rule']['level'] = rule_level
    assert json.loads(shuffle.generate_msg(alert))['severity'] == severity


@pytest.mark.parametrize('alert, rule_ids', [(alert_template, shuffle.SKIP_RULE_IDS)])
def test_filtered_msg(alert, rule_ids):
    """
    Test that the alerts with certain rule ids are filtered.

    Parameters
    ----------
    alert : json
        json data that simulates the values that could have been obtained from alert_file_location.
    rule_ids: str
         rule ids that will get the alert to be filtered

    """
    for skip_id in rule_ids:
        alert['rule']['id'] = skip_id
        assert not shuffle.filter_msg(alert)


@pytest.mark.parametrize('alert, rule_id', [(alert_template, 'rule-id')])
def test_not_filtered_msg(alert, rule_id):
    """
    Test that the alerts that not contain certain rule ids are not filtered.

    Parameters
    ----------
    alert : json
        json data that simulates the values that could have been obtained from alert_file_location.

    rule_id: str
         rule id that will not get the alert to be filtered
    """
    alert['rule']['id'] = rule_id
    assert shuffle.filter_msg(alert)


@pytest.mark.parametrize('msg, url', [(msg_template, 'http://webhook-url')])
def test_send_msg_raise_exception(msg, url):
    """
    Test that the send_msg function will raise an exception when passed the wrong webhook url

    Parameters
    ----------
    msg: str
        message to be sent via integratord

    url: str
        webhook url of the integrated service

    """
    with patch('requests.post') as sendmock, \
            pytest.raises(requests.exceptions.ConnectionError):
        sendmock.side_effect = requests.exceptions.ConnectionError
        shuffle.send_msg(msg, url)
