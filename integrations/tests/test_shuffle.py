# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for shuffle.py integration."""

import sys
import os
import json
import pytest
import shuffle

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

    msg : str
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

    """
    alert['rule']['id'] = rule_id
    assert shuffle.filter_msg(alert)
