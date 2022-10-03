# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for shuffle.py integration."""

import sys
import os
import pytest
import shuffle
import random

sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), '..', '..'))

alert_template = {'timestamp': 'year-month-dayThours:minuts:seconds+0000',
                  'rule': {'level': 0, 'description': 'alert description',
                           'id': 'rule-id',
                           'firedtimes': 1},
                  'id': 'alert_id',
                  'full_log': 'full log.', 'decoder': {'name': 'decoder-name'},
                  'location': 'wazuh-X'}

msg_template = '{"severity": 1, "pretext": "WAZUH Alert", "title": "alert description", "text": "full log.", "rule_id": "rule-id", "timestamp": "year-month-dayThours:minuts:seconds+0000", "id": "alert_id", "all_fields": {"timestamp": "year-month-dayThours:minuts:seconds+0000", "rule": {"level": 0, "description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": "full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X"}}'


@pytest.mark.parametrize('alert, expected_msg, rule_id', [
    (alert_template, msg_template, 'rule-id'),
    (alert_template, "", shuffle.SKIP_RULE_IDS[0])
])
def test_generate_msg(alert, expected_msg, rule_id):
    """
    Test that the expected message is generated when json_alert received.

    Parameters
    ----------
    json_alert : json
        json data that simulates the values that could have been obtained from alert_file_location.

    msg : str
        message that should be returned by the generate_msg function
    """
    alert['rule']['id'] = rule_id
    assert shuffle.generate_msg(alert) == expected_msg


@pytest.mark.parametrize('json_alert', [({'timestamp': 'year-month-dayThours:minuts:seconds+0000',
                                          'rule': {'level': 0, 'description': 'alert description',
                                                   'id': 'rule-id',
                                                   'firedtimes': 1},
                                          'id': 'alert_id',
                                          'full_log': 'full log.', 'decoder': {'name': 'decoder-name'},
                                          'location': 'wazuh-X'})])
def test_filtered_msg(json_alert):
    """
    Test that the alerts with certain rule ids are filtered.

    Parameters
    ----------
    json_alert : json
        json data that simulates the values that could have been obtained from alert_file_location.

    """
    json_alert['rule']['id'] = random.choice(shuffle.SKIP_RULE_IDS)

    assert not shuffle.filter_msg(json_alert)


@pytest.mark.parametrize('json_alert', [({'timestamp': 'year-month-dayThours:minuts:seconds+0000',
                                          'rule': {'level': 0, 'description': 'alert description',
                                                   'id': 'rule-id',
                                                   'firedtimes': 1},
                                          'id': 'alert_id',
                                          'full_log': 'full log.', 'decoder': {'name': 'decoder-name'},
                                          'location': 'wazuh-X'})])
def test_not_filtered_msg(json_alert):
    """
    Test that the alerts that not contain certain rule ids are not filtered.

    Parameters
    ----------
    json_alert : json
        json data that simulates the values that could have been obtained from alert_file_location.

    """
    assert shuffle.filter_msg(json_alert)
