# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for shuffle.py integration."""

import sys
import os
import pytest
import shuffle
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(
    os.path.realpath(__file__)), '..', '..'))

@pytest.mark.parametrize('json_alert, msg', [( {'timestamp': 'year-month-dayThours:minuts:seconds+0000',
                                                 'rule': {'level': 0, 'description': 'alert description',
                                                          'id': 'rule-id',
                                                          'firedtimes': 1},
                                                'id': 'alert_id',
                                                 'full_log': 'full log.', 'decoder': {'name': 'decoder-name'},
                                                 'location': 'wazuh-X'},
                                                '{"severity": 1, "pretext": "WAZUH Alert", "title": "alert description", "text": "full log.", "rule_id": "rule-id", "timestamp": "year-month-dayThours:minuts:seconds+0000", "id": "alert_id", "all_fields": {"timestamp": "year-month-dayThours:minuts:seconds+0000", "rule": {"level": 0, "description": "alert description", "id": "rule-id", "firedtimes": 1}, "id": "alert_id", "full_log": "full log.", "decoder": {"name": "decoder-name"}, "location": "wazuh-X"}}')])


def test_generate_msg(json_alert, msg):
    """
        Test that the expected message is generated when json_alert received.

        Parameters
        ----------
        json_alert : json
            json data that simulates the values that could have
            been obtained from alert_file_location.

        msg : str
            message that should be retourned by the generate_msg function
        """
    assert shuffle.generate_msg(json_alert) == msg
    # assert shuffle.generate_msg(json_alert) == msg


def test_filter_msg():
    pass


def test_send_msg():
    pass
