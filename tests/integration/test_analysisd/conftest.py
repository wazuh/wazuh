# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import shutil
import time
from collections import defaultdict
from datetime import datetime

import pytest

from wazuh_testing.constants.keys.events import *
from wazuh_testing.constants.paths.configurations import CUSTOM_RULES_PATH
from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH, OSSEC_LOG_PATH
from wazuh_testing.constants.users import WAZUH_UNIX_GROUP, WAZUH_UNIX_USER
from wazuh_testing.modules.analysisd import patterns, utils
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils import callbacks


@pytest.fixture()
def prepare_custom_rules_file(request, test_metadata):
    """Configure a syscollector custom rules for testing.
    Restarting wazuh-analysisd is required to apply this changes.
    """
    data_dir = getattr(request.module, 'RULES_SAMPLE_PATH')
    source_rule = os.path.join(data_dir, test_metadata['rules_file'])
    target_rule = os.path.join(CUSTOM_RULES_PATH, test_metadata['rules_file'])

    # copy custom rule with specific privileges
    shutil.copy(source_rule, target_rule)
    shutil.chown(target_rule, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    yield

    # remove custom rule
    os.remove(target_rule)


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    log_monitor = file_monitor.FileMonitor(OSSEC_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_STARTED))


def wait_mtime(path, time_step=5, timeout=-1):
    """
    Wait until the monitored log is not being modified.

    Args:
        path (str): Path to the file.
        time_step (int, optional): Time step between checks of mtime. Default `5`
        timeout (int, optional): Timeout for function to fail. Default `-1`

    Raises:
        FileNotFoundError: Raised when the file does not exist.
        TimeoutError: Raised when timeout is reached.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found.")

    last_mtime = 0.0
    tic = datetime.now().timestamp()

    while last_mtime != os.path.getmtime(path):
        last_mtime = os.path.getmtime(path)
        time.sleep(time_step)

        if last_mtime - tic >= timeout:
            raise TimeoutError("Reached timeout.")


@pytest.fixture(scope='module')
def generate_events_and_alerts(request):
    """Read the specified yaml and generate every event and alert using the input from every test case.

    Alerts are saved in a list and events have the following structure (example):
        {
            'path':
            {
                'Added': event
                'Modified': event
                'Deleted': event
            }
            ...
        }
    """
    events = defaultdict(dict)

    test_cases = getattr(request.module, 'test_metadata')
    socket_controller = getattr(request.module, 'receiver_sockets')[0]
    key = getattr(request.module, 'analysisd_regex_keyword')
    ips = getattr(request.module, 'analysisd_injections_per_second')

    for test_case in test_cases:
        event = (json.loads(re.match(key, test_case['input']).group(2)))

        try:
            value_name = '\\' + event[SYSCHECK_DATA][SYSCHECK_VALUE_NAME]
        except KeyError:
            value_name = ''

        events[event[SYSCHECK_DATA][SYSCHECK_PATH] + value_name].update({test_case['stage']: event})
        socket_controller.send(test_case['input'])
        time.sleep(1 / ips)

    n_alerts = len(test_cases)

    wait_mtime(ALERTS_JSON_PATH, time_step=5, timeout=60)

    with open(ALERTS_JSON_PATH, 'r') as f:
        alert_list = f.readlines()

    alerts = list()

    for alert in alert_list:
        result = utils.callback_fim_alert(alert)

        if result is not None:
            alerts.append(result)

    if len(alerts) != n_alerts:
        raise ValueError(f"Number of alerts in {ALERTS_JSON_PATH} is not correct: {len(alerts)} != {n_alerts}")

    setattr(request.module, 'events_dict', events)

    yield (i for i in alerts)
