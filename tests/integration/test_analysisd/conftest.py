# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import os
import re
import shutil
import time
from collections import defaultdict

import pytest

from wazuh_testing.constants.paths.configurations import CUSTOM_RULES_PATH, CUSTOM_RULES_FILE, WAZUH_CONF_PATH
from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH, WAZUH_LOG_PATH
from wazuh_testing.constants.users import WAZUH_UNIX_GROUP, WAZUH_UNIX_USER
from wazuh_testing.modules.analysisd import patterns
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, file


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


@pytest.fixture()
def configure_local_rules(request, test_configuration):
    """Configure a custom rule for testing. Restart Wazuh is needed for applying the configuration. """

    # save current configuration
    shutil.copy(CUSTOM_RULES_FILE, CUSTOM_RULES_FILE + '.cpy')

    # configuration for testing
    file_test = str(test_configuration)
    shutil.copy(file_test, CUSTOM_RULES_FILE)

    yield

    # restore previous configuration
    shutil.move(CUSTOM_RULES_FILE + '.cpy', CUSTOM_RULES_FILE)


@pytest.fixture()
def configure_remove_tags(request, test_metadata):
    """Configure a custom settting for testing. Restart Wazuh is needed for applying the configuration. """
    # Remove test case tags from ossec.conf
    file.replace_regex_in_file(test_metadata['remove_tags'], [''] * len(test_metadata['remove_tags']), WAZUH_CONF_PATH)


@pytest.fixture(scope='module')
def wait_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_STARTED))


@pytest.fixture(scope='module')
def generate_events_syscheck(request):
    """Read the specified yaml and generate every event using the input from every test case."""
    events = defaultdict(dict)

    test_cases = getattr(request.module, 'test_metadata')
    socket_controller = getattr(request.module, 'receiver_sockets')[0]
    key = getattr(request.module, 'analysisd_regex_keyword')
    ips = getattr(request.module, 'analysisd_injections_per_second')

    for test_case in test_cases:
        event = (json.loads(re.match(key, test_case['input']).group(2)))

        try:
            value_name = '\\' + event[patterns.SYSCHECK_DATA][patterns.SYSCHECK_VALUE_NAME]
        except KeyError:
            value_name = ''

        events[event[patterns.SYSCHECK_DATA][patterns.SYSCHECK_PATH] + value_name].update({test_case['stage']: event})
        socket_controller.send(test_case['input'])
        time.sleep(1 / ips)

    setattr(request.module, 'events_dict', events)


@pytest.fixture(scope='module')
def read_alerts_syscheck(request):
    """Read the alerts from the JSON file. Return single alerts.

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
    alerts = list()

    test_cases = getattr(request.module, 'test_metadata')

    file.wait_mtime(ALERTS_JSON_PATH, time_step=5, timeout=60)

    with open(ALERTS_JSON_PATH, 'r') as f:
        alert_list = f.readlines()

    for alert in alert_list:
        try:
            alert_json = json.loads(alert)
            if (alert_json[patterns.ALERTS_RULE][patterns.ALERTS_ID] in patterns.ANALYSISD_ALERTS_SYSCHECK_IDS):
                alerts.append(alert_json)
        except json.decoder.JSONDecodeError:
            continue

    if len(alerts) != len(test_cases):
        raise ValueError(f"Number of alerts in {ALERTS_JSON_PATH} is not correct: {len(alerts)} != {len(test_cases)}")

    yield (i for i in alerts)
