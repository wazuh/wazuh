# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import shutil

import pytest

from wazuh_testing.constants.paths.configurations import CUSTOM_RULES_PATH
from wazuh_testing.constants.paths.logs import OSSEC_LOG_PATH
from wazuh_testing.constants.users import WAZUH_UNIX_GROUP, WAZUH_UNIX_USER
from wazuh_testing.modules.analysisd import patterns
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
