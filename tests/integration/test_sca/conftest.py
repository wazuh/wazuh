"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import sys
import re

from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.platforms import WINDOWS

# Fixtures
@pytest.fixture()
def wait_for_sca_enabled():
    '''
    Wait for the sca module to start.
    '''
    def _callback_sca_ready(line):
        return re.match(patterns.SCA_RUNNING, line) or re.match(patterns.SCA_ENABLED, line)

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    timeout = 240 if sys.platform == WINDOWS else 60
    log_monitor.start(callback=_callback_sca_ready, timeout=timeout)
    assert log_monitor.callback_result
