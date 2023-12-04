# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import shutil

from wazuh_testing.modules.logcollector import logcollector
from logtest import callback_logtest_started
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

@pytest.fixture(scope='module')
def wait_for_logtest_startup(request):
    """Wait until logtest has begun."""
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callback_logtest_started, timeout=logcollector.LOG_COLLECTOR_GLOBAL_TIMEOUT, only_new_events=True)
