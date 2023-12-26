# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.modules.analysisd.patterns import LOGTEST_STARTED
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH

@pytest.fixture(scope='module')
def wait_for_logtest_startup(request):
    """Wait until logtest has begun."""
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=generate_callback(LOGTEST_STARTED), timeout=40, only_new_events=True)
