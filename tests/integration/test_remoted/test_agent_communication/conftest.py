"""
 Copyright (C) 2015-2043, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""


import pytest


from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.patterns import ANALYSISD_STARTED
from wazuh_testing.utils import callbacks
from wazuh_testing.tools.monitors import file_monitor


@pytest.fixture(scope='module')
def waiting_for_analysisd_startup(request):
    """Wait until analysisd has begun and alerts.json is created."""
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(ANALYSISD_STARTED))
