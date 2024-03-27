'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.daemons import LOGCOLLECTOR_DAEMON
from wazuh_testing.modules.logcollector.patterns import LOGCOLLECTOR_MODULE_START
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.file import truncate_file


@pytest.fixture()
def stop_logcollector(request):
    """Stop wazuh-logcollector and truncate logs file."""
    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(WAZUH_LOG_PATH)


@pytest.fixture()
def wait_for_logcollector_start(request):
    # Wait for logcollector thread to start
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(LOGCOLLECTOR_MODULE_START))
    assert (log_monitor.callback_result != None), f'Error logcollector start event not detected'
