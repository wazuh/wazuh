# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.modules.integrations.event_monitors import detect_integration_start


@pytest.fixture()
def wait_for_github_start():
    # Wait for module github starts
    file_monitor = FileMonitor(WAZUH_LOG_PATH)
    detect_integration_start("GitHub",file_monitor)
