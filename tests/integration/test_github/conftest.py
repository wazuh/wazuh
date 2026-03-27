# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sys

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.modulesd import patterns
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks


@pytest.fixture()
def wait_for_github_start():
    # Wait for module github starts
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(patterns.MODULESD_STARTED, {
                              'integration': 'GitHub'
                          }))
    assert (wazuh_log_monitor.callback_result == None), f'Error invalid configuration event not detected'

@pytest.fixture(scope="session", autouse=True)
def fix_ossec_conf_multiple_roots():
    """Temporary fix: DEB/RPM packages install ossec.conf with two <ossec_config> root
    blocks. The test framework's XML parser only supports a single root element, so we
    merge both blocks by removing the closing tag of the first block and the opening tag
    of the second block before the test session begins.
    """
    if sys.platform == WINDOWS:
        return

    try:
        with open(WAZUH_CONF_PATH, 'r') as f:
            content = f.read()

        # Only act when two root blocks are present
        if content.count('</ossec_config>') < 2:
            return

        # Remove the boundary between the two blocks: </ossec_config>...<ossec_config>
        import re
        fixed = re.sub(r'</ossec_config>\s*<ossec_config>', '', content, count=1)

        with open(WAZUH_CONF_PATH, 'w') as f:
            f.write(fixed)
    except OSError:
        # Not installed or no permission — tests will fail on their own if needed
        pass
