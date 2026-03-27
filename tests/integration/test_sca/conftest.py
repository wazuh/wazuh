"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import sys

from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH
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
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.SCA_RUNNING), timeout=60)
    assert log_monitor.callback_result

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
