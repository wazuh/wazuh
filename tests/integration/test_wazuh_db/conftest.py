import os
import sys
import re
import shutil

import pytest

from wazuh_testing.tools.wazuh_manager import create_group, delete_group
from wazuh_testing.constants import paths
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.file import truncate_file

@pytest.fixture(scope='function')
def create_groups(test_metadata):
    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)


@pytest.fixture(scope='function')
def clear_logs(request):
    """Reset the ossec.log and start a new monitor"""
    truncate_file(paths.logs.WAZUH_LOG_PATH)
    log_monitor = file_monitor.FileMonitor(paths.logs.WAZUH_LOG_PATH)
    setattr(request.module, 'wazuh_log_monitor', log_monitor)