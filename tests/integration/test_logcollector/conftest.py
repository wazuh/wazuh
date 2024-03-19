'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.daemons import LOGCOLLECTOR_DAEMON
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.file import truncate_file


@pytest.fixture()
def stop_logcollector(request):
    """Stop wazuh-logcollector and truncate logs file."""
    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(WAZUH_LOG_PATH)
