# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest


# Global SDK fixtures

@pytest.fixture(scope="module", autouse=True)
def mock_wazuh_status_check():
    with patch('wazuh.core.manager.check_wazuh_status') as wazuh_status_mock:
        yield wazuh_status_mock
