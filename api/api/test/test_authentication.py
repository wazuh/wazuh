# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

test_path = os.path.dirname(os.path.realpath(__file__))


@patch('wazuh.common.ossec_path', '/var/ossec')
def test_importing_module():
    import api.authentication
