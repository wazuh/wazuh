
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Common functions for using in tests."""

import os
from unittest.mock import mock_open

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')


def mock_ossec_init() -> str:
    """Return open_mock with ossec-init.conf content."""
    ossec_init_path = os.path.join(test_data_path, 'ossec-init.conf')
    with open(ossec_init_path) as f:
        ossec_init_data = f.read()

    return mock_open(read_data=ossec_init_data)
