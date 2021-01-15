#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for tools module."""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from tools import get_wazuh_version

wazuh_control_info = 'WAZUH_VERSION="TEST_VERSION"\n\
                      WAZUH_REVISION="TEST_REVISION"\n\
                      WAZUH_TYPE="TEST_TYPE"\n'

def test_get_wazuh_version():
    """Test get_wazuh_version function."""
        
    with patch(f'tools.call_wazuh_control', return_value=wazuh_control_info):
        wazuh_version = get_wazuh_version()

    assert "TEST_VERSION" == wazuh_version
