#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for tools module."""

import os
import sys
from unittest.mock import mock_open, patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from tests.common import mock_ossec_init
from tools import get_wazuh_paths

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')


@patch('tools.open', side_effect=mock_ossec_init())
def test_get_wazuh_paths(mock_ossec_init):
    """Test get_wazuh_paths function."""
    expected_wazuh_path = os.path.join('/', 'var', 'ossec')
    expected_wazuh_version = 'v3.11.0'
    expected_wazuh_queue = os.path.join(expected_wazuh_path, 'queue', 'ossec',
                                        'queue')
    wazuh_path, wazuh_version, wazuh_queue = get_wazuh_paths()

    assert expected_wazuh_path == wazuh_path
    assert expected_wazuh_version == wazuh_version
    assert expected_wazuh_queue == wazuh_queue
