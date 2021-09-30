#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for tools module."""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from tools import get_wazuh_queue

wazuh_installation_path = '/var/ossec'

def test_get_wazuh_queue():
    """Test get_wazuh_queue function."""

    with patch(f'tools.utils.find_wazuh_path', return_value=wazuh_installation_path):
        wazuh_queue = get_wazuh_queue()

    assert "/var/ossec/queue/sockets/queue" == wazuh_queue
