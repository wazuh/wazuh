#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from unittest.mock import patch
with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh import ciscat

@patch("wazuh.ciscat.get_item_agent", return_value=None)
def test_get_ciscat_agent(mock_response):
    """
        Tests get_netiface_agent method
    """
    ciscat.get_results_agent('001')


@patch("wazuh.ciscat._get_agent_items", return_value=None)
def test_get_ciscat_result(mock_response):
    """
        Tests get_packages method
    """
    ciscat.get_ciscat_results()