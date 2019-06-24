#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest import mock

import wazuh.ciscat


def mocked_get_item_agent(**kwargs):
    return {'totalItems': 4, 'items': []}


@mock.patch('wazuh.ciscat.get_item_agent', side_effect=mocked_get_item_agent)
def test_get_ciscat_results(*mocked_args):
    result = wazuh.ciscat.get_ciscat_results()
    assert isinstance(result, dict)
    assert isinstance(result['totalItems'], int)
    assert isinstance(result['items'], list)
