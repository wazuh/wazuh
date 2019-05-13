#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest import TestCase, mock

from wazuh.ciscat import get_results_agent


def mocked_get_item_agent(**kwargs):
    return {'totalItems': 4, 'items': []}


class TestCiscat(TestCase):
    @mock.patch('wazuh.ciscat.get_item_agent', side_effect=mocked_get_item_agent)
    def test_get_ciscat_results(self, get_function):
        result = get_results_agent('001')
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result['totalItems'], int)
        self.assertIsInstance(result['items'], list)
