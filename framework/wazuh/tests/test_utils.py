#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

from wazuh import exception
from wazuh.utils import sort_array

class Person(object):
    """__init__() functions as the class constructor"""
    def __init__(self, name=None, job=None):
        self.name = name
        self.job = job

mock_array = [{'rx': {'bytes': 4005, 'packets': 30}, 'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'}, 'mac': '02:42:ac:14:00:05', 'agent_id': '000'}, {'rx': {'bytes': 447914, 'packets': 1077}, 'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'}, 'mac': '02:42:ac:14:00:01', 'agent_id': '003'}]
mock_sort_by = ['rx_bytes']
mock_sort_by_multiple = ['mac', 'rx_bytes']
mock_array_order_by_mac = [{'rx': {'bytes': 447914, 'packets': 1077}, 'scan': {'id': 396115592, 'time': '2019/05/29 07:26:26'}, 'mac': '02:42:ac:14:00:01', 'agent_id': '003'}, {'rx': {'bytes': 4005, 'packets': 30}, 'scan': {'id': 1999992193, 'time': '2019/05/29 07:25:26'}, 'mac': '02:42:ac:14:00:05', 'agent_id': '000'}]
mock_array_class = [Person("Payne N. Diaz", "coach")]

def test_sort_array_type():
    """
    Tests utils.sort_array() response type
    """
    assert isinstance(sort_array(mock_array, mock_sort_by), list)

@pytest.mark.parametrize('array, sort_by, order, expected_exception', [
    ([{'test':'test'}], None, 'asc', 1404),
    ('{}', None, 'ramdom', 1402),
    (mock_array, ['test'], 'asc', 1403)
])
def test_sort_array_error(array, sort_by, order, expected_exception):
    """
    Tests utils.sort_array() function for all exceptions cases:
        * List with a dictionary and no sort parameter
        * Order type different to 'asc' or 'desc'
        * Sort parameter not allow
    """
    with pytest.raises(exception.WazuhException, match=f'.* {expected_exception} .*'):
        sort_array(array, sort_by, order)


@pytest.mark.parametrize('array, sort_by, order, allowed_sort_field, output', [
    ('', None, 'asc', None, ''),
    ([4005, 4006, 4019, 36], None, 'asc', None, [36, 4005, 4006, 4019]),
    ([4005, 4006, 4019, 36], None, 'desc', None, [4019, 4006, 4005, 36]),
    (mock_array, mock_sort_by, 'asc', mock_sort_by, mock_array),
    (mock_array, mock_sort_by_multiple, 'asc', None, mock_array_order_by_mac),
    (mock_array_class, ['name'], 'desc', ['name'], mock_array_class)
])
def test_sort_array(array, sort_by, order, allowed_sort_field, output):
    """
    Tests utils.sort_array() function for different cases:
        * Empty list
        * Sorted list with values
        * Sorted list with order parameter 'desc'
        * Sorted list with dict, sorted by one nester parameter
        * Sorted list with dict, sorted by different parameter
        * Sorted list with class
    """
    assert sort_array(array, sort_by, order, allowed_sort_field) == output
