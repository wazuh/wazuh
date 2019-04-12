# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from api import util


@pytest.mark.parametrize('param, param_type, expected_result', [
    (None, 'search', None),
    (None, 'sort', None),
    (None, 'random', None),
    ('ubuntu', 'search', {'value': 'ubuntu', 'negation': False}),
    ('-ubuntu', 'search', {'value': 'ubuntu', 'negation': True}),
    ('field1', 'sort', {'fields': ['field1'], 'order': 'asc'}),
    ('field1,field2', 'sort', {'fields': ['field1', 'field2'], 'order': 'asc'}),
    ('-field1,field2', 'sort', {'fields': ['field1', 'field2'], 'order': 'desc'}),
    ('random', 'random', 'random')
])
def test_parse_api_param(param, param_type, expected_result):
    assert util.parse_api_param(param, param_type) == expected_result
