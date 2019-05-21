#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest
import os

from wazuh.utils import WazuhVersion

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.5.0', 'Wazuh v3.5.2'),
    ('Wazuh v3.6.1', 'Wazuh v3.6.3'),
    ('Wazuh v3.7.2', 'Wazuh v3.8.0'),
    ('Wazuh v3.8.0', 'Wazuh v3.8.1'),
    ('Wazuh v3.9.0', 'Wazuh v3.9.2'),
    ('Wazuh v3.9.10', 'Wazuh v3.9.14'),
    ('Wazuh v3.10.1', 'Wazuh v3.10.10'),
    ('Wazuh v4.10.10', 'Wazuh v4.11.0'),
    ('Wazuh v5.1.15', 'Wazuh v5.2.0')
])
def test_version(version1, version2):
    """
    Test WazuhVersion class
    """
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version < new_version
    assert current_version <= new_version
    assert new_version > current_version
    assert new_version >= current_version
    assert current_version != new_version
    assert not(current_version == new_version)

    assert isinstance(current_version.to_array(), list)
    assert isinstance(new_version.to_array(), list)
