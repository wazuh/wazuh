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
    ('Wazuh v5.1.15', 'Wazuh v5.2.0'),
    ('v3.6.0', 'v3.6.1'),
    ('v3.9.1', 'v3.9.2'),
    ('v4.0.0', 'v4.0.1'),
    ('3.6.0', '3.6.1'),
    ('3.9.0', '3.9.2'),
    ('4.0.0', '4.0.1')
])
def test_version_ok(version1, version2):
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


@pytest.mark.parametrize('version1, version2', [
    ('v3.6.0', 'v.3.6.1'),
    ('Wazuh v4', 'Wazuh v5'),
    ('Wazuh v3.9', 'Wazuh v3.10'),
    ('ABC v3.10.1', 'ABC v3.10.12'),
    ('Wazuhv3.9.0', 'Wazuhv3.9.2'),
    ('3.9', '3.10'),
    ('3.9.0', '3.10'),
    ('3.10', '4.2'),
    ('3', '3.9.1')
])
def test_version_ko(version1, version2):
    """
    Test WazuhVersion class
    """
    try:
        current_version = WazuhVersion(version1)
        new_version = WazuhVersion(version2)
    except ValueError:
        return

    raise Exception


@pytest.mark.parametrize('version1, version2', [
    ('Wazuh v3.10.10', 'Wazuh v3.10.10'),
    ('Wazuh v5.1.15', 'Wazuh v5.1.15'),
    ('v3.6.0', 'v3.6.0'),
    ('v3.9.2', 'v3.9.2')
])
def test_same_version(version1, version2):
    """
    Test WazuhVersion class
    """
    current_version = WazuhVersion(version1)
    new_version = WazuhVersion(version2)

    assert current_version == new_version
    assert not(current_version < new_version)
    assert current_version <= new_version
    assert not(new_version > current_version)
    assert new_version >= current_version
    assert not(current_version != new_version)

    assert isinstance(current_version.to_array(), list)
    assert isinstance(new_version.to_array(), list)
