#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import pytest
import os

from wazuh.utils import WazuhVersion, filter_array_by_query


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# input data for testing q filter
input_array = [
        {"count": 3,
         "name": "default",
         "mergedSum": "a7d19a28cd5591eade763e852248197b",
         "configSum": "ab73af41699f13fdd81903b5f23d8d00"
        },
        {"count": 0,
         "name": "dmz",
         "mergedSum": "dd77862c4a41ae1b3854d67143f3d3e4",
         "configSum": "ab73af41699f13fdd81903b5f23d8d00"
        },
        {"count": 0,
         "name": "testsagentconf",
         "mergedSum": "2acdb385658097abb9528aa5ec18c490",
         "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
        },
        {"count": 0,
         "name": "testsagentconf2",
         "mergedSum": "391ae29c1b0355c610f45bf133d5ea55",
         "configSum": "297b4cea942e0b7d2d9c59f9433e3e97"
        }
    ]


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


@pytest.mark.parametrize('q, return_length', [
    ('name=firewall', 0),
    ('count=1', 0),
    ('name~a', 0),
    ('count<0', 0),
    ('count>3', 0),
    ('count=3;name~test', 0),
    ('count!=0;count!=3', 0),
    ('wrong_param=default', 0),
    ('wrong_param!=default', 0),
    ('wrong_param2~test', 0),
    ('name~test;mergedSum~2acdb', 1),
    ('name=dmz', 1),
    ('name~def', 1),
    ('count=3', 1),
    ('count>2', 1),
    ('count>0', 1),
    ('count!=0', 1),
    ('name~test;mergedSum~2acdb,name=dmz', 2),
    ('name=dmz,name=default', 2),
    ('name~test', 2),
    ('count<3;name~test', 2),
    ('name~d', 2),
    ('name!=dmz;name!=default', 2),
    ('count=0;name!=dmz', 2),
    ('count=0', 3),
    ('count<3', 3),
    ('count<1', 3),
    ('count!=3', 3),
    ('count>10,count<3', 3),
    ('configSum~29,count=3', 3),
    ('name~test,count>0', 3),
    ('count<4', 4),
    ('count>0,count<4', 4),
    ('name~def,count=0', 4),
    ('configSum~29,configSum~ab', 4)
])
def test_filter_array_by_query(q, return_length):
    """
    Test filter by query in an array
    """
    result = filter_array_by_query(q, input_array)

    for item in result:
        # check fields returned in result
        item_keys = set(item.keys())
        assert(len(item_keys) == len(input_array[0]))
        assert(item_keys == set(input_array[0].keys()))

    assert(len(result) == return_length)
