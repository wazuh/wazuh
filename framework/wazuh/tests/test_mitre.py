#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Framework tests for Mitre module."""

import os
import re
from sqlite3 import connect
from unittest.mock import patch
import pytest
import json

from .util import InitWDBSocketMock

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.mitre import get_attack

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')

json_keys = {'external_references', 'object_marking_refs',
             'x_mitre_contributors', 'x_mitre_data_sources', 'modified',
             'x_mitre_detection', 'created_by_ref', 'x_mitre_platforms',
             'kill_chain_phases', 'x_mitre_defense_bypassed', 'description',
             'id', 'name', 'created', 'x_mitre_version',
             'x_mitre_remote_support', 'type', 'x_mitre_permissions_required',
             'x_mitre_system_requirements', 'x_mitre_network_requirements',
             'x_mitre_effective_permissions', 'x_mitre_impact_type'}


def get_fake_mitre_data(sql_file, wdb_query):
    """Simulate a WazuhDB response to a SQL query for Mitre database."""
    query = re.search(r'^mitre sql (.+)$', wdb_query).group(1)
    mitre_db = connect(':memory:')
    cur = mitre_db.cursor()
    with open(os.path.join(test_data_path, sql_file)) as f:
        cur.executescript(f.read())
    result = mitre_db.execute(query).fetchall()

    return result


@pytest.mark.parametrize('offset, limit', [
    (0, 0),
    (0, 1),
    (1, 3),
    (9, 0),
    (15, 9),
    (29, 10),
    (34, 8),
    (49, 7),
    (51, 1),
    (67, 7),
    (122, 9),
    (149, 10),
    (167, 6),
    (171, 11),
    (183, 35),
    (230, 20),
    (342, 58),
    (521, 3),
    (759, 9),
    (893, 13),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql', mitre=True))
def test_get_attack(mock_wdb, offset, limit):
    """Test if data are retrieved properly from Mitre database."""
    # check error when limit = 0
    try:
        result = get_attack(offset=offset, limit=limit)
    except Exception as e:
        if e.code == 1406:
            return
        else:
            raise e

    # check result lenght
    try:
        assert len(result['items']) == limit
    except AssertionError:
        assert len(result['items']) <= 10

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(json.loads(item['json']).keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('attack', [
    ('T1015'),
    ('T1176'),
    ('T1087'),
    ('T1015'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql', mitre=True))
def test_get_attack_filter_attack(mock_wdb, attack):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(attack=attack)

    # check result lenght
    assert len(result['items']) == 1

    # check JSON keys
    result_keys = set(json.loads(result['items'][0]['json']).keys())
    assert result_keys != set()
    assert result_keys.issubset(json_keys)


@pytest.mark.parametrize('phase', [
    ('Persistence'),
    ('persistence'),
    ('defense evasion'),
    ('Defense Evasion'),
    ('Privilege Escalation'),
    ('privilege escalation'),
    ('Discovery'),
    ('discovery'),
    ('Credential Access'),
    ('credential access'),
    ('Execution'),
    ('execution'),
    ('Lateral Movement'),
    ('lateral movement'),
    ('collection'),
    ('Collection'),
    ('Exfiltration'),
    ('exFilTration'),
    ('Command and Control'),
    ('command and Control'),
    ('Impact'),
    ('impacT'),
    ('Initial Access'),
    ('initial ACCess'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql', mitre=True))
def test_get_attack_filter_phase(mock_wdb, phase):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(phase=phase)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(json.loads(item['json']).keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('platform', [
    ('Linux'),
    ('linuX'),
    ('macOS'),
    ('macos'),
    ('Windows'),
    ('winDows')
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql', mitre=True))
def test_get_attack_filter_platform(mock_wdb, platform):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(platform=platform)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(json.loads(item['json']).keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('phase, platform', [
    ('persistence', 'macos'),
    ('defense evasion', 'linux'),
    ('Defense Evasion', 'windows'),
    ('Privilege Escalation', 'macos'),
    ##('privilege escalation'),
    #('Discovery', 'windows'),
    ##('discovery'),
    #('Credential Access', 'linux'),
    #('credential access', 'macOS'),
    #('Execution', 'windows'),
    ##('execution'),
    #('Lateral Movement', 'linux'),
    #('lateral movement', 'macos'),
    #('collection', 'linux'),
    ##('Collection'),
    #('Exfiltration', 'windows'),
    ##('exFilTration'),
    #('Command and Control', 'linux'),
    ##('command and Control'),
    #('Impact', 'linux'),
    ##('impacT'),
    #('Initial Access', 'Windows'),
    ##('initial ACCess'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql', mitre=True))
def test_get_attack_filter_multiple(mock_wdb, phase, platform):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(phase=phase, platform=platform)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(json.loads(item['json']).keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)
        # check phase and platform
        assert phase.lower() in item['phases'].lower()
        assert platform.lower() in item['platforms'].lower()
