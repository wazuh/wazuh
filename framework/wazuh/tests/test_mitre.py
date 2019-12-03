#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Framework tests for Mitre module."""

import os
from sqlite3 import connect
from unittest.mock import patch

import pytest

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


def get_fake_mitre_data(sql_file):
    """Create a fake database for Mitre."""
    mitre_db = connect(':memory:')
    cur = mitre_db.cursor()
    with open(os.path.join(test_data_path, sql_file)) as f:
        cur.executescript(f.read())

    return mitre_db


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
        sql_schema_file='schema_mitre_test.sql'))
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
        item_keys = set(item['json'].keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('attack', [
    ('T1015'),
    ('T1176'),
    ('T1087'),
    ('T1015'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql',))
def test_get_attack_filter_attack(mock_wdb, attack):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(attack=attack)

    # check result lenght
    assert len(result['items']) == 1

    # check JSON keys
    result_keys = set(result['items'][0]['json'].keys())
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
        sql_schema_file='schema_mitre_test.sql'))
def test_get_attack_filter_phase(mock_wdb, phase):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(phase=phase)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(item['json'].keys())
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
        sql_schema_file='schema_mitre_test.sql'))
def test_get_attack_filter_platform(mock_wdb, platform):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(platform=platform)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(item['json'].keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('q', [
    ('attack=T1123'),
    ('phase=persistence'),
    ('platform=linux'),
    ('phase=discovery'),
    ('attack=T1131'),
    ('platform=windows')
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_get_attack_filter_q(mock_wdb, q):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(q=q)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(item['json'].keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)


@pytest.mark.parametrize('phase, platform', [
    ('persistence', 'macos'),
    ('defense evasion', 'linux'),
    ('Defense Evasion', 'windows'),
    ('Privilege Escalation', 'macos'),
    ('privilege escalation', 'linux'),
    ('Discovery', 'windows'),
    ('discovery', 'macos'),
    ('Credential Access', 'linux'),
    ('credential access', 'macOS'),
    ('Execution', 'windows'),
    ('execution', 'macos'),
    ('Lateral Movement', 'linux'),
    ('lateral movement', 'macos'),
    ('collection', 'linux'),
    ('Collection', 'windowS'),
    ('Exfiltration', 'windows'),
    ('exFilTration', 'linux'),
    ('Command and Control', 'macos'),
    ('command and Control', 'windows'),
    ('Impact', 'linux'),
    ('impacT', 'macos'),
    ('Initial Access', 'Windows'),
    ('initial ACCess', 'linux'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_get_attack_filter_multiple(mock_wdb, phase, platform):
    """Test if data are retrieved properly from Mitre database."""
    result = get_attack(phase=phase, platform=platform)

    # check result lenght
    assert len(result['items']) > 0

    # check JSON keys for each item
    for item in result['items']:
        item_keys = set(item['json'].keys())
        assert item_keys != set()
        assert item_keys.issubset(json_keys)
        # check phase and platform
        assert phase.lower() in [phase.lower() for phase in item['phases']]
        assert platform.lower() in [platform.lower() for platform in
                                    item['platforms']]


@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_check_total_items(mock_wdb):
    """Test the number of returned items."""
    # load test database and make the query
    cur = get_fake_mitre_data('schema_mitre_test.sql').cursor()
    cur.execute(f'SELECT COUNT(DISTINCT id) FROM attack')
    rows = cur.fetchone()
    expected_total_items = rows[0]

    total_items = get_attack()['totalItems']

    assert expected_total_items == total_items


@pytest.mark.parametrize('platform', [
    ('linux'),
    ('macos'),
    ('windows')
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_check_total_items_platform(mock_wdb, platform):
    """Test the number of returned items when filtering by platform."""
    # load test database and make the query
    cur = get_fake_mitre_data('schema_mitre_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT attack_id) FROM has_platform WHERE "
                f"(platform_name='{platform}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]

    total_items = get_attack(platform=platform)['totalItems']

    assert expected_total_items == total_items


@pytest.mark.parametrize('phase', [
    ('Persistence'),
    ('Defense Evasion'),
    ('Privilege Escalation'),
    ('Discovery'),
    ('Credential Access'),
    ('Execution'),
    ('Lateral Movement'),
    ('Collection'),
    ('Exfiltration'),
    ('command and Control'),
    ('Impact'),
    ('Initial Access'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_check_total_items_phase(mock_wdb, phase):
    """Test the number of returned items when filtering by phase."""
    # load test database and make the query
    cur = get_fake_mitre_data('schema_mitre_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT attack_id) FROM has_phase WHERE "
                f"(phase_name='{phase}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]

    total_items = get_attack(phase=phase)['totalItems']

    assert expected_total_items == total_items


@pytest.mark.parametrize('platform, phase', [
    ('linux', 'Persistence'),
    ('macos', 'Defense Evasion'),
    ('windows', 'Privilege Escalation'),
    ('linux', 'Discovery'),
    ('macos', 'Credential Access'),
    ('windows', 'Execution'),
    ('macos', 'Lateral Movement'),
    ('linux', 'Collection'),
    ('windows', 'Exfiltration'),
    ('linux', 'command and Control'),
    ('windows', 'Impact'),
    ('macos', 'Initial Access'),
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_check_total_items_multiple_filters(mock_wdb, platform, phase):
    """Test the number of returned items when filtering by phase and platform."""  # noqa: E501
    # load test database and make the query
    cur = get_fake_mitre_data('schema_mitre_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT has_platform.attack_id) FROM "
                "has_platform LEFT JOIN has_phase ON has_platform.attack_id = "
                f"has_phase.attack_id WHERE (platform_name='{platform}' "
                f" COLLATE NOCASE) AND (phase_name='{phase}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]

    total_items = get_attack(platform=platform, phase=phase)['totalItems']

    assert expected_total_items == total_items


@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_sort_mitre(mock_wdb):
    """Test sort filter."""
    result_asc = get_attack(sort={"fields": ["id"], "order": "asc"}, limit=1)
    result_desc = get_attack(sort={"fields": ["id"], "order": "desc"}, limit=1)

    assert result_asc['items'][0]['id'] < result_desc['items'][0]['id']


@pytest.mark.parametrize('search', [
    ('new shell opens or when a user logs'),
    ('rootkits'),
    ('Monitor Registry keys'),
    ('correlate with other'),
    ('Exfiltration'),
    ('Windows'),
    ('clipboard from')
])
@patch('wazuh.utils.WazuhDBConnection', return_value=InitWDBSocketMock(
        sql_schema_file='schema_mitre_test.sql'))
def test_check_total_items_searched_attack(mock_wdb, search):
    """Test the number of returned items when filtering by search."""
    # load test database and make the query
    cur = get_fake_mitre_data('schema_mitre_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT id) FROM"
                f" attack WHERE json LIKE '%{search}%'")

    rows = cur.fetchone()
    expected_total_items = rows[0]

    total_items = get_attack(search={'value':search, 'negation':0})['totalItems']

    assert expected_total_items == total_items
