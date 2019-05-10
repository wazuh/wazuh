# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest

from wazuh.rule import Rule
from wazuh.exception import WazuhException

rule_ossec_conf = {
    'rule_dir': ['ruleset/rules'],
    'rule_exclude': 'rules1.xml'
}

rule_contents = '''
<group name="ossec,">
  <rule id="501" level="3">
    <if_sid>500</if_sid>
    <if_fts />
    <options>alert_by_email</options>
    <match>Agent started</match>
    <description>New ossec agent connected.</description>
    <group>pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,</group>
  </rule>
</group>
    '''


def rules_files(file_path):
    """
    Returns a list of rules names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'rules{x}.xml'), range(2))


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('status', [
    None,
    'all',
    'enabled',
    'disabled',
    'random'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_status(mock_config, mock_glob, status, func):
    """
    Tests getting rules using status filter
    """
    m = mock_open(read_data=rule_contents)
    if status == 'random':
        with pytest.raises(WazuhException, match='.* 1202 .*'):
            func(status=status)
    else:
        with patch('builtins.open', m):
            d_files = func(status=status)
            if isinstance(d_files['items'][0], Rule):
                d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
            if status is None or status == 'all':
                assert d_files['totalItems'] == 2
                assert d_files['items'][0]['status'] == 'enabled'
                assert d_files['items'][1]['status'] == 'disabled'
            else:
                assert d_files['totalItems'] == 1
                assert d_files['items'][0]['status'] == status


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('path', [
    None,
    'ruleset/rules',
    'random'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_path(mock_config, mock_glob, path, func):
    """
    Tests getting rules files filtering by path
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        d_files = func(path=path)
        if path == 'random':
            assert d_files['totalItems'] == 0
            assert len(d_files['items']) == 0
        else:
            assert d_files['totalItems'] == 2
            if isinstance(d_files['items'][0], Rule):
                d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
            assert d_files['items'][0]['path'] == 'ruleset/rules'


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('offset, limit', [
    (0, 0),
    (0, 1),
    (0, 500),
    (1, 500),
    (2, 500),
    (3, 500)
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_pagination(mock_config, mock_glob, offset, limit, func):
    """
    Tests getting rules files using offset and limit
    """
    if limit > 0:
        m = mock_open(read_data=rule_contents)
        with patch('builtins.open', m):
            d_files = func(offset=offset, limit=limit)
            limit = d_files['totalItems'] if limit > d_files['totalItems'] else limit
            assert d_files['totalItems'] == 2
            assert len(d_files['items']) == (limit - offset if limit > offset else 0)
    else:
        with pytest.raises(WazuhException, match='.* 1406 .*'):
            Rule.get_rules_files(offset=offset, limit=limit)


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('sort', [
    None,
    {"fields": ["file"], "order": "asc"},
    {"fields": ["file"], "order": "desc"}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_sort(mock_config, mock_glob, sort, func):
    """
    Tests getting rules files and sorting results
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        d_files = func(sort=sort)
        if isinstance(d_files['items'][0], Rule):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if sort is not None:
            assert d_files['items'][0]['file'] == f"rules{'0' if sort['order'] == 'asc' else '1'}.xml"


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('search', [
    None,
    {"value": "1", "negation": 0},
    {"value": "1", "negation": 1}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_search(mock_config, mock_glob, search, func):
    """
    Tests getting rules files and searching results
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        d_files = Rule.get_rules_files(search=search)
        if isinstance(d_files['items'][0], Rule):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if search is not None:
            assert d_files['items'][0]['file'] == f"rules{'0' if search['negation'] else '1'}.xml"


@pytest.mark.parametrize('func', [
    Rule.get_file
])
@pytest.mark.parametrize('filename', [
    'rules1.xml',
    'noexists.xml'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_download_rule_file_status(mock_config, mock_glob, filename, func):
    """
    Tests download XML rule file
    """
    m = mock_open(read_data=rule_contents)
    if filename == 'noexists.xml':
        with pytest.raises(WazuhException, match='.* 1415 .*'):
            func(filename=filename)
    else:
        with patch('builtins.open', m):
            d_files = func(filename=filename)
            assert d_files.find('rule') != -1

