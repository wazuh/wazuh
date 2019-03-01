# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

from wazuh.rule import Rule
from wazuh.exception import WazuhException

rule_ossec_conf = {
    'rule_dir': ['ruleset/rules'],
    'rule_exclude': 'rules1.xml'
}


def rules_files(file_path):
    """
    Returns a list of rules names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'rules{x}.xml'), range(2))


@pytest.mark.parametrize('status', [
    None,
    'all',
    'enabled',
    'disabled',
    'random'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_status(mock_config, mock_glob, status):
    """
    Tests getting rules file using status filter
    """
    if status == 'random':
        with pytest.raises(WazuhException, match='.* 1202 .*'):
            Rule.get_rules_files(status=status)
    else:
        d_files = Rule.get_rules_files(status=status)
        if status is None or status == 'all':
            assert d_files['totalItems'] == 2
            assert d_files['items'][0]['status'] == 'enabled'
            assert d_files['items'][1]['status'] == 'disabled'
        else:
            assert d_files['totalItems'] == 1
            assert d_files['items'][0]['status'] == status


@pytest.mark.parametrize('path', [
    None,
    'ruleset/rules',
    'random'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_path(mock_config, mock_glob, path):
    """
    Tests getting rules files filtering by path
    """
    d_files = Rule.get_rules_files(path=path)
    if path == 'random':
        assert d_files['totalItems'] == 0
        assert len(d_files['items']) == 0
    else:
        assert d_files['totalItems'] == 2
        assert d_files['items'][0]['path'] == 'ruleset/rules'


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
def test_get_rules_file_pagination(mock_config, mock_glob, offset, limit):
    """
    Tests getting rules files using offset and limit
    """
    if limit > 0:
        d_files = Rule.get_rules_files(offset=offset, limit=limit)
        limit = d_files['totalItems'] if limit > d_files['totalItems'] else limit
        assert d_files['totalItems'] == 2
        assert len(d_files['items']) == (limit - offset if limit > offset else 0)
    else:
        with pytest.raises(WazuhException, match='.* 1406 .*'):
            Rule.get_rules_files(offset=offset, limit=limit)


@pytest.mark.parametrize('sort', [
    None,
    {"fields": ["file"], "order": "asc"},
    {"fields": ["file"], "order": "desc"}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_pagination(mock_config, mock_glob, sort):
    """
    Tests getting rules files and sorting results
    """
    d_files = Rule.get_rules_files(sort=sort)
    if sort is not None:
        assert d_files['items'][0]['file'] == f"rules{'0' if sort['order'] == 'asc' else '1'}.xml"


@pytest.mark.parametrize('search', [
    None,
    {"value": "1", "negation": 0},
    {"value": "1", "negation": 1}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_pagination(mock_config, mock_glob, search):
    """
    Tests getting rules files and searching results
    """
    d_files = Rule.get_rules_files(search=search)
    if search is not None:
        assert d_files['items'][0]['file'] == f"rules{'0' if search['negation'] else '1'}.xml"
