# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.rule import Rule
        from wazuh.exception import WazuhException

rule_ossec_conf = {
    'rule_dir': 'ruleset/rules',
    'rule_exclude': 'rules1.xml',
    'rule_include': 'rules2.xml'
}

other_rule_ossec_conf = {
    'rule_dir': ['ruleset/rules'],
    'rule_exclude': 'rules1.xml',
    'rule_include': ['rules2.xml']
}

rule_contents = '''
<group name="ossec,">
  <rule id="501" level="3" overwrite="no">
    <if_sid>500</if_sid>
    <if_fts />
    <options>alert_by_email</options>
    <match>Agent started</match>
    <description>New ossec agent connected.</description>
    <group>pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.3</group>
    <list field="user" lookup="match_key">etc/lists/list-user</list>
    <field name="netinfo.iface.name">ens33</field>
    <regex>$(\d+.\d+.\d+.\d+)</regex>
  </rule>
</group>
    '''

mocked_items = {'items': [], 'totalItems': 0}


def rules_files(file_path):
    """
    Returns a list of rules names
    :param file_path: A glob file path containing *.xml in the end.
    :return: A generator
    """
    return map(lambda x: file_path.replace('*.xml', f'rules{x}.xml'), range(2))


def test_rule__init__():
    rule = Rule()
    assert rule.file is None
    assert rule.path is None
    assert rule.description is ""
    assert rule.id is None
    assert rule.level is None
    assert rule.status is None
    assert isinstance(rule.groups, list)
    assert isinstance(rule.pci, list)
    assert isinstance(rule.gpg13, list)
    assert isinstance(rule.gdpr, list)
    assert isinstance(rule.hipaa, list)
    assert isinstance(rule.nist_800_53, list)
    assert isinstance(rule.details,dict)


def test_rule__str__():
    result = Rule().__str__()
    assert isinstance(result, str)


def test_rule__compare__():
    rule = Rule()
    rule.id = '001'
    rule_to_compare = Rule()
    rule_to_compare.id = '002'

    result = rule.__lt__(rule_to_compare)
    assert isinstance(result, bool)

    result = rule.__le__(rule_to_compare)
    assert isinstance(result, bool)

    result = rule.__gt__(rule_to_compare)
    assert isinstance(result, bool)

    result = rule.__ge__(rule_to_compare)
    assert isinstance(result, bool)


def test_failed_rule__compare__():
    rule = Rule()
    rule.id = '001'

    with pytest.raises(WazuhException, match=".* 1204 .*"):
        rule.__lt__('bad_rule')

    with pytest.raises(WazuhException, match=".* 1204 .*"):
        rule.__le__('bad_rule')

    with pytest.raises(WazuhException, match=".* 1204 .*"):
        rule.__gt__('bad_rule')

    with pytest.raises(WazuhException, match=".* 1204 .*"):
        rule.__ge__('bad_rule')


def test_rule_to_dict():
    result = Rule().to_dict()
    assert isinstance(result, dict)


def test_set_group():
    Rule().set_group('test')


def test_set_pci():
    Rule().set_pci('test')


def test_set_gpg13():
    Rule().set_gpg13('test')


def test_set_gdpr():
    Rule().set_gdpr('test')


def test_set_hippa():
    Rule().set_hipaa('test')


def test_nist_800_53():
    Rule().set_nist_800_53('test')


@pytest.mark.parametrize('detail, value, details', [
    ('if_sid', '400', {}),
    ('if_sid', '400', {'if_sid':'500'})
])
def test_add_details(detail, value, details):
    rule = Rule()
    rule.details = dict(frozenset(details.items()))
    rule.add_detail(detail, value)
    if not details:
        assert isinstance(rule.details[detail], str)
    else:
        assert isinstance(rule.details[detail], list)


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
def test_get_rules_file_status_include(mock_config, mock_glob, status, func):
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
                assert d_files['totalItems'] == 3
                assert d_files['items'][0]['status'] == 'enabled'
                assert d_files['items'][1]['status'] == 'disabled'
                assert d_files['items'][2]['status'] == 'enabled'
            elif status is 'enabled':
                assert d_files['totalItems'] == 2
                assert d_files['items'][0]['status'] == status
                assert d_files['items'][1]['status'] == status
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
@patch('wazuh.configuration.get_ossec_conf', return_value=other_rule_ossec_conf)
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
            assert d_files['totalItems'] == 3
            if isinstance(d_files['items'][0], Rule):
                d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
            assert d_files['items'][0]['path'] == 'ruleset/rules'


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('file', [
    'rules0.xml',
    'rules1.xml',
    'rules2.xml'
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_file_param(mock_config, mock_glob, file, func):
    """
    Tests getting rules using status filter
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        d_files = func(file=file)
        if isinstance(d_files['items'][0], Rule):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        assert d_files['items'][0]['file'] == file


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
            assert d_files['totalItems'] == 3
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
            assert d_files['items'][0]['file'] == f"rules{'0' if sort['order'] == 'asc' else '2'}.xml"


@pytest.mark.parametrize('func', [
    Rule.get_rules_files,
    Rule.get_rules
])
@pytest.mark.parametrize('search', [
    None,
    {"value": "rules1", "negation": 0},
    {"value": "rules1", "negation": 1}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_file_search(mock_config, mock_glob, search, func):
    """
    Tests getting rules files and searching results
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        d_files = func(search=search)
        if isinstance(d_files['items'][0], Rule):
            d_files['items'] = list(map(lambda x: x.to_dict(), d_files['items']))
        if search is not None:
            assert d_files['items'][0]['file'] == f"rules{'0' if search['negation'] else '1'}.xml"


@patch('wazuh.configuration.get_ossec_conf', return_value=None)
def test_failed_get_rules_file(mock_config):
    """
    Test failed get_rules_file function when ossec.conf don't have ruleset section
    """
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        with pytest.raises(WazuhException, match=".* 1200 .*"):
            Rule.get_rules_files()


@pytest.mark.parametrize('arg', [
    {'group': 'user1'},
    {'pci': 'user1'},
    {'gpg13': '10.0'},
    {'gdpr': 'IV_35.7.a'},
    {'hipaa': '164.312.a'},
    {'nist_800_53': 'AU.1'},
    {'id': '510'},
    {'level': '2'},
    {'level': '2-2'}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=other_rule_ossec_conf)
def test_get_rules(mock_config, mock_glob, arg):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_rules(**arg)

        assert isinstance(result, dict)
        assert set(result.keys()) == {'items', 'totalItems'}


def test_failed_get_rules():
    with pytest.raises(WazuhException, match=".* 1203 .*"):
        Rule.get_rules(level='2-3-4')


@pytest.mark.parametrize('arg', [
    {'search': None},
    {'search': {"value": "rules1", "negation": 0}},
    {'sort': None},
    {'sort': {"fields": ["file"], "order": "asc"}}
])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_groups(mock_config, mock_glob, arg):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_groups(**arg)

        assert isinstance(result, dict)
        assert set(result.keys()) == {'items', 'totalItems'}

@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_pci(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_pci()
        assert isinstance(result, dict)
        assert '10.6.1' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_gpg13(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_gpg13()
        assert isinstance(result, dict)
        assert '10.1' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_gdpr(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_gdpr()
        assert isinstance(result, dict)
        assert 'IV_35.7.d' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_hipaa(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_hipaa()
        assert isinstance(result, dict)
        assert '164.312.b' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_nist_800_53(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_nist_800_53()
        assert isinstance(result, dict)
        assert 'AU.3' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_hipaa(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_hipaa()
        assert isinstance(result, dict)
        assert '164.312.b' in result['items'][0]


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_nist_800_53(mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        result = Rule.get_nist_800_53()
        assert isinstance(result, dict)
        assert 'AU.3' in result['items'][0]


@pytest.mark.parametrize('sort', [
    None,
    {
        'order': 'asc'
    }
])
@pytest.mark.parametrize('search', [
    None,
    {
        'value': '10.1',
        'negation': False
    }
])
@pytest.mark.parametrize('requirement', [
    'pci',
    'gdpr',
    'gpg13',
    'hipaa',
    'nist-800-53',
    'wrong'

])
@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_protected_get_requirement(mocked_config, mocked_glob, requirement, sort, search):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        if requirement == 'wrong':
            with pytest.raises(WazuhException, match='.* 1205 .*'):
                Rule._get_requirement(requirement)
        else:
            assert isinstance(Rule._get_requirement(requirement, sort=sort, search=search), dict)


@patch('wazuh.rule.glob', side_effect=rules_files)
@patch('wazuh.configuration.get_ossec_conf', return_value=rule_ossec_conf)
@patch('wazuh.rule.filter', return_value=[{'text': 'value'}])
def test_failed_load_rules_from_file(mock_findall, mocked_config, mocked_glob):
    m = mock_open(read_data=rule_contents)
    with patch('builtins.open', m):
        with pytest.raises(WazuhException, match=".* 1201 .*"):
            Rule.get_rules()
