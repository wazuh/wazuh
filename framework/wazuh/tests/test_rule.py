# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, mock_open, MagicMock
from wazuh.core.common import USER_RULES_PATH
import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh import rule
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.core.exception import WazuhError


# Variables
parent_directory = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
data_path = 'core/tests/data/rules'

rule_ossec_conf = {
  "ruleset": {
    "rule_dir": ["core/tests/data/rules"],
    "rule_exclude": ["0010-rules_config.xml"]
  }
}

other_rule_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['ruleset/decoders', 'etc/decoders'],
        'rule_dir': [data_path],
        'rule_exclude': ['0010-rules_config.xml'],
        'list': ['etc/lists/audit-keys', 'etc/lists/amazon/aws-eventnames', 'etc/lists/security-eventchannel']
    }
}

get_rule_file_ossec_conf = {
  "ruleset": {
    "rule_dir": [
        "core/tests/data/rules",
        "tests/data/etc/rules",
        "tests/data/etc/rules/subpath",],
    "rule_exclude": ["0010-rules_config.xml"]
  }
}

rule_contents = '''
<group name="ossec,">
  <rule id="501" level="3" overwrite="no">
    <if_sid>500</if_sid>
    <if_fts />
    <options>alert_by_email</options>
    <match>Agent started</match>
    <description>New ossec agent connected.</description>
    <group>pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.3,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
    <list field="user" lookup="match_key">etc/lists/list-user</list>
    <field name="netinfo.iface.name">ens33</field>
    <regex>$(\\d{2,3}.\\d{2,3}.\\d{2,3}.\\d{2,3})</regex>
  </rule>
</group>
    '''


@pytest.fixture(scope='module', autouse=True)
def mock_wazuh_path():
    with patch('wazuh.core.common.WAZUH_PATH', new=parent_directory):
        yield


@pytest.fixture(scope='module', autouse=True)
def mock_rules_path():
    with patch('wazuh.core.common.RULES_PATH', new=data_path):
        yield


@pytest.mark.parametrize('func', [
    rule.get_rules_files,
    rule.get_rules
])
@pytest.mark.parametrize('status', [
    None,
    'all',
    'enabled',
    'disabled',
    'random'
])
@patch("wazuh.rule.configuration.get_ossec_conf", return_value=rule_ossec_conf)
def test_get_rules_files_status_include(mock_ossec, status, func):
    """Test getting rules using status filter."""
    m = mock_open(read_data=rule_contents)
    if status == 'random':
        # Check the error raised when using an invalid rule status
        with pytest.raises(WazuhError, match='.* 1202 .*'):
            func(status=status)
    else:
        with patch('builtins.open', m):
            # Check the result with a valid rule status (all, enabled, disabled)
            d_files = func(status=status).to_dict()
            assert d_files['total_affected_items'] == len(d_files['affected_items']) and \
                   len(d_files['affected_items']) != 0
            if status == 'enabled':
                assert d_files['affected_items'][0]['status'] == 'enabled'
            if status != 'enabled':
                index_disabled = next((index for (index, d) in enumerate(
                    d_files['affected_items']) if d["status"] == "disabled"), None)
                assert d_files['affected_items'][index_disabled]['filename'] == '0010-rules_config.xml'


@pytest.mark.parametrize('func', [
    rule.get_rules_files,
    rule.get_rules
])
@pytest.mark.parametrize('file_', [
    ['0010-rules_config.xml'],
    ['0015-ossec_rules.xml']
])
@patch('wazuh.core.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_rules_files_file_param(mock_config, file_, func):
    """Test getting rules using param filter."""
    d_files = func(filename=file_)
    assert [d_files.affected_items[0]['filename']] == file_
    if func == rule.get_rules_files:
        assert d_files.total_affected_items == 1
    else:
        assert d_files.total_affected_items == len(d_files.affected_items)


@patch('wazuh.core.configuration.get_ossec_conf', return_value=None)
def test_failed_get_rules_file(mock_config):
    """
    Test failed get_rules_file function when ossec.conf don't have ruleset section
    """
    with pytest.raises(WazuhError, match=".* 1200 .*"):
        rule.get_rules_files()


@pytest.mark.parametrize('arg', [
    {'group': 'web', 'pci_dss': 'user1'},
    {'rule_ids': ['31301'], 'filename': '0025-sendmail_rules.xml'},
    {'group': 'user1'},
    {'pci_dss': 'user1'},
    {'pci_dss': '11.4'},
    {'gpg13': '4.13'},
    {'gdpr': 'IV_35.7.d'},
    {'hipaa': '164.312.b'},
    {'nist_800_53': 'AU.14'},
    {'tsc': 'CC7.4'},
    {'mitre': 'T1017'},
    {'rule_ids': [510], 'status': 'all'},
    {'rule_ids': [1, 1]},
    {'rule_ids': [510, 1], 'filename': ['noexists.xml']},
    {'rule_ids': [510, 999999], 'status': 'disabled'},
    {'level': '2'},
    {'level': '2-2'},
    {'rule_ids': ['1', '2', '4', '8']},
    {'rule_ids': ['3']}  # No exists
])
@patch('wazuh.core.configuration.get_ossec_conf', return_value=other_rule_ossec_conf)
def test_get_rules(mock_config, arg):
    """Test get_rules function."""
    result = rule.get_rules(**arg)

    assert isinstance(result, AffectedItemsWazuhResult)
    for rule_ in result.to_dict()['affected_items']:
        if list(arg.keys())[0] != 'level':
            key = list(arg.keys())[0] if list(arg.keys())[0] != 'rule_ids' else 'id'

            if key == 'id':
                for rule_id in arg[list(arg.keys())[0]]:
                    assert rule_id in [rule_[key]]
            else:
                for rule_id in [arg[list(arg.keys())[0]]]:
                    assert rule_id in rule_[key]
        else:
            try:
                found = arg[list(arg.keys())[0]] in str(rule_[list(arg.keys())[0]])
                if found:
                    assert True
                assert str(rule_[list(arg.keys())[0]]) in arg[list(arg.keys())[0]]
            except WazuhError as e:
                # Check the error raised when using an nonexistent rule_id
                assert 'rule_ids' in arg.keys()
                assert e.code == 1208


def test_failed_get_rules():
    """Test error 1203 in get_rules function."""
    with pytest.raises(WazuhError, match=".* 1203 .*"):
        rule.get_rules(level='2-3-4')


@pytest.mark.parametrize('arg', [
    {'search_text': None},
    {'search_text': "firewall", "complementary_search": False}
])
@patch('wazuh.core.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_groups(mock_config, arg):
    """Test get_groups function."""
    result = rule.get_groups(**arg)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 0
    assert result.total_affected_items > 0


@pytest.mark.parametrize('requirement', [
    'pci_dss', 'gdpr', 'hipaa', 'nist_800_53', 'gpg13', 'tsc', 'mitre'
])
@patch('wazuh.core.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_requirement(mocked_config, requirement):
    """Test get_requirement function."""
    result = rule.get_requirement(requirement=requirement)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 0
    assert result.total_affected_items > 0


@pytest.mark.parametrize('requirement', [
    'a', 'b', 'c'
])
@patch('wazuh.core.configuration.get_ossec_conf', return_value=rule_ossec_conf)
def test_get_requirement_invalid(mocked_config, requirement):
    """Test get_requirement (invalid) function."""
    result = rule.get_requirement(requirement=requirement)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_failed_items == 1
    assert result.total_affected_items == 0


@pytest.mark.parametrize('filename, raw, relative_dirname, contains', [
    ('0010-rules_config.xml', True, None, None),
    ('0015-ossec_rules.xml', False, None, None),
    ('test_rules.xml', False, None, 'NEW RULE WITHOUT SUBPATH'),
    ('test_rules.xml', True, 'tests/data/etc/rules/subpath', 'NEW RULE SUBPATH'),
    ('test_rules.xml', True, 'tests/data/etc/rules/subpath/', 'NEW RULE SUBPATH'),
])
@patch('wazuh.core.common.RULES_PATH', new=os.path.join(parent_directory, data_path))
@patch('wazuh.core.common.USER_RULES_PATH', new=os.path.join(parent_directory, "tests","data", "etc", "rules"))
def test_get_rule_file(filename, raw, relative_dirname, contains):
    """Test downloading a specified rule filter."""
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        d_files = rule.get_rule_file(filename=filename, raw=raw, relative_dirname=relative_dirname)
        if raw:
            assert isinstance(d_files, str)
            if contains:
                assert d_files.find(contains)
        else:
            assert isinstance(d_files, AffectedItemsWazuhResult)
            assert d_files.affected_items
            assert not d_files.failed_items


@patch('wazuh.core.common.RULES_PATH', new=os.path.join(parent_directory, data_path))
@patch('wazuh.core.common.USER_RULES_PATH', new=os.path.join(parent_directory, "tests", "data", "etc", "rules"))
def test_get_rule_file_exceptions():
    """Test file exceptions on get_rule_file method."""
    # File does not exist in default ruleset
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        result = rule.get_rule_file(filename='non_existing_file.xml')
        assert not result.affected_items
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1415

        # File does not exist in user ruleset
        result = rule.get_rule_file(filename='non_existing_file.xml', raw=False)
        assert not result.affected_items
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1415

        # File exist in default ruleset but not in custom ruleset
        result = rule.get_rule_file(filename='0010-rules_config.xml', raw=False, 
                                    relative_dirname=USER_RULES_PATH)
        assert not result.affected_items
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1415
        
        # Invalid XML
        result = rule.get_rule_file(filename='wrong_rules.xml', raw=False)
        assert not result.affected_items
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1413

        # File permissions
        with patch('builtins.open', side_effect=PermissionError):
            result = rule.get_rule_file(filename='0010-rules_config.xml')
            assert not result.affected_items
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1414


@pytest.mark.parametrize('file, overwrite', [
    ('test.xml', False),
    ('test_rules.xml', True),
])
@patch('wazuh.rule.delete_rule_file')
@patch('wazuh.rule.upload_file')
@patch('wazuh.core.utils.full_copy')
@patch('wazuh.rule.remove')
@patch('wazuh.rule.safe_move')
@patch('wazuh.core.utils.check_remote_commands')
def test_upload_file(mock_remote_commands, mock_safe_move, mock_remove, mock_full_copy, mock_xml, mock_delete, file,
                     overwrite):
    """Test uploading a rule file.

    Parameters
    ----------
    file : str
        Rule filename.
    overwrite : boolean
        True for updating existing files, False otherwise.
    """
    with patch('wazuh.rule.exists', return_value=overwrite):
        result = rule.upload_rule_file(filename=file, content='test', overwrite=overwrite)

        # Assert data match what was expected, type of the result and correct parameters in delete() method.
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        rule_path = os.path.join('etc', 'rules', file)
        assert result.affected_items[0] == rule_path, 'Expected item not found'
        mock_xml.assert_called_once_with('test', rule_path)
        if overwrite:
            mock_delete.assert_called_once_with(filename=file), 'delete_rule_file method not called with expected ' \
                                                                'parameter'
            mock_remove.assert_called_once()
            mock_safe_move.assert_called_once()


@patch('wazuh.rule.delete_rule_file')
@patch('wazuh.rule.upload_file')
@patch('wazuh.rule.safe_move')
@patch('wazuh.core.utils.check_remote_commands')
def test_upload_file_ko(mock_remote_commands, mock_safe_move, mock_xml, mock_delete):
    """Test exceptions on upload function."""
    # Error when file exists and overwrite is not True
    with patch('wazuh.rule.exists'):
        result = rule.upload_rule_file(filename='test_rules.xml', content='test', overwrite=False)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1905, 'Error code not expected.'

    # Error when content is empty
    result = rule.upload_rule_file(filename='no_exist.xml', content='', overwrite=False)
    assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
    assert result.render()['data']['failed_items'][0]['error']['code'] == 1112, 'Error code not expected.'

    # Error doing backup
    with patch('wazuh.rule.exists'):
        result = rule.upload_rule_file(filename='test_rules.xml', content='test', overwrite=True)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1019, 'Error code not expected.'


def test_delete_rule_file():
    """Test deleting a rule file."""
    with patch('wazuh.rule.exists', return_value=True):
        # Assert returned type is AffectedItemsWazuhResult when everything is correct
        with patch('wazuh.rule.remove'):
            assert(isinstance(rule.delete_rule_file(filename='file'), AffectedItemsWazuhResult))
        # Assert error code when remove() method returns IOError
        with patch('wazuh.manager.remove', side_effect=IOError()):
            result = rule.delete_rule_file(filename='file')
            assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1907, 'Error code not expected.'

    # Assert error code when exists() method returns False
    with patch('wazuh.manager.exists', return_value=False):
        result = rule.delete_rule_file(filename='file')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1906, 'Error code not expected.'
