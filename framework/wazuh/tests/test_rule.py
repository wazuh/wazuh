# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import glob
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
core_data_path = 'core/tests/data/rules'
tests_data_path = 'tests/data/etc/rules'

rule_ossec_conf = {
  "ruleset": {
    "rule_dir": [core_data_path],
    "rule_exclude": ["0010-rules_config.xml"]
  }
}

other_rule_ossec_conf = {
    'ruleset': {
        'decoder_dir': ['ruleset/decoders', 'etc/decoders'],
        'rule_dir': [core_data_path],
        'rule_exclude': ['0010-rules_config.xml'],
        'list': ['etc/lists/audit-keys', 'etc/lists/amazon/aws-eventnames', 'etc/lists/security-eventchannel', 'etc/lists/malicious-ioc/malware-hashes', 'etc/lists/malicious-ioc/malicious-ip', 'etc/lists/malicious-ioc/malicious-domains']
    }
}

get_rule_file_ossec_conf = {
  "ruleset": {
    "rule_dir": [
        core_data_path,
        tests_data_path,
        os.path.join(tests_data_path, 'subpath'),
        os.path.join(tests_data_path, 'subpath2'),],
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
def mock_wazuh_paths():
    with patch('wazuh.core.common.RULES_PATH', new=os.path.join(parent_directory, core_data_path)):
        with patch('wazuh.core.common.USER_RULES_PATH', new=os.path.join(parent_directory, tests_data_path)):
            with patch('wazuh.core.common.WAZUH_PATH', new=parent_directory):
                with patch('wazuh.rule.to_relative_path', side_effect=lambda x: os.path.relpath(x, parent_directory)):
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


@pytest.mark.parametrize('filename, relative_dirname, result', [
    ('0010-rules_config.xml', None, 'core/tests/data/rules/0010-rules_config.xml'),
    ('test_rules.xml', None, 'tests/data/etc/rules/test_rules.xml'),
    ('test_rules.xml', 'tests/data/etc/rules', 'tests/data/etc/rules/test_rules.xml'),
    ('test_rules.xml', 'tests/data/etc/rules/subpath', 'tests/data/etc/rules/subpath/test_rules.xml'),
    ('test_rules.xml', 'tests/data/etc/rules/subpath/', 'tests/data/etc/rules/subpath/test_rules.xml'),
    ('not_found.xml', None, ''),
])
def test_get_rule_file_path(filename, relative_dirname, result, mock_wazuh_paths):
    """Test get_rule_file_path function."""
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        res = rule.get_rule_file_path(filename=filename,
                                            relative_dirname=relative_dirname)
        assert res == os.path.join(wazuh.core.common.WAZUH_PATH, result) if result else not res


@pytest.mark.parametrize('filename, raw, relative_dirname, contains', [
    ('0010-rules_config.xml', True, None, None),
    ('0015-ossec_rules.xml', False, None, None),
    ('test_rules.xml', False, None, 'NEW RULE WITHOUT SUBPATH'),
    ('test_rules.xml', True, 'tests/data/etc/rules/subpath', 'NEW RULE SUBPATH'),
    ('test_rules.xml', True, 'tests/data/etc/rules/subpath/', 'NEW RULE SUBPATH'),
])
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


@pytest.mark.parametrize('relative_dirname, res_path, err_code', [
    (None, 'tests/data/etc/rules', None),
    ('tests/data/etc/rules/', 'tests/data/etc/rules', None),
    ('tests/data/etc/rules/subpath', 'tests/data/etc/rules/subpath', None),
    ('tests/data/etc/rules/subpath/', 'tests/data/etc/rules/subpath', None),
    ('tests/data/etc/rules/subpath3', 'tests/data/etc/rules/subpath3', 1209),
    ('core/tests/data/rules', 'core/tests/data/rules', 1210),
    ('tests/data/etc/rules/subpath2', 'tests/data/etc/rules/subpath2', 1211),
])
def test_validate_upload_delete_dir(relative_dirname, res_path, err_code):
    """Test validate_upload_delete_dir function."""
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        ret_path, ret_err = rule.validate_upload_delete_dir(relative_dirname = relative_dirname)
        assert ret_path == res_path and (ret_err.code == err_code if err_code else not ret_err)


@pytest.mark.parametrize('file, relative_dirname, overwrite, rule_path', [
    ('test_rules.xml', None, True, 'tests/data/etc/rules/test_rules.xml'),
    ('test_rules.xml', 'tests/data/etc/rules/subpath', True, 'tests/data/etc/rules/subpath/test_rules.xml'),
    ('test_new_rule.xml', None, False, 'tests/data/etc/rules/test_new_rule.xml'),
    ('test_new_rule.xml', 'tests/data/etc/rules/subpath', False, 'tests/data/etc/rules/subpath/test_new_rule.xml'),
])
@patch('wazuh.rule.delete_rule_file')
@patch('wazuh.rule.full_copy')
@patch('wazuh.rule.upload_file')
@patch('wazuh.rule.remove')
@patch('wazuh.rule.safe_move')
@patch('wazuh.rule.validate_dummy_logtest')
def test_upload_file(mock_logtest, mock_safe_move, mock_remove, mock_xml, mock_full_copy,
                     mock_delete, file, relative_dirname, overwrite, rule_path):
    """Test uploading a rule file.

    Parameters
    ----------
    file : str
        Rule filename.
    relative_dirname: str
        Relative path of the file.
    overwrite : boolean
        True for updating existing files, False otherwise.
    rule_path: str
        Relative path of the file
    """

    content = 'test'
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        ret_validation = rule.validate_upload_delete_dir(relative_dirname=relative_dirname)
        with patch('wazuh.rule.validate_upload_delete_dir', return_value=ret_validation):
            with patch('wazuh.rule.exists', return_value=overwrite):
                result = rule.upload_rule_file(filename=file, relative_dirname=relative_dirname,
                                                content=content, overwrite=overwrite)

                # Assert data match what was expected, type of the result and correct
                # parameters in delete() method.
                assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
                assert result.affected_items[0] == rule_path, 'Expected item not found'
                mock_xml.assert_called_once_with(content, rule_path)
                if overwrite:
                    full_path = os.path.join(wazuh.common.WAZUH_PATH, rule_path)
                    backup_file = full_path+'.backup'
                    mock_full_copy.assert_called_once_with(full_path, backup_file), \
                    'full_copy function not called with expected parameters'
                    mock_delete.assert_called_once_with(filename= file,
                                                        relative_dirname=os.path.dirname(rule_path)), \
                        'delete_rule_file method not called with expected parameter'
                    mock_remove.assert_called_once()
                    mock_safe_move.assert_called_once()


@patch('wazuh.rule.delete_rule_file', side_effect=WazuhError(1019))
@patch('wazuh.rule.upload_file')
@patch('wazuh.rule.safe_move')
@patch('wazuh.core.utils.check_remote_commands')
def test_upload_file_ko(*args):
    """Test exceptions on upload function."""
    content = 'test'
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        ret_validation = rule.validate_upload_delete_dir(relative_dirname=None)
        with patch('wazuh.rule.validate_upload_delete_dir', return_value=ret_validation):
            # Error when file exists and overwrite is not True
            result = rule.upload_rule_file(filename='test_rules.xml', content=content, overwrite=False)
            assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1905, 'Error code not expected.'

        # Error when content is empty
        result = rule.upload_rule_file(filename='test_rules.xml', content='', overwrite=False)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1112, 'Error code not expected.'

        # Error doing backup
        result = rule.upload_rule_file(filename='test_rules.xml', content=content, overwrite=True)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1019, 'Error code not expected.'

        # Error relative_path is not declared in rule_dir
        result = rule.upload_rule_file(filename='test_rule.xml',
                                            relative_dirname='tests/data/etc/rules/subpath3',
                                            content='test')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1209,\
            'Error code not expected.'

        # Error uploading rule in default ruleset dir
        result = rule.upload_rule_file(filename='test_rules.xml',
                                    relative_dirname='core/tests/data/rules',
                                    content=content, overwrite=True)
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1210,\
            'Error code not expected.'

        # Error upload file to existing rule_dir but the directory is not found
        result = rule.upload_rule_file(filename='test_rule.xml',
                                            relative_dirname='tests/data/etc/rules/subpath2',
                                            content='test')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1211,\
            'Error code not expected.'

        # clean backup files
        search_pattern = os.path.join(wazuh.core.common.WAZUH_PATH, "**", "*.backup")
        for bkp in glob.glob(search_pattern, recursive=True):
            os.remove(bkp)


@pytest.mark.parametrize('file, relative_dirname', [
    ('test_rules.xml', None),
    ('test_rules.xml', 'tests/data/etc/rules'),
])
def test_delete_rule_file(file, relative_dirname):
    """Test deleting a rule file."""
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        with patch('wazuh.rule.exists', return_value=True):
            with patch('wazuh.rule.remove'):
                # Assert returned type is AffectedItemsWazuhResult when everything is correct
                assert(isinstance(rule.delete_rule_file(filename=file, relative_dirname=relative_dirname),
                                AffectedItemsWazuhResult))

def test_delete_rule_file_ko():
    """Delete rule file invalid test cases"""
    with patch('wazuh.core.configuration.get_ossec_conf', return_value=get_rule_file_ossec_conf):
        # Assert error code when remove() method returns IOError
        with patch('wazuh.rule.remove', side_effect=IOError()):
            result = rule.delete_rule_file(filename='test_rules.xml')
            assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
            assert result.render()['data']['failed_items'][0]['error']['code'] == 1907,\
                'Error code not expected.'

        # Assert error code when exists() method returns False
        result = rule.delete_rule_file(filename='file')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1906,\
            'Error code not expected.'

        # Assert error code passing invalid relative_dirname
        result = rule.delete_rule_file(filename='test_rules.xml',
                                        relative_dirname='etc/not_exists')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1209,\
            'Error code not expected.'

        # Error uploading rule in default ruleset dir
        result = rule.delete_rule_file(filename='test1_rules.xml',
                                        relative_dirname='core/tests/data/rules')
        assert isinstance(result, AffectedItemsWazuhResult), 'No expected result type'
        assert result.render()['data']['failed_items'][0]['error']['code'] == 1210,\
            'Error code not expected.'
