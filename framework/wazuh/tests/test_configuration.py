# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
import sys
from unittest.mock import patch, MagicMock
import subprocess

import pytest
from wazuh import exception, common


with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.results import AffectedItemsWazuhResult, WazuhResult
        from wazuh.exception import WazuhError, WazuhInternalError
        from wazuh import configuration


parent_directory = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
tmp_path = 'core/tests/data'


@pytest.fixture(scope='module', autouse=True)
def mock_ossec_path():
    with patch('wazuh.common.ossec_path', new=os.path.join(parent_directory, tmp_path)):
        yield


@pytest.mark.parametrize("json_dst, section_name, option, value", [
    ({'new': None}, None, 'new', 1),
    ({'new': [None]}, None, 'new', [1]),
    ({}, None, 'new', 1),
    ({}, None, 'new', False),
    ({'old': [None]}, 'ruleset', 'include', [1])
])
def test_insert(json_dst, section_name, option, value):
    """Checks insert function."""
    configuration._insert(json_dst, section_name, option, value)
    if value:
        if isinstance(value, list):
            assert value in json_dst[option]
        else:
            assert value == json_dst[option]
    else:
        assert json_dst == {}


@pytest.mark.parametrize("json_dst, section_name, section_data", [
    ({'old': []}, 'ruleset', 'include'),
    ({'labels': []}, 'labels', ['label']),
    ({'ruleset': []}, 'labels', ['label']),
    ({'global': {'label': 5}}, 'global', {'label': 4}),
    ({'global': {'white_list': []}}, 'global', {'white_list': [4], 'label2': 5}),
    ({'cluster': {'label': 5}}, 'cluster', {'label': 4})
])
def test_insert_section(json_dst, section_name, section_data):
    """Checks insert_section function."""
    configuration._insert_section(json_dst, section_name, section_data)
    if isinstance(json_dst[section_name], list):
        json_dst[section_name] = json_dst[section_name][0]
    assert json_dst[section_name] == section_data


# @pytest.mark.parametrize("json_dst, section_name, section_data", [
#     ({'old': []}, 'ruleset', 'include'),
#     ({'labels': []}, 'labels', ['label']),
#     ({'ruleset': []}, 'labels', ['label']),
#     ({'global': {'label': 5}}, 'global', {'label': 4}),
#     ({'global': {'white_list': []}}, 'global', {'white_list': [4], 'label2': 5}),
#     ({'cluster': {'label': 5}}, 'cluster', {'label': 4})
# ])
# def test_read_option(section_name, opt):
#     """Checks insert_section function."""
#     configuration._insert_section(json_dst, section_name, section_data)
#     if isinstance(json_dst[section_name], list):
#         json_dst[section_name] = json_dst[section_name][0]
#     assert json_dst[section_name] == section_data


def test_conf2json():
    pass


def test_ossecconf2json():
    pass


def test_agentconf2json():
    pass


def test_rcl2json():
    pass


def test_rootkit_files2json():
    pass


def test_rootkit_trojans2json():
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration._rootkit_trojans2json(filepath=os.path.join(
                parent_directory, tmp_path, 'configuration/trojan.txt'))

    assert isinstance(configuration._rootkit_trojans2json(filepath=os.path.join(
        parent_directory, tmp_path, 'configuration/trojan.txt')), list)


def test_get_ossec_conf():
    with patch('wazuh.configuration.load_wazuh_xml', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration.get_ossec_conf()

    assert isinstance(configuration.get_ossec_conf(conf_file=os.path.join(
        parent_directory, tmp_path, 'configuration/ossec.conf')), WazuhResult)

    with pytest.raises(WazuhError, match=".* 1102 .*"):
        configuration.get_ossec_conf(section='noexists',
                                     conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))

    with pytest.raises(WazuhError, match=".* 1106 .*"):
        configuration.get_ossec_conf(section='remote',
                                     conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))

    assert isinstance(configuration.get_ossec_conf(
        section='cluster', conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf')), WazuhResult)

    assert isinstance(configuration.get_ossec_conf(
        section='cluster', field='name', conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf')), WazuhResult)

    assert isinstance(configuration.get_ossec_conf(
        section='integration', field='node',
        conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf')), WazuhResult)

    with pytest.raises(WazuhError, match=".* 1103 .*"):
        configuration.get_ossec_conf(
            section='integration', field='error',
            conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))


def test_get_agent_conf():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.get_agent_conf(group_id='noexists')

    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1006 .*"):
            configuration.get_agent_conf(group_id='default', filename='noexists.conf')

    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.configuration.load_wazuh_xml', return_value=Exception):
            with pytest.raises(WazuhError, match=".* 1101 .*"):
                assert isinstance(configuration.get_agent_conf(group_id='default'), dict)

    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert isinstance(configuration.get_agent_conf(group_id='default'), dict)


def test_get_agent_conf_multigroup():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.get_agent_conf_multigroup()
    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1006 .*"):
            configuration.get_agent_conf_multigroup(multigroup_id='multigroup', filename='noexists.conf')
    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.configuration.load_wazuh_xml', return_value=Exception):
            with pytest.raises(WazuhError, match=".* 1101 .*"):
                configuration.get_agent_conf_multigroup(multigroup_id='multigroup')
    with patch('wazuh.common.multi_groups_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        result = configuration.get_agent_conf_multigroup(multigroup_id='multigroup')
        assert set(result.keys()) == {'totalItems', 'items'}


def test_get_file_conf():
    with patch('wazuh.common.shared_path', new=os.path.join(parent_directory, tmp_path, 'noexists')):
        with pytest.raises(WazuhError, match=".* 1710 .*"):
            configuration.get_file_conf(filename='ossec.conf', group_id='default', type_conf='conf',
                                        return_format='xml')

    with pytest.raises(WazuhError, match=".* 1006 .*"):
        configuration.get_file_conf(filename='ossec.conf', group_id='default', type_conf='conf', return_format='xml')

    with patch('wazuh.common.shared_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='conf',
                                                      return_format='xml'), str)
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='rcl',
                                                      return_format='xml'), dict)
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default',
                                                      return_format='xml'), str)
        assert isinstance(configuration.get_file_conf(filename='rootkit_files.txt', group_id='default',
                                                      return_format='xml'), list)
        assert isinstance(configuration.get_file_conf(filename='rootkit_trojans.txt', group_id='default',
                                                      return_format='xml'), list)
        assert isinstance(configuration.get_file_conf(filename='ar.conf', group_id='default',
                                                      return_format='xml'), list)
        assert isinstance(configuration.get_file_conf(filename='rcl.conf', group_id='default',
                                                      return_format='xml'), dict)
        with pytest.raises(WazuhError, match=".* 1104 .*"):
            assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='noconf',
                                                          return_format='xml'), str)


def test_parse_internal_options():
    with patch('wazuh.common.internal_options',
               new=os.path.join(parent_directory, tmp_path, 'configuration/default/agent.conf')):
        with pytest.raises(WazuhInternalError, match=".* 1108 .*"):
            configuration.parse_internal_options('ossec', 'python')

    with patch('wazuh.common.internal_options',
               new=os.path.join(parent_directory, tmp_path, 'noexists')):
        with pytest.raises(WazuhInternalError, match=".* 1107 .*"):
            configuration.parse_internal_options('ossec', 'python')


def test_get_internal_options_value():
    with patch('wazuh.configuration.parse_internal_options', return_value='str'):
        with pytest.raises(WazuhError, match=".* 1109 .*"):
            configuration.get_internal_options_value('ossec', 'python', 5, 1)

    with patch('wazuh.configuration.parse_internal_options', return_value='0'):
        with pytest.raises(WazuhError, match=".* 1110 .*"):
            configuration.get_internal_options_value('ossec', 'python', 5, 1)

    with patch('wazuh.configuration.parse_internal_options', return_value='1'):
        assert configuration.get_internal_options_value('ossec', 'python', 5, 1) == 1


def test_upload_group_configuration():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.upload_group_configuration('noexists', 'noexists')

    with patch('wazuh.common.shared_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhInternalError, match=".* 1743 .*"):
            configuration.upload_group_configuration('default', "{'a': 'b'}")
        with patch('wazuh.configuration.open', return_value=Exception):
            with pytest.raises(WazuhError, match=".* 1113 .*"):
                configuration.upload_group_configuration('default', "{'a': 'b'}")
        with patch('wazuh.configuration.subprocess.check_output', return_value=True):
            assert isinstance(configuration.upload_group_configuration('default', "{'a': 'b'}"), str)
            with patch('wazuh.configuration.safe_move', side_effect=Exception):
                with pytest.raises(WazuhInternalError, match=".* 1016 .*"):
                    configuration.upload_group_configuration('default', "{'a': 'b'}")
        with patch('wazuh.configuration.subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(cmd='ls', returncode=1, output=b'ERROR')):
            with pytest.raises(WazuhError, match=".* 1115 .*"):
                configuration.upload_group_configuration('default', "{'a': 'b'}")
            with patch('wazuh.configuration.re.findall', return_value='1114'):
                with pytest.raises(WazuhError, match=".* 1114 .*"):
                    configuration.upload_group_configuration('default', "{'a': 'b'}")


def test_upload_group_file():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.upload_group_file('noexists', 'given', 'noexists')

    with patch('wazuh.configuration.os_path.exists', return_value=True):
        with pytest.raises(WazuhError, match=".* 1112 .*"):
            configuration.upload_group_file('default', [], 'agent.conf')

    with patch('wazuh.common.shared_path', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.configuration.subprocess.check_output', return_value=True):
            with patch('wazuh.configuration.os_path.exists', return_value=True):
                assert isinstance(configuration.upload_group_file('default', "{'a': 'b'}", 'agent.conf'), str)

    with pytest.raises(WazuhError, match=".* 1111 .*"):
        configuration.upload_group_file('default', [], 'a.conf')


@pytest.mark.parametrize("exception_type, agent_id, component, config, exception_", [
    (WazuhError, '000', None, None, 1307),
    (WazuhError, '000', None, 'given', 1307),
    (WazuhError, '000', 'given', 'given', 1101),
    (WazuhInternalError, '000', 'agent', 'given', 1121),
    (WazuhInternalError, '001', 'agent', 'given', 1121)
])
def test_get_active_configuration_first_exceptions(exception_type, agent_id, component, config, exception_):
    """This test checks the first three exceptions."""
    with patch('wazuh.configuration.OssecSocket.__init__', return_value=Exception):
        with pytest.raises(exception_type, match=f".* {exception_} .*"):
            configuration.get_active_configuration(agent_id, component, config)


@pytest.mark.parametrize("agent_id, component, config, exception_", [
    ('000', 'agent', 'given', 1118)
])
def test_get_active_configuration_second_exceptions(agent_id, component, config, exception_):
    """This test checks the fourth exception."""
    with patch('wazuh.configuration.OssecSocket.__init__', return_value=None):
        with patch('wazuh.configuration.OssecSocket.send', side_effect=None):
            with patch('wazuh.configuration.OssecSocket.receive', side_effect=ValueError):
                with pytest.raises(WazuhInternalError, match=f".* {exception_} .*"):
                    configuration.get_active_configuration(agent_id, component, config)


@pytest.mark.parametrize("agent_id, component, config, exception_", [
    ('000', 'agent', 'given', 1116)
])
def test_get_active_configuration_third_exceptions(agent_id, component, config, exception_):
    """This test checks the last exception."""
    with patch('wazuh.configuration.OssecSocket.__init__', return_value=None):
        with patch('wazuh.configuration.OssecSocket.send', side_effect=None):
            with patch('wazuh.configuration.OssecSocket.receive', return_value=b'test 1'):
                with patch('wazuh.configuration.OssecSocket.close', side_effect=None):
                    with pytest.raises(WazuhError, match=f".* {exception_} .*"):
                        configuration.get_active_configuration(agent_id, component, config)


@pytest.mark.parametrize("agent_id, component, config, exception_", [
    ('000', 'agent', 'given', None)
])
def test_get_active_configuration_fourth_exception(agent_id, component, config, exception_):
    with patch('wazuh.configuration.OssecSocket.__init__', return_value=None):
        with patch('wazuh.configuration.OssecSocket.send', side_effect=None):
            with patch('wazuh.configuration.OssecSocket.receive', return_value=b'ok {"a": "2"}'):
                with patch('wazuh.configuration.OssecSocket.close', side_effect=None):
                    assert {"a": "2"} == configuration.get_active_configuration(agent_id, component, config)
