# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess
import sys
from types import MappingProxyType
from unittest.mock import mock_open, ANY
from unittest.mock import patch, MagicMock

import pytest
from defusedxml.ElementTree import fromstring

from wazuh.core.common import OSSEC_CONF, REMOTED_SOCKET

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.core.exception import WazuhError, WazuhInternalError
        from wazuh.core import configuration

parent_directory = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
tmp_path = 'tests/data'


@pytest.fixture(scope='module', autouse=True)
def mock_wazuh_path():
    with patch('wazuh.core.common.WAZUH_PATH', new=os.path.join(parent_directory, tmp_path)):
        yield


@pytest.mark.parametrize("json_dst, section_name, option, value", [
    ({'new': None}, None, 'new', 1),
    ({'new': [None]}, None, 'new', [1]),
    ({}, None, 'new', 1),
    ({}, None, 'new', False),
    ({'old': [None]}, 'ruleset', 'include', [1]),
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


def test_read_option():
    """Checks insert_section function."""
    with open(os.path.join(parent_directory, tmp_path, 'configuration/default/options.conf')) as f:
        data = fromstring(f.read())
        assert configuration._read_option('open-scap', data)[0] == 'directories'
        assert configuration._read_option('syscheck', data)[0] == 'directories'
        assert configuration._read_option('labels', data)[0] == 'directories'

    with open(os.path.join(parent_directory, tmp_path, 'configuration/default/options1.conf')) as f:
        data = fromstring(f.read())
        assert configuration._read_option('labels', data)[0] == 'label'
        assert configuration._read_option('test', data) == ('label', {'name': 'first', 'item': 'test'})

    with open(os.path.join(parent_directory, tmp_path, 'configuration/default/synchronization.conf')) as f:
        data = fromstring(f.read())
        assert configuration._read_option('open-scap', data)[0] == 'synchronization'
        assert configuration._read_option('syscheck', data)[0] == 'synchronization'

    with open(os.path.join(parent_directory, tmp_path, 'configuration/default/vulnerability_detection.conf')) as f:
        data = fromstring(f.read())
        EXPECTED_VALUES = MappingProxyType(
            {'enabled': 'no', 'feed-update-interval': '60m', 'index-status': 'yes'}
        )
        for section in data:
            assert configuration._read_option('vulnerability-detection', section) == (section.tag,
                                                                                     EXPECTED_VALUES[section.tag])

    with open(os.path.join(parent_directory, tmp_path, 'configuration/default/indexer.conf')) as f:
        data = fromstring(f.read())
        EXPECTED_VALUES = MappingProxyType(
            {
                'enabled': 'yes',
                'hosts': ['http://127.0.0.1:9200', 'http://127.0.0.2:9200'],
                'username': 'admin',
                'password': 'admin',
            }
        )
        for section in data:
            assert configuration._read_option('indexer', section) == (section.tag,
                                                                    EXPECTED_VALUES[section.tag])


@pytest.mark.parametrize("configuration_file, expected_values", [
    ('journald.conf', MappingProxyType({
            "location": "journald",
            "log_format": "journald",
            "filter": [{
                "field": "MESSAGE_ID",
                "item": "^8d45620c1a4348dbb17410da57c60c66$"
            }],
            "only-future-events": "no"
        })
     ),
    ('journald1.conf', MappingProxyType({
            "location": "journald",
            "log_format": "journald",
            "filter": [
                {
                    "field": "_SYSTEMD_UNIT",
                    "item": "^cron.service$"
                },
                {

                    "field": "PRIORITY",
                    "ignore_if_missing": "yes",
                    "item": "[0-3]"
                }
            ]
        })
     )
])
def test_read_option_journald(configuration_file, expected_values):
    with open(os.path.join(parent_directory, tmp_path, f'configuration/default/{configuration_file}')) as f:
        data = fromstring(f.read())
        list_of_filters = []

        for section in data:
            if section.tag == 'filter':
                list_of_filters.append(configuration._read_option('localfile', section)[1])
            else:
                assert configuration._read_option('localfile', section) == (section.tag,
                                                                            expected_values[section.tag])

        assert list_of_filters == expected_values["filter"]

def test_agentconf2json():
    xml_conf = configuration.load_wazuh_xml(
        os.path.join(parent_directory, tmp_path, 'configuration/default/agent1.conf'))

    assert configuration._agentconf2json(xml_conf=xml_conf)[0]['filters'] == {'name': 'agent_name'}


def test_rcl2json():
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration._rcl2json(filepath=os.path.join(
                parent_directory, tmp_path, 'configuration/trojan.txt'))

    assert configuration._rcl2json(filepath=os.path.join(
        parent_directory, tmp_path, 'configuration/trojan.txt'))['vars'] == {'trojan': 'trojan'}


def test_rootkit_files2json():
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration._rootkit_files2json(filepath=os.path.join(
                parent_directory, tmp_path, 'configuration/trojan.txt'))

    assert configuration._rootkit_files2json(filepath=os.path.join(
        parent_directory, tmp_path, 'configuration/trojan.txt'))[0]['filename'] == 'trojan'


def test_rootkit_trojans2json():
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration._rootkit_trojans2json(filepath=os.path.join(
                parent_directory, tmp_path, 'configuration/trojan.txt'))

    assert configuration._rootkit_trojans2json(filepath=os.path.join(
        parent_directory, tmp_path, 'configuration/trojan.txt'))[0]['filename'] == 'trojan'


def test_merged_mg2json():
    """Checks that _merged_mg2json parses the file content correctly."""
    with patch('builtins.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration._merged_mg2json(file_path=os.path.join(
                parent_directory, tmp_path, 'configuration/default/merged.mg'))

    item = configuration._merged_mg2json(file_path=os.path.join(
        parent_directory, tmp_path, 'configuration/default/merged.mg'))[0]

    assert item['file_name'] == 'ar.conf'
    assert item['file_size'] == 77
    assert item['file_content'] == 'restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n'


def test_get_ossec_conf():
    with patch('wazuh.core.configuration.load_wazuh_xml', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1101 .*"):
            configuration.get_ossec_conf()

    with patch('wazuh.core.configuration.load_wazuh_xml', return_value=Exception):
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            configuration.get_ossec_conf(from_import=True)
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 0

    with pytest.raises(WazuhError, match=".* 1102 .*"):
        configuration.get_ossec_conf(section='noexists',
                                     conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))

    with pytest.raises(WazuhError, match=".* 1106 .*"):
        configuration.get_ossec_conf(section='remote',
                                     conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))

    with pytest.raises(WazuhError, match=".* 1103 .*"):
        configuration.get_ossec_conf(
            section='integration', field='error',
            conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'))

    assert configuration.get_ossec_conf(conf_file=os.path.join(
        parent_directory, tmp_path, 'configuration/ossec.conf'))['cluster']['name'] == 'wazuh'

    assert configuration.get_ossec_conf(
        section='cluster',
        conf_file=os.path.join(parent_directory, tmp_path,
                               'configuration/ossec.conf'))['cluster']['name'] == 'wazuh'

    assert configuration.get_ossec_conf(
        section='cluster', field='name',
        conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf')
    )['cluster']['name'] == 'wazuh'

    assert configuration.get_ossec_conf(
        section='integration', field='node',
        conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf')
    )['integration'][0]['node'] == 'wazuh-worker'

    assert configuration.get_ossec_conf(
        conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'),
        section='ruleset',
        field='rule_dir',
        distinct=False)['ruleset']['rule_dir'] == ['ruleset/rules', 'ruleset/rules', 'etc/rules']

    assert configuration.get_ossec_conf(
        conf_file=os.path.join(parent_directory, tmp_path, 'configuration/ossec.conf'),
        section='ruleset',
        field='rule_dir',
        distinct=True)['ruleset']['rule_dir'] == ['ruleset/rules', 'etc/rules']


def test_get_agent_conf():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.get_agent_conf(group_id='noexists')

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1006 .*"):
            configuration.get_agent_conf(group_id='default', filename='noexists.conf')

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.load_wazuh_xml', return_value=Exception):
            with pytest.raises(WazuhError, match=".* 1101 .*"):
                assert isinstance(configuration.get_agent_conf(group_id='default'), dict)

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert configuration.get_agent_conf(group_id='default', filename='agent1.conf')['total_affected_items'] == 1


def test_get_agent_conf_multigroup():
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.get_agent_conf_multigroup()

    with patch('wazuh.core.common.MULTI_GROUPS_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1006 .*"):
            configuration.get_agent_conf_multigroup(multigroup_id='multigroup', filename='noexists.conf')

    with patch('wazuh.core.common.MULTI_GROUPS_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.load_wazuh_xml', return_value=Exception):
            with pytest.raises(WazuhError, match=".* 1101 .*"):
                configuration.get_agent_conf_multigroup(multigroup_id='multigroup')

    with patch('wazuh.core.common.MULTI_GROUPS_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        result = configuration.get_agent_conf_multigroup(multigroup_id='multigroup')
        assert set(result.keys()) == {'totalItems', 'items'}


def test_get_file_conf():
    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'noexists')):
        with pytest.raises(WazuhError, match=".* 1710 .*"):
            configuration.get_file_conf(filename='ossec.conf', group_id='default', type_conf='conf',
                                        raw=True)

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1006 .*"):
            configuration.get_file_conf(filename='noexists.conf', group_id='default', type_conf='conf',
                                        raw=True)

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='conf'),
                          dict)
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='rcl'),
                          dict)
        assert isinstance(configuration.get_file_conf(filename='agent.conf', group_id='default',
                                                      raw=True), str)
        rootkit_files = [{'filename': 'NEW_ELEMENT', 'name': 'FOR', 'link': 'TESTING'}]
        assert configuration.get_file_conf(filename='rootkit_files.txt', group_id='default') == rootkit_files
        rootkit_trojans = [{'filename': 'NEW_ELEMENT', 'name': 'FOR', 'description': 'TESTING'}]
        assert configuration.get_file_conf(filename='rootkit_trojans.txt', group_id='default',) == rootkit_trojans
        ar_list = ['restart-ossec0 - restart-ossec.sh - 0', 'restart-ossec0 - restart-ossec.cmd - 0',
                   'restart-wazuh0 - restart-ossec.sh - 0', 'restart-wazuh0 - restart-ossec.cmd - 0',
                   'restart-wazuh0 - restart-wazuh - 0', 'restart-wazuh0 - restart-wazuh.exe - 0']
        assert configuration.get_file_conf(filename='ar.conf', group_id='default') == ar_list
        rcl = {'vars': {}, 'controls': [{}, {'name': 'NEW_ELEMENT', 'cis': [], 'pci': [], 'condition': 'FOR',
                                             'reference': 'TESTING', 'checks': []}]}
        assert configuration.get_file_conf(filename='rcl.conf', group_id='default') == rcl
        with pytest.raises(WazuhError, match=".* 1104 .*"):
            configuration.get_file_conf(filename='agent.conf', group_id='default', type_conf='noconf')


def test_parse_internal_options():
    with patch('wazuh.core.common.INTERNAL_OPTIONS_CONF',
               new=os.path.join(parent_directory, tmp_path, 'configuration/noexists.conf')):
        with pytest.raises(WazuhInternalError, match=".* 1107 .*"):
            configuration.parse_internal_options('ossec', 'python')

    with patch('wazuh.core.common.INTERNAL_OPTIONS_CONF',
               new=os.path.join(parent_directory, tmp_path, 'configuration/local_internal_options.conf')):
        with patch('wazuh.core.common.LOCAL_INTERNAL_OPTIONS_CONF',
                   new=os.path.join(parent_directory, tmp_path, 'configuration/local_internal_options.conf')):
            with pytest.raises(WazuhInternalError, match=".* 1108 .*"):
                configuration.parse_internal_options('ossec', 'python')


def test_get_internal_options_value():
    with patch('wazuh.core.configuration.parse_internal_options', return_value='str'):
        with pytest.raises(WazuhError, match=".* 1109 .*"):
            configuration.get_internal_options_value('ossec', 'python', 5, 1)

    with patch('wazuh.core.configuration.parse_internal_options', return_value='0'):
        with pytest.raises(WazuhError, match=".* 1110 .*"):
            configuration.get_internal_options_value('ossec', 'python', 5, 1)

    with patch('wazuh.core.configuration.parse_internal_options', return_value='1'):
        assert configuration.get_internal_options_value('ossec', 'python', 5, 1) == 1


@patch('wazuh.core.configuration.common.wazuh_gid')
@patch('wazuh.core.configuration.common.wazuh_uid')
@patch('builtins.open')
def test_upload_group_configuration(mock_open, mock_wazuh_uid, mock_wazuh_gid):
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.upload_group_configuration('noexists', 'noexists')

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.tempfile.mkstemp', return_value=['mock_handle', 'mock_tmp_file']):
            with patch('wazuh.core.configuration.open'):
                with pytest.raises(WazuhInternalError, match=".* 1743 .*"):
                    configuration.upload_group_configuration('default', "<agent_config>new_config</agent_config>")
            with patch('wazuh.core.configuration.open', return_value=Exception):
                with pytest.raises(WazuhError, match=".* 1113 .*"):
                    configuration.upload_group_configuration('default', "<agent_config>new_config</agent_config>")
            with patch('builtins.open'):
                with patch('wazuh.core.configuration.subprocess.check_output', return_value=True):
                    with patch('wazuh.core.utils.chown', side_effect=None):
                        with patch('wazuh.core.utils.chmod', side_effect=None):
                            with patch('wazuh.core.configuration.safe_move'):
                                assert isinstance(configuration.upload_group_configuration('default',
                                                                                           "<agent_config>new_config"
                                                                                           "</agent_config>"),
                                                  str)
                            with patch('wazuh.core.configuration.safe_move', side_effect=Exception):
                                with pytest.raises(WazuhInternalError, match=".* 1016 .*"):
                                    configuration.upload_group_configuration('default',
                                                                             "<agent_config>new_config</agent_config>")
            with patch('wazuh.core.configuration.subprocess.check_output',
                       side_effect=subprocess.CalledProcessError(cmd='ls', returncode=1, output=b'ERROR')):
                with patch('wazuh.core.configuration.re.findall', return_value=None):
                    with pytest.raises(WazuhError, match=".* 1115 .*"):
                        configuration.upload_group_configuration('default', "<agent_config>new_config</agent_config>")
                with patch('wazuh.core.configuration.re.findall', return_value='1114'):
                    with patch('os.path.exists', return_value=True):
                        with patch('wazuh.core.configuration.remove') as mock_remove:
                            with pytest.raises(WazuhError, match=".* 1114 .*"):
                                configuration.upload_group_configuration('default',
                                                                         "<agent_config>new_config</agent_config>")
                                mock_remove.assert_called_once()


@patch('wazuh.core.configuration.common.wazuh_gid')
@patch('wazuh.core.configuration.common.wazuh_uid')
@patch('builtins.open')
@patch('wazuh.core.configuration.safe_move')
def test_upload_group_file(mock_safe_move, mock_open, mock_wazuh_uid, mock_wazuh_gid):
    with pytest.raises(WazuhError, match=".* 1710 .*"):
        configuration.upload_group_file('noexists', 'given', 'noexists')

    with patch('wazuh.core.configuration.os_path.exists', return_value=True):
        with pytest.raises(WazuhError, match=".* 1112 .*"):
            configuration.upload_group_file('default', [], 'agent.conf')

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with patch('wazuh.core.configuration.tempfile.mkstemp', return_value=['mock_handle', 'mock_tmp_file']):
            with patch('wazuh.core.configuration.subprocess.check_output', return_value=True):
                with patch('wazuh.core.utils.chown', side_effect=None):
                    with patch('wazuh.core.utils.chmod', side_effect=None):
                        assert configuration.upload_group_file('default',
                                                               "<agent_config>new_config</agent_config>",
                                                               'agent.conf') == \
                               'Agent configuration was successfully updated'

    with patch('wazuh.core.common.SHARED_PATH', new=os.path.join(parent_directory, tmp_path, 'configuration')):
        with pytest.raises(WazuhError, match=".* 1111 .*"):
            configuration.upload_group_file('default', [], 'a.conf')


@pytest.mark.parametrize("agent_id, component, socket, socket_dir, rec_msg", [
    ('000', 'auth', 'auth', 'sockets', 'ok {"auth": {"use_password": "yes"}}'),
    ('000', 'auth', 'auth', 'sockets', 'ok {"auth": {"use_password": "no"}}'),
    ('000', 'auth', 'auth', 'sockets', 'ok {"auth": {}}'),
    ('000', 'agent', 'analysis', 'sockets', {"error": 0, "data": {"enabled": "yes"}}),
    ('000', 'analysis', 'analysis', 'sockets', {"error": 0, "data": {"enabled": "yes"}}),
    ('000', 'com', 'com', 'sockets', 'ok {"com": {"enabled": "yes"}}'),
    ('000', 'csyslog', 'csyslog', 'sockets', 'ok {"csyslog": {"enabled": "yes"}}'),
    ('000', 'integrator', 'integrator', 'sockets', 'ok {"integrator": {"enabled": "yes"}}'),
    ('000', 'logcollector', 'logcollector', 'sockets', 'ok {"logcollector": {"enabled": "yes"}}'),
    ('000', 'mail', 'mail', 'sockets', 'ok {"mail": {"enabled": "yes"}}'),
    ('000', 'monitor', 'monitor', 'sockets', 'ok {"monitor": {"enabled": "yes"}}'),
    ('000', 'request', 'remote', 'sockets', {"error": 0, "data": {"enabled": "yes"}}),
    ('000', 'syscheck', 'syscheck', 'sockets', 'ok {"syscheck": {"enabled": "yes"}}'),
    ('000', 'wazuh-db', 'wdb', 'db', {"error": 0, "data": {"enabled": "yes"}}),
    ('000', 'wmodules', 'wmodules', 'sockets', 'ok {"wmodules": {"enabled": "yes"}}'),
    ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {"use_password": "yes"}}'),
    ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {"use_password": "no"}}'),
    ('001', 'auth', 'remote', 'sockets', 'ok {"auth": {}}'),
    ('001', 'agent', 'remote', 'sockets', 'ok {"agent": {"enabled": "yes"}}'),
    ('001', 'analysis', 'remote', 'sockets', 'ok {"analysis": {"enabled": "yes"}}'),
    ('001', 'com', 'remote', 'sockets', 'ok {"com": {"enabled": "yes"}}'),
    ('001', 'csyslog', 'remote', 'sockets', 'ok {"csyslog": {"enabled": "yes"}}'),
    ('001', 'integrator', 'remote', 'sockets', 'ok {"integrator": {"enabled": "yes"}}'),
    ('001', 'logcollector', 'remote', 'sockets', 'ok {"logcollector": {"enabled": "yes"}}'),
    ('001', 'mail', 'remote', 'sockets', 'ok {"mail": {"enabled": "yes"}}'),
    ('001', 'monitor', 'remote', 'sockets', 'ok {"monitor": {"enabled": "yes"}}'),
    ('001', 'request', 'remote', 'sockets', 'ok {"request": {"enabled": "yes"}}'),
    ('001', 'syscheck', 'remote', 'sockets', 'ok {"syscheck": {"enabled": "yes"}}'),
    ('001', 'wmodules', 'remote', 'sockets', 'ok {"wmodules": {"enabled": "yes"}}')
])
@patch('builtins.open', mock_open(read_data='test_password'))
@patch('wazuh.core.wazuh_socket.create_wazuh_socket_message')
@patch('os.path.exists')
@patch('wazuh.core.common.WAZUH_PATH', new='/var/ossec')
def test_get_active_configuration(mock_exists, mock_create_wazuh_socket_message, agent_id, component, socket,
                                  socket_dir, rec_msg):
    """This test checks the proper working of get_active_configuration function."""
    sockets_json_protocol = {'remote', 'analysis', 'wdb'}
    config = MagicMock()

    socket_class = "WazuhSocket" if socket not in sockets_json_protocol or agent_id != '000' else "WazuhSocketJSON"
    with patch(f'wazuh.core.wazuh_socket.{socket_class}.close') as mock_close:
        with patch(f'wazuh.core.wazuh_socket.{socket_class}.send') as mock_send:
            with patch(f'wazuh.core.wazuh_socket.{socket_class}.__init__', return_value=None) as mock__init__:
                with patch(f'wazuh.core.wazuh_socket.{socket_class}.receive',
                           return_value=rec_msg.encode() if socket_class == "WazuhSocket" else rec_msg) as mock_receive:
                    result = configuration.get_active_configuration(agent_id, component, config)

                    mock__init__.assert_called_with(
                        f"/var/ossec/queue/{socket_dir}/{socket}" if agent_id == '000' else REMOTED_SOCKET)

                    if socket_class == "WazuhSocket":
                        mock_send.assert_called_with(f"getconfig {config}".encode() if agent_id == '000' else \
                                                         f"{agent_id} {component} getconfig {config}".encode())
                    else:  # socket_class == "WazuhSocketJSON"
                        mock_create_wazuh_socket_message.assert_called_with(origin={'module': ANY},
                                                                            command="getconfig",
                                                                            parameters={'section': config})
                        mock_send.assert_called_with(mock_create_wazuh_socket_message.return_value)

                    mock_receive.assert_called_once()
                    mock_close.assert_called_once()

                    if result.get('auth', {}).get('use_password') == "yes":
                        assert result.get('authd.pass') == 'test_password'
                    else:
                        assert 'authd.pass' not in result


@pytest.mark.parametrize('agent_id, component, config, socket_exist, socket_class, expected_error, expected_id', [
    # Checks for 000 or any other agent
    ('000', 'test_component', None, ANY, 'WazuhSocket', WazuhError, 1307),  # No configuration
    ('000', None, 'test_config', ANY, 'WazuhSocket', WazuhError, 1307),  # No component
    ('000', 'test_component', 'test_config', ANY, 'WazuhSocket', WazuhError, 1101),  # Component not in components
    ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhError, 1116),  # Cannot send request
    ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhError, 1117),  # No such file or directory

    # Checks for 000 - Simple messages
    ('000', 'syscheck', 'syscheck', False, 'WazuhSocket', WazuhError, 1121),  # Socket does not exist
    ('000', 'syscheck', 'syscheck', True, 'WazuhSocket', WazuhInternalError, 1121),  # Error connecting with socket
    ('000', 'syscheck', 'syscheck', True, 'WazuhSocket', WazuhInternalError, 1118),  # Data could not be received

    # Checks for 000 - JSON messages
    ('000', 'request', 'global', False, 'WazuhSocketJSON', WazuhError, 1121),  # Socket does not exist
    ('000', 'request', 'global', True, 'WazuhSocketJSON', WazuhInternalError, 1121),  # Error connecting with socket
    ('000', 'request', 'global', True, 'WazuhSocketJSON', WazuhInternalError, 1118),  # Data could not be received

    # Checks for 001
    ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhInternalError, 1121),  # Error connecting with socket
    ('001', 'syscheck', 'syscheck', ANY, 'WazuhSocket', WazuhInternalError, 1118)  # Data could not be received

])
@patch('os.path.exists')
def test_get_active_configuration_ko(mock_exists, agent_id, component, config, socket_exist, socket_class,
                                     expected_error, expected_id):
    """Test all raised exceptions"""
    mock_exists.return_value = socket_exist
    with patch(f'wazuh.core.wazuh_socket.{socket_class}.__init__',
               return_value=MagicMock() if expected_id == 1121 and socket_exist else None):
        with patch(f'wazuh.core.wazuh_socket.{socket_class}.send'):
            with patch(f'wazuh.core.wazuh_socket.{socket_class}.receive',
                       side_effect=ValueError if expected_id == 1118 else None,
                       return_value=b'test 1' if expected_id == 1116 else b'test No such file or directory'):
                with patch(f'wazuh.core.wazuh_socket.{socket_class}.close'):
                    with pytest.raises(expected_error, match=f'.* {expected_id} .*'):
                        configuration.get_active_configuration(agent_id, component, config)


def test_write_ossec_conf():
    content = "New config"
    with patch('wazuh.core.configuration.open', mock_open()) as mocked_file:
        configuration.write_ossec_conf(new_conf=content)
        mocked_file.assert_called_once_with(OSSEC_CONF, 'w')
        mocked_file().writelines.assert_called_once_with(content)


def test_write_ossec_conf_exceptions():
    with patch('wazuh.core.configuration.open', return_value=Exception):
        with pytest.raises(WazuhError, match=".* 1126 .*"):
            configuration.write_ossec_conf(new_conf="placeholder")


@pytest.mark.parametrize(
    'update_check_config,expected',
    (
        [{configuration.GLOBAL_KEY: {configuration.UPDATE_CHECK_OSSEC_FIELD: 'yes'}}, True],
        [{configuration.GLOBAL_KEY: {configuration.UPDATE_CHECK_OSSEC_FIELD: 'no'}}, False],
        [{configuration.GLOBAL_KEY: {}}, True],
        [{}, True],
        [{'ossec_config': {}}, True]
    )
)
@patch('wazuh.core.configuration.get_ossec_conf')
def test_update_check_is_enabled(get_ossec_conf_mock, update_check_config, expected):
    """
    Test that update_check_is_enabled function returns the expected value,
    based on the value of UPDATE_CHECK_OSSEC_FIELD.
    """
    get_ossec_conf_mock.return_value = update_check_config

    assert configuration.update_check_is_enabled() == expected


@pytest.mark.parametrize("error_id, value", [
    (1101, None),
    (1102, None),
    (1103, None),
    (1106, True)
])
def test_update_check_is_enabled_exceptions(error_id, value):
    """Test update_check_is_enabled exception handling."""
    with patch('wazuh.core.configuration.get_ossec_conf', side_effect=WazuhError(error_id), return_value=value):
        if value is not None:
            assert configuration.update_check_is_enabled() == value
        else:
            with pytest.raises(WazuhError, match=f'.* {error_id} .*'):
                configuration.update_check_is_enabled()


@pytest.mark.parametrize(
    'config, expected',
    (
        [{configuration.GLOBAL_KEY: {configuration.CTI_URL_FIELD: configuration.DEFAULT_CTI_URL}},
         configuration.DEFAULT_CTI_URL],
        [{configuration.GLOBAL_KEY: {configuration.CTI_URL_FIELD: 'https://test-cti.com'}}, 'https://test-cti.com'],
        [{configuration.GLOBAL_KEY: {}}, configuration.DEFAULT_CTI_URL],
        [{}, configuration.DEFAULT_CTI_URL],
        [{'ossec_config': {}}, configuration.DEFAULT_CTI_URL]
    )
)
@patch('wazuh.core.configuration.get_ossec_conf')
def test_get_cti_url(get_ossec_conf_mock, config, expected):
    """Check that get_cti_url function returns the expected value, based on the CTI_URL_FIELD."""
    get_ossec_conf_mock.return_value = config

    assert configuration.get_cti_url() == expected


@pytest.mark.parametrize("error_id, value", [
    (1101, None),
    (1102, None),
    (1103, None),
    (1106, configuration.DEFAULT_CTI_URL)
])
def test_get_cti_url_exceptions(error_id, value):
    """Test get_cti_url exception handling."""
    with patch('wazuh.core.configuration.get_ossec_conf', side_effect=WazuhError(error_id), return_value=value):
        if value is not None:
            assert configuration.get_cti_url() == value
        else:
            with pytest.raises(WazuhError, match=f'.* {error_id} .*'):
                configuration.get_cti_url()
