#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import MagicMock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.agent import add_agent, assign_agents_to_group, create_group, delete_agents, delete_groups, \
            get_agent_conf, get_agent_config, get_agent_groups, get_agents, get_agents_in_group, \
            get_agents_keys, get_agents_summary_os, get_agents_summary_status, get_agents_sync_group, \
            get_distinct_agents, get_file_conf, get_full_overview, get_group_files, get_outdated_agents, \
            get_upgrade_result, remove_agent_from_group, remove_agent_from_groups, remove_agents_from_group, \
            restart_agents, upgrade_agents, upload_group_file, restart_agents_by_node
        from wazuh.core.agent import Agent
        from wazuh import WazuhError, WazuhException, WazuhInternalError
        from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
        from wazuh.core.tests.test_agent import InitAgent
        from api.util import remove_nones_to_dict
        from wazuh.core.exception import WazuhResourceNotFound

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_path = os.path.join(test_data_path, 'agent')
test_shared_path = os.path.join(test_agent_path, 'shared')
test_multigroup_path = os.path.join(test_agent_path, 'multigroups')
test_global_bd_path = os.path.join(test_data_path, 'global.db')

test_data = InitAgent(data_path=test_data_path)
full_agent_list = ['000', '001', '002', '003', '004', '005', '006', '007', '008']
short_agent_list = ['000', '001', '002', '003', '004', '005']


def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = test_data.cur.execute(query).fetchall()
    return list(map(remove_nones_to_dict, map(dict, result)))


@pytest.mark.parametrize('fields, expected_items', [
    (['os.platform'], [{'os': {'platform': 'ubuntu'}, 'count': 4}, {'os': {'platform': 'unknown'}, 'count': 2}]),
    (['version'], [{'version': 'Wazuh v3.9.0', 'count': 1}, {'version': 'Wazuh v3.8.2', 'count': 2},
                   {'version': 'Wazuh v3.6.2', 'count': 1}, {'version': 'unknown', 'count': 2}]),
    (['os.platform', 'os.major'], [{'os': {'major': '18', 'platform': 'ubuntu'}, 'count': 3},
                                   {'os': {'major': '16', 'platform': 'ubuntu'}, 'count': 1},
                                   {'os': {'major': 'unknown', 'platform': 'unknown'}, 'count': 2}]),
    (['node_name'], [{'node_name': 'unknown', 'count': 2}, {'node_name': 'node01', 'count': 4}]),
    (['os.name', 'os.platform', 'os.version'], [
        {'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '18.04.1 LTS'}, 'count': 3},
        {'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '16.04.1 LTS'}, 'count': 1},
        {'os': {'name': 'unknown', 'platform': 'unknown', 'version': 'unknown'}, 'count': 2}]),
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_distinct_agents(socket_mock, send_mock, fields, expected_items):
    """Test `get_distinct_agents` function from agent module.

    Parameters
    ----------
    fields : list
        List of fields to check their values.
    expected_items : list
        List of expected values for the provided fields.
    """
    distinct = get_distinct_agents(short_agent_list, fields=fields, sort={'fields': fields, 'order': 'desc'})
    assert isinstance(distinct, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert distinct.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_summary_status(socket_mock, send_mock):
    """Test `get_agents_summary` function from agent module."""
    summary = get_agents_summary_status(short_agent_list)
    assert isinstance(summary, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    # Asserts are based on what it should get from the fake database
    expected_results = {'active': 3, 'disconnected': 1, 'never_connected': 1, 'pending': 1, 'total': 6}
    summary_data = summary['data']
    assert set(summary_data.keys()) == set(expected_results.keys())
    assert summary_data['active'] == expected_results['active']
    assert summary_data['disconnected'] == expected_results['disconnected']
    assert summary_data['never_connected'] == expected_results['never_connected']
    assert summary_data['pending'] == expected_results['pending']
    assert summary_data['total'] == expected_results['total']


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_summary_os(connect_mock, send_mock):
    """Tests `get_os_summary function`."""
    summary = get_agents_summary_os(short_agent_list)
    assert isinstance(summary, AffectedItemsWazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert summary.affected_items == ['ubuntu'], f"Expected ['ubuntu'] OS but received '{summary['items']} instead."


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['001', '002'], ['001', '002'], None),
    (['000'], [], 1703),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.core.agent.Agent.restart')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart_agents(socket_mock, send_mock, agents_info_mock, restart_mock, agent_list, expected_items, error_code):
    """Test `restart_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'restart_agents'.
    error_code : int
        The expected error code.
    """
    result = restart_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['000', '001', '002'], ['001', '002'], None),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.core.agent.Agent.restart')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart_agents_by_node(socket_mock, send_mock, agents_info_mock, restart_mock, agent_list, expected_items,
                                      error_code):
    """Test `restart_agents_by_node` function from agent module.

        Parameters
        ----------
        agent_list : List of str
            List of agent ID's.
        expected_items : List of str
            List of expected agent ID's returned by 'restart_agents'.
        error_code : int
            The expected error code.
        """
    result = restart_agents_by_node(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents(socket_mock, send_mock, agent_list, expected_items):
    """Test `get_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'get_agents'.
    """
    result = get_agents(agent_list=agent_list, select=['id'])
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items
    assert len(result.affected_items) == len(expected_items)
    assert (expected_id == agent_id for expected_id, agent_id in zip(expected_items, result.affected_items))
    if result.failed_items:
        assert (failed_item.message == 'Agent does not exist' for failed_item in result.failed_items.keys())


@pytest.mark.parametrize('group, group_exists, expected_agents', [
    ('default', True, ['001', '002', '005']),
    ('not_exists_group', False, None)
])
@patch('wazuh.agent.get_agents')
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_in_group(socket_mock, send_mock, mock_get_groups, mock_get_agents, group, group_exists,
                                   expected_agents):
    """Test `get_agents_in_group` from agent module.

    Parameters
    ----------
    group : str
        Name of the group to which the agent belongs.
    group_exists : bool
        Value to be returned by the mocked function 'group_exists'.
    expected_agents : List of str
        List of agent ID's that belongs to a given group.
    """
    mock_get_groups.return_value = ['default']
    if group_exists:
        # Since the decorator is mocked, pass `group_list` using `call_args` from mock
        get_agents_in_group(group_list=[group], select=['id'])
        kwargs = mock_get_agents.call_args[1]
        agents = get_agents(agent_list=short_agent_list, **kwargs)
        assert agents.affected_items
        assert len(agents.affected_items) == len(expected_agents)
        for expected_agent, affected_agent in zip(expected_agents, agents.affected_items):
            assert expected_agent == next(iter(affected_agent.values()))
    else:
        # If not `group_exists`, expect an error
        with pytest.raises(WazuhResourceNotFound, match='.* 1710 .*'):
            get_agents_in_group(group_list=[group])


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_keys(socket_mock, send_mock, agent_list, expected_items):
    """Test `get_agents_keys` from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'get_agents_keys'.
    """
    agent_keys = get_agents_keys(agent_list=agent_list)
    assert agent_keys.affected_items
    assert len(agent_keys.affected_items) == len(expected_items)
    for expected_id, agent in zip(expected_items, agent_keys.affected_items):
        assert expected_id == agent['id']
        assert agent['key']
        if agent_keys.failed_items:
            assert (failed_item.message == 'Agent does not exist' for failed_item in agent_keys.failed_items.keys())


@pytest.mark.parametrize('agent_list, older_than, remove_msg, error_code, expected_items', [
    (['001', '002', '003'], "1s", 'Agent was successfully deleted', None, ['001', '002', '003']),
    (['000'], "1s", None, 1703, []),
    (['001', '500'], "1s", 'Agent was successfully deleted', 1701, ['001']),
    (['001', '002'], "1s", WazuhException(1700), 1700, []),
])
@patch('wazuh.agent.Agent.remove')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_delete_agents(socket_mock, send_mock, mock_remove, agent_list, older_than, remove_msg, error_code, expected_items):
    """Test `delete_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    remove_msg : str
        String message to be returned by mocked 'remove' function.
    error_code : int
        The expected error code.
    expected_items : List of str
        List of expected agent ID's returned by
    """
    mock_remove.side_effect = remove_msg
    result = delete_agents(agent_list, older_than=older_than)
    assert result.affected_items == sorted(expected_items), \
        f'"Affected_items" does not match. Should be "{result.affected_items}".'
    if result.failed_items:
        assert next(iter(result.failed_items)).code == error_code
    assert result['older_than'] == older_than


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_delete_agents_different_status(socket_mock, send_mock):
    """Test `delete_agents` function from agent module.

    It will force a failed item due to agent not eligible (different status).
    """
    result = delete_agents(['001', '002'], status='active')
    assert result.affected_items == [], f'"Affected_items" does not match. Should be empty.'
    assert result.failed_items
    for failed_item in result.failed_items:
        assert failed_item.code == 1731
        assert 'Agent is not eligible for removal: The agent has a status different to \'active\'' \
               in failed_item.message


@pytest.mark.parametrize('name, agent_id, key', [
    ('agent-1', '001', 'b3650e11eba2f27er4d160c69de533ee7eed601636a85ba2455d53a90927747f'),
    ('a' * 129, '002', 'f304f582f2417a3fddad69d9ae2b4f3b6e6fda788229668af9a6934d454ef44d')
])
@patch('wazuh.core.agent.fcntl.lockf')
@patch('wazuh.core.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
@patch('wazuh.core.agent.copyfile')
@patch('wazuh.core.agent.common.ossec_uid')
@patch('wazuh.core.agent.common.ossec_gid')
@patch('wazuh.core.agent.safe_move')
@patch('builtins.open')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_add_agent(socket_mock, send_mock, open_mock, safe_move_mock, common_gid_mock, common_uid_mock,
                         copyfile_mock, chmod_mock, chown_mock, fcntl_mock, name, agent_id, key):
    """Test `add_agent` from agent module.

    Parameters
    ----------
    name : str
        Name of the agent.
    expected_id : str
        ID of the agent whose name is the specified one.
    key : str
        The agent key.
    """
    try:
        add_result = add_agent(name=name, agent_id=agent_id, key=key, use_only_authd=False)
        assert add_result.dikt['data']['id'] == agent_id
        assert add_result.dikt['data']['key']
    except WazuhError as e:
        assert e.code == 1738, 'The exception was raised as expected but "error_code" does not match.'


@pytest.mark.parametrize('group_list, expected_result', [
    (['group-1', 'group-2'], ['group-1', 'group-2']),
    (['invalid_group'], [])
])
@patch('wazuh.core.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_groups(socket_mock, send_mock, group_list, expected_result):
    """Test `get_agent_groups` from agent module.

    This will check if the provided groups exists.

    Parameters
    ----------
    group_list : List of str
        List of groups to check if they exists.
    expected_result : List of str
        List of expected groups to be returned by 'get_agent_groups'.
    """
    group_result = get_agent_groups(group_list)
    assert len(group_result.affected_items) == len(expected_result)
    for item, group_name in zip(group_result.affected_items, group_list):
        assert item['name'] == group_name
        assert item['mergedSum']
        assert item['configSum']


@pytest.mark.parametrize('db_global, system_groups, error_code', [
    (test_global_bd_path, 'invalid_group', 1710)
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_groups_exceptions(socket_mock, send_mock, mock_get_groups, db_global, system_groups, error_code):
    """Test `get_agent_groups` function from agent module raises the expected exceptions if an invalid 'global.db' path
    or group is specified.

    """
    mock_get_groups.return_value = {'valid-group'}
    with patch('wazuh.core.common.database_path_global', new=db_global):
        try:
            group_result = get_agent_groups(group_list=[system_groups])
            assert group_result.failed_items
            assert next(iter(group_result.failed_items)).code == error_code
        except WazuhException as e:
            assert e.code == error_code, 'The exception was raised as expected but "error_code" does not match.'


@pytest.mark.parametrize('group_list', [
    ['group-1'],
    ['invalid-group']
])
@patch('wazuh.core.common.database_path_global', new=test_global_bd_path)
@patch('wazuh.core.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.common.shared_path', new=test_shared_path)
def test_agent_get_group_files(group_list):
    """Test `get_group_files` from agent module.

    Parameters
    ----------
    group_list : List of str
        List of groups to get their files.
    """
    result = get_group_files(group_list=group_list)
    # Assert 'items' contains agent.conf, merged.mg and ar.conf and 'hash' is not empty
    if result.total_failed_items != 0:
        assert list(result.failed_items.keys())[0].code == 1710
    else:
        assert result.total_affected_items == 3
        assert set(item['filename'] for item in result.affected_items).difference(
            set(['agent.conf', 'merged.mg', 'ar.conf'])) == set()
        for item in result.affected_items:
            assert item['hash']


@pytest.mark.parametrize('shared_path, group_list, group_exists, side_effect, expected_exception', [
    (test_shared_path, ['none'], False, None, WazuhResourceNotFound(1710)),
    ('invalid-path', ['default'], True, None, WazuhError(1006)),
    (test_shared_path, ['default'], True, WazuhError(1405), WazuhError(1405)),
    (test_shared_path, ['default'], True, WazuhException(1400), WazuhInternalError(1727))
])
@patch('wazuh.agent.process_array')
@patch('wazuh.core.agent.Agent.group_exists')
def test_agent_get_group_files_exceptions(mock_group_exists, mock_process_array, shared_path, group_list, group_exists,
                                          side_effect, expected_exception):
    """Test `get_group_files` function from agent module raises the expected exceptions if an invalid 'global.db' path
    is specified.

    Parameters
    ----------
    group_list : List of str
        List of groups to get their files.
    group_exists : bool
        Value to be returned by the mocked function `group_exists`.
    side_effect : Exception
        Exception type to be raised by the mocked `process_array` function.
    expected_exception : Exception
        Exception expected to be raised by `get_group_files` with the given parameters.
    """
    with patch('wazuh.core.common.shared_path', new=shared_path):
        mock_group_exists.return_value = group_exists
        mock_process_array.side_effect = side_effect
        try:
            result = get_group_files(group_list=group_list)
            assert list(result.failed_items.keys())[0] == expected_exception
        except (WazuhError, WazuhInternalError) as e:
            assert e.code == expected_exception.code, 'The exception raised is not the one expected.'


@pytest.mark.parametrize('group_id', [
    'non-existant-group',
    'invalid-group'
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.core.common.ossec_gid', return_value=getgrnam('root'))
@patch('wazuh.core.common.ossec_uid', return_value=getpwnam('root'))
@patch('wazuh.agent.chown_r')
def test_create_group(chown_mock, uid_mock, gid_mock, group_id):
    """Test `create_group` function from agent module.

    When a group is created a folder with the same name is created in `common.shared_path`.

    Parameters
    ----------
    group_id : str
        Name of the group to be created.
    """
    expected_msg = f"Group '{group_id}' created."
    path_to_group = os.path.join(test_shared_path, group_id)
    try:
        result = create_group(group_id)
        assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
        assert len(result.dikt) == 1, \
            f'Result dikt lenght is "{len(result.dikt)}" instead of "1". Result dikt content is: {result.dikt}'
        assert result.dikt['message'] == expected_msg, \
            f'The "result.dikt[\'message\']" received is not the expected.\n' \
            f'Expected: "{expected_msg}"\n' \
            f'Received: "{result.dikt["message"]}"'
        assert os.path.exists(path_to_group), \
            f'The path "{path_to_group}" does not exists and should be created by "create_group" function.'
    finally:
        # Remove the new folder to avoid affecting other tests
        shutil.rmtree(path_to_group, ignore_errors=True)


@pytest.mark.parametrize('group_id, exception, exception_code', [
    ('default', WazuhError, 1711),
    ('group-1', WazuhError, 1711),
    ('invalid!', WazuhError, 1722),
    ('delete-me', WazuhInternalError, 1005)
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
def test_create_group_exceptions(group_id, exception, exception_code):
    """Test `create_group` function from agent module raises the expected exceptions if an invalid `group_id` is
    specified.

    Parameters
    ----------
    group_id : str
        The invalid group id to use.
    exception : Exception
        The expected exception to be raised by `create_group`.
    exception_code : int
        Expected error code for the Wazuh Exception object raised by `get_group_files` with the given parameters.
    """
    try:
        create_group(group_id)
    except exception as e:
        assert e.code == exception_code
    finally:
        # Remove the new group file to avoid affecting the next tests
        shutil.rmtree(os.path.join(test_shared_path, 'delete-me'), ignore_errors=True)


@pytest.mark.parametrize('group_list', [
    ['random-1'],
    ['random-1', 'random-2'],
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.remove_agents_from_group', return_value=AffectedItemsWazuhResult())
@patch('wazuh.agent.Agent.delete_single_group')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_delete_groups(socket_mock, send_mock, mock_delete, mock_remove_agent, mock_get_groups, group_list):
    """Test `delete_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of groups to be deleted.
    """

    def groups():
        return set(group_list)

    mock_get_groups.side_effect = groups
    result = delete_groups(group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(group_list)) == set()
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_name', ['test_group'])
@patch('wazuh.agent.remove_agents_from_group')
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_delete_groups_permission_exception(socket_mock, send_mock, mock_get_groups, mock_remove_agents,
                                                  group_name):
    """Test delete_group function when trying to delete an existant group but without enough privileges.

    Parameters
    ----------
    group_name : str
        Name of the group to be deleted.
    """

    def remove(agent_list=None, group_list=None):
        result = AffectedItemsWazuhResult()
        result.add_failed_item()
        return result

    mock_remove_agents.side_effect = remove
    mock_get_groups.side_effect = {group_name}
    result = delete_groups([group_name])
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.failed_items, dict)
    # Check failed items
    assert result.total_failed_items == 1
    assert WazuhError(4015) in result.failed_items
    assert result.failed_items.get(WazuhError(4015)) == {group_name}


@pytest.mark.parametrize('group_list, expected_errors', [
    (['none-1'], [WazuhResourceNotFound(1710)]),
    (['default'], [WazuhError(1712)]),
    (['none-1', 'none-2'], [WazuhResourceNotFound(1710)]),
    (['default', 'none-1'], [WazuhError(1712), WazuhResourceNotFound(1710)]),
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.core.common.database_path_global', new=test_global_bd_path)
@patch('wazuh.agent.get_groups')
def test_agent_delete_groups_other_exceptions(mock_get_groups, group_list, expected_errors):
    """Test `delete_groups` function from agent module returns the expected exceptions when using invalid group lists.

    Parameters
    ----------
    group_list : List of str
        List of groups to be deleted.
    expected_errors : list of WazuhError
        List of expected WazuhError to be raised by delete_groups if a group is not valid. An exception will be returned
        for each invalid group.
    """
    mock_get_groups.side_effect = {'default'}
    result = delete_groups(group_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.failed_items, dict)
    # Check failed items
    assert result.total_failed_items == len(group_list)
    assert len(result.failed_items.keys()) == len(expected_errors)
    assert set(result.failed_items.keys()).difference(set(expected_errors)) == set()


@pytest.mark.parametrize('group_list, agent_list, num_failed', [
    (['group-1'], ['001'], 0),
    (['group-1'], ['001', '002', '003'], 0),
    (['group-1'], ['001', '002', '003', '100'], 1),
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.agent.Agent.add_group_to_agent')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_assign_agents_to_group(socket_mock, send_mock, add_group_mock, group_list, agent_list, num_failed):
    """Test `assign_agents_to_group` function from agent module. Does not check its raised exceptions.

    Parameters
    ----------
    group_list : List of str
        List of group to apply to the agents
    agent_list : List of str
        List of agent ID's.
    num_failed : numeric
        Number of expected failed_items
    """
    result = assign_agents_to_group(group_list, agent_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set()
    # Check failed items
    assert result.total_failed_items == num_failed


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['none-1'], ['001'], WazuhResourceNotFound(1710), True),
    (['group-1'], ['100'], WazuhResourceNotFound(1701), False),
    (['default'], ['000'], WazuhError(1703), False)
])
@patch('wazuh.agent.Agent.group_exists')
@patch('wazuh.agent.Agent.add_group_to_agent')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_assign_agents_to_group_exceptions(socket_mock, send_mock, mock_add_group, mock_group_exists, group_list,
                                                 agent_list, expected_error, catch_exception):
    """Test `assign_agents_to_group` function from agent module raises the expected exceptions when using invalid groups.

    Parameters
    ----------
    group_list : List of str
        List of group to apply to the agents
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        Expected exception to be raised by `assign_agents_to_group` function using the specified parameters.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """

    def group_exists(group_id):
        return group_id != 'none-1'

    def add_group_to_agent(group_id, agent_id, force=False, replace=False, replace_list=None):
        return f"Agent {agent_id} assigned to {group_id}"

    mock_group_exists.side_effect = group_exists
    mock_add_group.side_effect = add_group_to_agent
    try:
        result = assign_agents_to_group(group_list, agent_list)
        assert not catch_exception
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict)
        # Check failed items
        assert result.total_failed_items == len(group_list)
        assert result.total_failed_items == len(result.failed_items)
        assert set(result.failed_items.keys()).difference(set([expected_error])) == set()
    except WazuhException as ex:
        assert catch_exception
        assert ex == expected_error


@pytest.mark.parametrize('group_id, agent_id', [
    ('default', '001'),
    ('group-1', '005')
])
@patch('wazuh.core.common.database_path_global', new=test_global_bd_path)
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.get_agents_info')
def test_agent_remove_agent_from_group(mock_get_agents, mock_get_groups, mock_unset, group_id, agent_id):
    """Test `remove_agent_from_group` function from agent module. Does not check its raised exceptions.

    Parameters
    ----------
    group_id : str
        Name of the group from where the agent will be removed.
    agent_id : str
        ID of the agent to be removed from the group.
    """
    expected_msg = f"Agent '{agent_id}' removed from '{group_id}'"
    mock_get_agents.return_value = short_agent_list
    mock_unset.return_value = expected_msg
    mock_get_groups.return_value = {group_id}

    result = remove_agent_from_group(group_list=[group_id], agent_list=[agent_id])
    mock_unset.assert_called_once_with(agent_id=agent_id, group_id=group_id, force=True)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize('group_id, agent_id, expected_error', [
    ('any-group', '100', WazuhResourceNotFound(1701)),
    ('any-group', '000', WazuhError(1703)),
    ('group-1', '005', WazuhResourceNotFound(1710)),
])
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', side_effect={'default'})
def test_agent_remove_agent_from_group_exceptions(group_mock, agents_info_mock, group_id, agent_id, expected_error):
    """Test `remove_agent_from_group` function from agent module raises the expected exceptions if an invalid 'agent_id'
    or 'group_id' are specified.

    Parameters
    ----------
    group_id : str
        The invalid group id to use.
    agent_id : str
        the invalid agent id to use.
    expected_error : WazuhError
        The WazuhError object expected to be raised by remove_agent_from_group with the given parameters.
    """
    try:
        remove_agent_from_group(group_list=[group_id], agent_list=[agent_id])
        pytest.fail('An exception should be raised for the given configuration.')
    except (WazuhError, WazuhResourceNotFound) as error:
        assert error == expected_error


@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['001'])
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
def test_agent_remove_agent_from_groups(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list):
    """Test `remove_agent_from_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    result = remove_agent_from_groups(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(group_list)) == set(), f'received: {result.affected_items}'
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['any-group'], ['100'], WazuhResourceNotFound(1701), True),
    (['any-group'], ['000'], WazuhError(1703), True),
    (['any-group'], ['005'], WazuhResourceNotFound(1710), False),
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
def test_agent_remove_agent_from_groups_exceptions(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list,
                                                   expected_error, catch_exception):
    """Test `remove_agent_from_groups` function from agent module raises the expected errors when using invalid group
    or agent lists.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        The expected error to be raised or returned by the function.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    try:
        result = remove_agent_from_groups(group_list=group_list, agent_list=agent_list)
        assert not catch_exception, \
            f'An "WazuhError" exception was expected but was not raised.'
        # Check Typing
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict), \
            f'"failed_items" should be a dict object but was "{type(result.failed_items)}" instead.'
        # Check Failed Items
        assert result.total_failed_items == len(group_list), \
            f'The number of "failed_items" is "{result.total_failed_items}" but was expected to be ' \
            f'"{len(group_list)}".'
        assert result.total_failed_items == len(result.failed_items), \
            f'"total_failed_items" lenght does not match with "failed_items".'
        assert set(result.failed_items.keys()).difference(set([expected_error])) == set(), \
            f'The "failed_items" received does not match.\n' \
            f' - The "failed_items" received is: "{set(result.failed_items.keys())}"\n' \
            f' - The "failed_items" expected was "{set([expected_error])}"\n' \
            f' - The difference between them is "{set(result.failed_items.keys()).difference(set([expected_error]))}"\n'
    except (WazuhError, WazuhResourceNotFound) as error:
        assert catch_exception, \
            f'No exception should be raised at this point. An AffectedItemsWazuhResult object with at least one ' \
            f'failed item was expected instead.'
        assert error == expected_error


@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['001'])
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
def test_agent_remove_agents_from_group(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list):
    """Test `remove_agents_from_group` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed. The list must contain only one group name.
    agent_list : List of str
        List of agent ID's.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    result = remove_agents_from_group(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set(), f'received: {result.affected_items}'
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['non-group'], ['000'], WazuhResourceNotFound(1710), True),
    (['group-1'], ['000'], WazuhError(1703), False),
    (['group-1'], ['100'], WazuhResourceNotFound(1701), False),
])
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
def test_agent_remove_agents_from_group_exceptions(group_mock, agents_info_mock, group_list, agent_list,
                                                   expected_error, catch_exception):
    """Test `remove_agents_from_group` function from agent module raises the expected exceptions when using invalid
    parameters.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        The expected error to be raised or returned by the function.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """
    try:
        result = remove_agents_from_group(group_list=group_list, agent_list=agent_list)
        # Ensure no exception was expected
        assert not catch_exception
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict)
        # Check failed items
        assert result.total_failed_items == len(group_list)
        assert result.total_failed_items == len(result.failed_items)
        assert set(result.failed_items.keys()).difference(set([expected_error])) == set()
    except (WazuhError, WazuhResourceNotFound) as error:
        assert catch_exception
        assert error == expected_error


@pytest.mark.parametrize('agent_list, outdated_agents', [
    (short_agent_list, ['001', '002', '005'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_outdated_agents(socket_mock, send_mock, agent_list, outdated_agents):
    """Test get_oudated_agents function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's to check
    outdated_agents : List of str
        List of agent ID's we expect to be outdated.
    """
    expected_results = list()
    for agentID in ['001', '002', '005']:
        agent = Agent(agentID)
        agent.load_info_from_db()
        expected_results.append({'version': agent.version, 'id': agentID, 'name': agent.name})
    result = get_outdated_agents(agent_list=short_agent_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list), \
        f'"affected_items" should be a list object but was "{type(result.affected_items)}" instead.'
    # Check affected items
    assert result.total_affected_items == len(expected_results), \
        f'"total_affected_items" ({result.total_affected_items}) does not match with the number of expected ' \
        f'results ({len(expected_results)})'
    assert [item for item in result.affected_items if item not in expected_results] == list(), \
        f'The "affected_items" received does not match.\n' \
        f' - The "affected_items" received is "{result.affected_items}"\n' \
        f' - The "affected_items" expected was "{expected_results}"\n' \
        f' - The difference is "{[item for item in result.affected_items if not item in expected_results]}"\n'
    # Check failed items
    assert result.total_failed_items == 0, \
        f'"failed_items" should be "0" but is "{result.total_failed_items}"'


@pytest.mark.parametrize('agent_list', [['001', '002', '003', '004']])
def test_agent_upgrade_agents(agent_list):
    """Test `upgrade_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's to be updated.
    """
    with patch('wazuh.agent.core_upgrade_agents') as core_upgrade_agents_mock:
        core_upgrade_agents_mock.return_value = {'error': 0,
                                                 'data': [{'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1},
                                                          {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2},
                                                          {'error': 6,
                                                           'message': 'Agent information not found in database',
                                                           'agent': 3},
                                                          {'error': 6,
                                                           'message': 'Agent information not found in database',
                                                           'agent': 4}
                                                          ],
                                                 'message': 'Success'}
        result = upgrade_agents(agent_list=agent_list)

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items[0]['agent'] == agent_list[0]
    assert result.affected_items[1]['agent'] == agent_list[1]
    assert list(result.failed_items.values())[0] == set(agent_list[2:])


@pytest.mark.parametrize('agent_list', [['001', '002', '003']])
def test_agent_get_upgrade_result(agent_list):
    """Test `get_upgrade_result` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's to be upgraded.
    """
    with patch('wazuh.agent.core_upgrade_agents') as core_upgrade_agents_mock:
        core_upgrade_agents_mock.return_value = {'error': 0,
                                                  'data': [
                                                      {'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1,
                                                       'module': 'upgrade_module', 'command': 'upgrade',
                                                       'status': 'upgraded', 'create_time': '2020/09/23 10:39:53',
                                                       'update_time': '2020/09/23 10:54:53'},
                                                      {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2,
                                                       'module': 'upgrade_module', 'command': 'upgrade',
                                                       'status': 'Legacy upgrade: ...',
                                                       'create_time': '2020/09/23 11:24:27',
                                                       'update_time': '2020/09/23 11:24:47'},
                                                      {'error': 7, 'message': 'No task in DB', 'agent': 3}],
                                                 'message': 'Success'}

        result = get_upgrade_result(agent_list=agent_list)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items[0]['agent'] == agent_list[0]
    assert list(result.failed_items.values())[0] == set(agent_list[2:])


@pytest.mark.parametrize('agent_list', [['001', '002', '003', '004']])
def test_agent_upgrade_agents_custom(agent_list):
    """Test `upgrade_agents_custom` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's to be updated.
    """
    with patch('wazuh.agent.core_upgrade_agents') as core_upgrade_agents_mock:
        core_upgrade_agents_mock.return_value = {'error': 0,
                                                 'data': [{'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1},
                                                          {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2},
                                                          {'error': 6,
                                                           'message': 'Agent information not found in database',
                                                           'agent': 3},
                                                          {'error': 6,
                                                           'message': 'Agent information not found in database',
                                                           'agent': 4}
                                                          ],
                                                 'message': 'Success'}
        result = upgrade_agents(agent_list=agent_list, file_path='testing', installer='testing.sh')

    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items[0]['agent'] == agent_list[0]
    assert result.affected_items[1]['agent'] == agent_list[1]
    assert list(result.failed_items.values())[0] == set(agent_list[2:])


@pytest.mark.parametrize('agent_list, component, configuration', [
    (['001'], 'logcollector', 'internal')
])
@patch('wazuh.core.configuration.OssecSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_config(socket_mock, send_mock, ossec_socket_mock, agent_list, component, configuration):
    """Test `get_agent_config` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    component : str
        Name of the component.
    configuration : str
        Name of the configuration file.
    """
    ossec_socket_mock.return_value.receive.return_value = b'ok {"test": "conf"}'

    result = get_agent_config(agent_list=agent_list, component=component, config=configuration)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert result.dikt['data'] == {"test": "conf"}, 'Result message is not as expected.'


@pytest.mark.parametrize('agent_list', [
    ['005']
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_config_exceptions(socket_mock, send_mock, agent_list):
    """Test `get_agent_config` function from agent module raises the expected exceptions when using invalid parameters.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    """
    try:
        get_agent_config(agent_list=agent_list)
        pytest.fail('An exception should be raised.')
    except WazuhError as error:
        assert error == WazuhError(1740)


@pytest.mark.parametrize('agent_list', [
    full_agent_list[1:]
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.core.common.multi_groups_path', new=test_multigroup_path)
@patch('wazuh.agent.get_agents_info', return_value=full_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_sync_group(socket_mock, send_mock, get_agent_mock, agent_list):
    """Test `get_agents_sync_group` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    """
    result = get_agents_sync_group(agent_list=agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    # Check affected items
    assert result.total_affected_items == len(agent_list)
    assert len([item for item in result.affected_items if 'synced' in item]) == len(agent_list)


@pytest.mark.parametrize('agent_list, expected_error', [
    (['000'], WazuhError(1703)),
    (['100'], WazuhResourceNotFound(1701))
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_sync_group_exceptions(socket_mock, send_mock, agent_list, expected_error):
    """Test `get_agents_sync_group` function from agent module returns the expected exceptions when using invalid
    parameters.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        Expected WazuhError to be returned (not raised) by the function.
    """
    result = get_agents_sync_group(agent_list=agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    # Check failed items
    assert result.total_failed_items == len(agent_list)
    assert isinstance(result.failed_items, dict)
    assert result.failed_items == {expected_error: {agent_list[0]}}


@pytest.mark.parametrize('filename, group_list', [
    ('agent.conf', ['default'])
])
@patch('wazuh.core.common.database_path_global', new=test_global_bd_path)
@patch('wazuh.core.common.shared_path', new=test_shared_path)
def test_agent_get_file_conf(filename, group_list):
    """Test `get_file_conf` from agent module.

    Parameters
    ----------
    filename : str
        Name of the agent.
    group_list : List of str
        List of group names.
    """
    result = get_file_conf(filename=filename, group_list=group_list)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'data' in result.dikt
    assert isinstance(result.dikt['data'], dict)
    assert 'total_affected_items' in result.dikt['data']
    assert result.dikt['data']['total_affected_items'] == 1


@pytest.mark.parametrize('group_list', [
    ['default']
])
@patch('wazuh.core.common.database_path_global', new=test_global_bd_path)
@patch('wazuh.core.common.shared_path', new=test_shared_path)
def test_agent_get_agent_conf(group_list):
    """Test `get_agent_agent_conf` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    result = get_agent_conf(group_list=group_list)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'total_affected_items' in result.dikt['data']
    assert result.dikt['data']['total_affected_items'] == 1


@pytest.mark.parametrize('group_list', [
    ['default']
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.core.configuration.upload_group_configuration')
def test_agent_upload_group_file(mock_upload, group_list):
    """Test `upload_group_file` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    expected_msg = 'Agent configuration was successfully updated'
    mock_upload.return_value = expected_msg
    result = upload_group_file(group_list=group_list, file_data="sample")
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'message' in result.dikt
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize('agent_list, group_list, index_error, last_agent', [
    (['001'], ['group-2'], False, '001'),
    (['001', '002'], ['group-2', 'group-1'], False, '002'),
    (['001', '002', '003'], ['group-2', 'group-1'], False, '002'),
    (full_agent_list, ['group-1'], False, '004'),
    (full_agent_list, ['group-1'], True, None)
])
@patch('wazuh.core.common.shared_path', new=test_shared_path)
@patch('wazuh.agent.get_distinct_agents')
@patch('wazuh.agent.get_agent_groups')
@patch('wazuh.agent.get_agents_summary_status')
@patch('wazuh.agent.get_agents')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_full_overview(socket_mock, send_mock, get_mock, summary_mock, group_mock, distinct_mock, agent_list,
                                 group_list, index_error, last_agent):
    """Test `get_full_overview` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    group_list : List of str
        List of group names.
    index_error : bool
        True if an `index_error` exception must be raised, False otherwise.
    last_agent : str
        ID of the last registered agent.
    """
    expected_fields = ['nodes', 'groups', 'agent_os', 'agent_status', 'agent_version', 'last_registered_agent']

    def mocked_get_distinct_agents(fields):
        return get_distinct_agents(agent_list=agent_list, fields=fields)

    def mocked_get_agent_groups():
        return get_agent_groups(group_list=group_list)

    def mocked_get_agents_summary_status():
        return get_agents_summary_status(agent_list=agent_list)

    def mocked_get_agents(limit, sort, q):
        if index_error:
            raise IndexError()
        else:
            return get_agents(agent_list=agent_list, limit=limit, sort=sort, q=q)

    distinct_mock.side_effect = mocked_get_distinct_agents
    group_mock.side_effect = mocked_get_agent_groups
    summary_mock.side_effect = mocked_get_agents_summary_status
    get_mock.side_effect = mocked_get_agents
    result = get_full_overview()
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert set(result.dikt['data'].keys()) == set(expected_fields)
    if index_error:
        assert len(result.dikt['data']['last_registered_agent']) == 0
    else:
        assert result.dikt['data']['last_registered_agent'][0]['id'] == last_agent
