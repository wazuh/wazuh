# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import call, ANY, patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        import scripts.agent_upgrade as agent_upgrade
        from wazuh.core.exception import WazuhError, WazuhInternalError
        from wazuh.core.results import AffectedItemsWazuhResult


@patch('scripts.agent_upgrade.exit')
def test_signal_handler(mock_exit):
    """Check if exit is called in signal_handler function."""
    agent_upgrade.signal_handler('test', 'test')
    mock_exit.assert_called_once_with(1)


@patch('scripts.agent_upgrade.argparse.ArgumentParser')
def test_get_script_arguments(mock_ArgumentParser):
    agent_upgrade.get_script_arguments()
    mock_ArgumentParser.assert_called_once_with()
    mock_ArgumentParser.return_value.add_argument.assert_has_calls([
        call('-a', '--agents', nargs='+', help='Agent IDs to upgrade.'),
        call('-r', '--repository', type=str, help='Specify a repository URL. [Default: packages.wazuh.com/4.x/wpk/]'),
        call('-v', '--version', type=str, help='Version to upgrade. [Default: latest Wazuh version]'),
        call('-F', '--force', action='store_true', help='Forces the agents to upgrade, ignoring version validations.'),
        call('-s', '--silent', action='store_true', help='Do not show output.'),
        call('-l', '--list_outdated', action='store_true', help='Generates a list with all outdated agents.'),
        call('-f', '--file', type=str, help='Custom WPK filename.'),
        call('-d', '--debug', action='store_true', help='Debug mode.'),
        call('-x', '--execute', type=str, help='Executable filename in the WPK custom file. [Default: upgrade.sh]'),
        call('--http', action='store_true', help='Uses http protocol instead of https.')
    ])


@pytest.mark.parametrize('api_response, total_affected_items', [
    ({'version': 'Wazuh v4.2.1', 'id': '002', 'name': 'test'}, 1),
    ({}, 0)
])
def test_list_outdated(capfd, api_response, total_affected_items):
    """Check if expected message is printed in list_outdated function.

    Parameters
    ----------
    api_response : dict
        Outdated agents that the API should return.
    total_affected_items : int
        Number of affected items.
    """
    result = AffectedItemsWazuhResult()
    result.affected_items = [api_response]
    result.total_affected_items = total_affected_items

    with patch('wazuh.agent.get_outdated_agents', return_value=result):
        agent_upgrade.list_outdated()
        out, err = capfd.readouterr()
        if total_affected_items:
            assert all(value in out for value in api_response.values())
        else:
            assert out == 'All agents are updated.\n'


@pytest.mark.asyncio
async def test_get_agents_versions():
    class AffectedItems:
        def __init__(self, affected_items):
            self.affected_items = affected_items

    agents_list = ["001", "002"]
    mocked_version = "v4.5.0"
    affected_items = [{"id": agent, "version": mocked_version} for agent in agents_list]

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=AffectedItems(affected_items)) \
            as forward_mock:
        result = await agent_upgrade.get_agents_versions(agents_list)
        assert all(result[agent] == {'prev_version': mocked_version, 'new_version': None} for agent in agents_list)


@pytest.mark.asyncio
async def test_get_agent_version():
    class AffectedItems:
        def __init__(self, affected_items):
            self.affected_items = affected_items

    agent_id = "001"
    mocked_version = "v4.6.0"
    affected_items = [{"id": agent_id, "version": mocked_version}]

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=AffectedItems(affected_items)):
        result = await agent_upgrade.get_agent_version(agent_id)
        assert result == mocked_version


def test_create_command():
    """Check that expected result is returned in create_command function"""
    agent_upgrade.args = MagicMock()
    result = agent_upgrade.create_command()
    assert result == {'agent_list': ANY, 'installer': ANY, 'file_path': ANY}

    agent_upgrade.args.file = ''
    agent_upgrade.args.execute = ''
    result = agent_upgrade.create_command()
    assert result == {'agent_list': ANY, 'wpk_repo': ANY, 'version': ANY, 'use_http': ANY, 'force': ANY, 'package_type': ANY}


@pytest.mark.parametrize('agents_versions, failed_agents, expected_output', [
    ({'001': {'prev_version': '4.2.0', 'new_version': '4.4.0'}}, {'001': 'test_error'},
     '\nUpgraded agents:\n\tAgent 001 upgraded: 4.2.0 -> 4.4.0\n\nFailed upgrades:\n\tAgent 001 status: test_error\n'),
    ({}, {}, ''),
    ({'001': {'prev_version': '4.2.0', 'new_version': '4.4.0'}}, {},
     '\nUpgraded agents:\n\tAgent 001 upgraded: 4.2.0 -> 4.4.0\n'),
    ({}, {'001': 'test_error'}, '\nFailed upgrades:\n\tAgent 001 status: test_error\n')
])
def test_print_result(capfd, agents_versions, failed_agents, expected_output):
    """Check that expected output is printed for each combination of parameters.

    Parameters
    ----------
    agents_versions : dict
        Dictionary with the previous version and the new one.
    failed_agents : dict
        Contain the error's information.
    expected_output : str
        Message that should be printed in the function.
    """
    agent_upgrade.print_result(agents_versions=agents_versions, failed_agents=failed_agents)
    out, err = capfd.readouterr()
    assert out == expected_output


@pytest.mark.asyncio
@pytest.mark.parametrize('silent', [
    True, False
])
@patch('scripts.agent_upgrade.print_result')
@patch('scripts.agent_upgrade.sleep')
async def test_check_status(mock_sleep, mock_print_result, silent):
    """Check if methods inside check_status function are run with expected parameters.

    Parameters
    ----------
    silent : bool
        Do not show output if it is True.
    """

    task_results = MagicMock()
    task_results.affected_items = [{'agent': '001', 'status': 'Updated'},
                                   {'agent': '002', 'status': 'Error', 'error_msg': 'test_error'}]
    agent_upgrade.args = MagicMock()
    agent_upgrade.args.version = '4.2.0'
    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=task_results) as mock_forward_func:
        await agent_upgrade.check_status(affected_agents=['001', '002'],
                                         result_dict={'001': {'new_version': '4.4.0'}, '002': {'new_version': '4.3.0'}},
                                         failed_agents={}, silent=silent)

        mock_forward_func.assert_called_once_with(agent_upgrade.get_upgrade_result, f_kwargs={'agent_list': ANY})
        if not silent:
            mock_print_result.assert_called_once_with(agents_versions={'001': {'new_version': '4.2.0'}},
                                                      failed_agents={'002': 'test_error'})
        else:
            mock_print_result.assert_not_called()

@pytest.mark.asyncio
@patch('scripts.agent_upgrade.signal')
@patch('scripts.agent_upgrade.exit')
@patch('scripts.agent_upgrade.list_outdated')
@patch('scripts.agent_upgrade.get_agents_versions')
@patch('scripts.agent_upgrade.check_status')
async def test_main(mock_check_status, mock_get_agents_versions, mock_list_outdated, mock_exit, mock_signal, capfd):
    """Check if methods inside main function are run with expected parameters"""
    agent_upgrade.arg_parser = MagicMock()
    agent_upgrade.args = MagicMock()
    agent_upgrade.args.list_outdated = ['001']
    agent_upgrade.args.agents = []
    agent_upgrade.args.silent = False
    task_results = MagicMock()
    task_results.failed_items = {'1000': ['001', '002']}
    task_results.affected_items = [{'agent': '003'}]

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=task_results):
        await agent_upgrade.main()
        mock_signal.assert_called_once_with(agent_upgrade.SIGINT, agent_upgrade.signal_handler)
        mock_list_outdated.assert_called_once()
        mock_exit.assert_has_calls([call(0), call(0)])
        agent_upgrade.arg_parser.print_help.assert_called_once()
        mock_get_agents_versions.assert_called_with(agents=['003'])
        mock_check_status.assert_called_with(affected_agents=['003'], result_dict=ANY, failed_agents={}, silent=False)
        out, err = capfd.readouterr()
        assert out == 'Agents that cannot be upgraded:\n\tAgent 001, 002 upgrade failed. Status: 1000\n'

@pytest.mark.asyncio
async def test_main_ko(capfd):
    """Check that expected exceptions are raised in main function."""
    agent_upgrade.args = MagicMock()
    agent_upgrade.args.list_outdated = ['001']

    with patch('scripts.agent_upgrade.list_outdated', side_effect=WazuhError(1000)):
        with pytest.raises(WazuhError, match='.* 1000 .*'):
            await agent_upgrade.main()
        out, err = capfd.readouterr()
        assert out == 'Error 1000: Wazuh Internal Error\n'

    with patch('scripts.agent_upgrade.list_outdated', side_effect=Exception):
        with pytest.raises(Exception):
            await agent_upgrade.main()
        out, err = capfd.readouterr()
        assert out == 'Internal error: \n'

@pytest.mark.asyncio
async def test_main_internal_error_ko(capfd):
    """Check that the main function exits successfully when there's an internal error."""
    agent_upgrade.args = MagicMock()
    agent_upgrade.args.list_outdated = []
    exc = WazuhInternalError(1816, 'Agent information not found in database')

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=exc):
        with pytest.raises(WazuhInternalError, match='.* 1816 .*'):
            await agent_upgrade.main()
        out, err = capfd.readouterr()
        assert out == 'Internal error: Error 1816 - Agent information not found in database\n'
