# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os.path import join
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
        call('-f', '--file', type=str,
             help="Custom WPK file. The file must already be placed in '{0}' (remoted "
                  "delivers custom WPKs from that directory by filename). A bare "
                  "filename or a path inside that directory are accepted.".format(
                      join(agent_upgrade.common.WAZUH_PATH, 'var', 'upgrade'))),
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


def test_create_command():
    """Check that expected result is returned in create_command function"""
    upgrade_dir = join(agent_upgrade.common.WAZUH_PATH, 'var', 'upgrade')

    agent_upgrade.args = MagicMock()
    agent_upgrade.args.file = 'test.wpk'
    with patch('scripts.agent_upgrade.isfile', return_value=True):
        result = agent_upgrade.create_command()
    assert result == {'agent_list': ANY, 'installer': ANY, 'file_path': ANY, 'request_time': ANY}
    assert result['file_path'] == join(upgrade_dir, 'test.wpk')

    agent_upgrade.args.file = ''
    agent_upgrade.args.execute = ''
    result = agent_upgrade.create_command()
    assert result == {'agent_list': ANY, 'wpk_repo': ANY, 'version': ANY, 'use_http': ANY, 'force': ANY, 'package_type': ANY, 'request_time': ANY}


def test_resolve_wpk_file():
    """Check that WPK paths are resolved into the upgrade directory."""
    upgrade_dir = join(agent_upgrade.common.WAZUH_PATH, 'var', 'upgrade')

    with patch('scripts.agent_upgrade.isfile', return_value=True):
        # Bare filename and a path already inside the upgrade directory are both accepted
        assert agent_upgrade.resolve_wpk_file('test.wpk') == join(upgrade_dir, 'test.wpk')
        assert agent_upgrade.resolve_wpk_file(join(upgrade_dir, 'test.wpk')) == join(upgrade_dir, 'test.wpk')


@pytest.mark.parametrize('file_arg, isfile_result', [
    ('/tmp/elsewhere/test.wpk', True),  # path outside the upgrade directory
    ('test.wpk', False)  # file not present in the upgrade directory
])
def test_resolve_wpk_file_ko(capfd, file_arg, isfile_result):
    """Check that invalid WPK locations abort before any task is created."""
    with patch('scripts.agent_upgrade.isfile', return_value=isfile_result):
        with pytest.raises(SystemExit) as exc_info:
            agent_upgrade.resolve_wpk_file(file_arg)
    assert exc_info.value.code == 1
    out, err = capfd.readouterr()
    assert 'Error' in out


@pytest.mark.asyncio
@patch('scripts.agent_upgrade.signal')
@patch('scripts.agent_upgrade.exit')
@patch('scripts.agent_upgrade.list_outdated')
async def test_main(mock_list_outdated, mock_exit, mock_signal, capfd):
    """Check if methods inside main function are run with expected parameters"""
    agent_upgrade.arg_parser = MagicMock()
    agent_upgrade.args = MagicMock()
    agent_upgrade.args.list_outdated = ['001']
    agent_upgrade.args.agents = []
    agent_upgrade.args.silent = False
    agent_upgrade.args.file = ''
    agent_upgrade.args.execute = ''
    task_results = MagicMock()
    task_results.failed_items = {'1000': ['001', '002']}
    task_results.total_affected_items = 1

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=task_results):
        await agent_upgrade.main()
        mock_signal.assert_called_once_with(agent_upgrade.SIGINT, agent_upgrade.signal_handler)
        mock_list_outdated.assert_called_once()
        mock_exit.assert_has_calls([call(0), call(0)])
        agent_upgrade.arg_parser.print_help.assert_called_once()
        out, err = capfd.readouterr()
        assert 'Agents that cannot be upgraded:\n\tAgent 001, 002 upgrade failed. Status: 1000\n' in out
        assert 'Upgrade tasks created for 1 agent(s).' in out

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
    agent_upgrade.args.file = ''
    agent_upgrade.args.execute = ''
    exc = WazuhInternalError(1816, 'Agent information not found in database')

    with patch('scripts.agent_upgrade.cluster_utils.forward_function', return_value=exc):
        with pytest.raises(WazuhInternalError, match='.* 1816 .*'):
            await agent_upgrade.main()
        out, err = capfd.readouterr()
        assert out == 'Internal error: Error 1816 - Agent information not found in database\n'
