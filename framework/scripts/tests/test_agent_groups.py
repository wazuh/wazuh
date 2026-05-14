# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sys
from unittest.mock import call, patch, MagicMock

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from scripts import agent_groups
        from wazuh import agent


@patch('scripts.agent_groups.exit')
def test_signal_handler(mock_exit):
    """Check if exit is called in signal_handler function."""
    agent_groups.signal_handler('test', 'test')
    mock_exit.assert_called_once_with(1)


@pytest.mark.asyncio
@patch('builtins.print')
async def test_show_groups(print_mock: MagicMock):
    """Check that the show_groups function displays the groups properly."""
    class AffectedItems:
        def __init__(self, affected_items):
            self.affected_items = affected_items
            self.total_affected_items = len(affected_items)

    with patch('scripts.agent_groups.cluster_utils.forward_function', 
               return_value=AffectedItems([{'name': 'a', 'count': 1}, {'name': 'b', 'count': 2}])) as forward_mock:
        await agent_groups.show_groups()
        forward_mock.assert_has_calls([call(func=agent.get_agent_groups, f_kwargs={}),
                                call(func=agent.get_agents, f_kwargs={'q': 'id!=000;group=null'})])
        print_mock.assert_has_calls([call('Groups (2):'), call('  a (1)'),
                                     call('  b (2)'), call('Unassigned agents: 2.')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_show_group(print_mock: MagicMock):
    """Check that the show_group function shows the groups to which an agent belongs."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            self.total_failed_items = len(failed_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'id': 1, 'name': 'a', 'count': 1}, {'id': 2, 'name': 'b', 'count': 2}],
                             failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        agent_id = '1'
        await agent_groups.show_group(agent_id)
        forward_mock.assert_called_once_with(func=agent.get_agents, f_kwargs={'agent_list': [agent_id]})
        print_mock.assert_has_calls([call("The agent 'a' with ID '1' belongs to groups: Null.")])
        print_mock.reset_mock()

        await agent_groups.show_group('0')
        print_mock.assert_has_calls([call('a')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_show_synced_agent(print_mock):
    """Check that the synchronization status of an agent's groups is returned correctly."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'id': 1, 'name': 'a', 'synced': True},
                                             {'id': 2, 'name': 'b', 'synced': False}],
                             failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        agent_id = 0
        await agent_groups.show_synced_agent(agent_id)
        forward_mock.assert_called_once_with(func=agent.get_agents_sync_group, f_kwargs={'agent_list': [agent_id]})
        print_mock.assert_has_calls([call("Agent '0' is synchronized. ")])
        print_mock.reset_mock()
        await agent_groups.show_synced_agent(0)
        print_mock.assert_has_calls([call('a')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_show_agents_with_group(print_mock):
    """Check that agents belonging to a certain group are returned."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'name': 'a', 'id': 1, 'synced': True},
                                             {'id': 2, 'name': 'b', 'synced': False}],
                             failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        await agent_groups.show_agents_with_group(group_id='testing')
        forward_mock.assert_called_once_with(func=agent.get_agents_in_group, 
                                             f_kwargs={'group_list': ['testing'], 'select': ['name'],
                                                            'limit': None})
        print_mock.assert_has_calls([call("2 agent(s) in group 'testing':"),
                                     call('  ID: 1  Name: a.'), call('  ID: 2  Name: b.')])
        print_mock.reset_mock()
        await agent_groups.show_agents_with_group(group_id='testing')
        print_mock.assert_has_calls([call("No agents found in group 'testing'.")])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_show_group_files(print_mock):
    """Check that the files of the specified group are returned."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'filename': 'a', 'hash': 'aa'}, {'filename': 'b', 'hash': 'bb'}],
                             failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        await agent_groups.show_group_files(group_id='testing')
        forward_mock.assert_called_once_with(func=agent.get_group_files, f_kwargs={'group_list': ['testing']})
        print_mock.assert_has_calls([call("2 files for 'testing' group:"), call('  a  [aa]'), call('  b  [bb]')])
        print_mock.reset_mock()
        await agent_groups.show_group_files(group_id='testing')
        print_mock.assert_has_calls([call("0 files for 'testing' group:"), call('  a  [aa]'), call('  b  [bb]')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_unset_group(print_mock):
    """Check the unassignment of one or more groups for an agent."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs, is_async):
        return AffectedItems(affected_items=[{'filename': 'a', 'hash': 'aa'}, {'filename': 'b', 'hash': 'bb'}],
                             failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            agent_id = '99'
            group_id = 'testing'
            await agent_groups.unset_group(agent_id=agent_id, group_id=group_id)
            forward_mock.assert_called_once_with(func=agent.remove_agent_from_groups,
                                        f_kwargs={'agent_list': [agent_id], 'group_list': [group_id]}, is_async=True)
            get_stdin_mock.assert_has_calls([call("Do you want to delete the group 'testing' of agent '99'? [y/N]: ")])
            print_mock.assert_has_calls([call("Agent '99' removed from testing.")])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            await agent_groups.unset_group(agent_id='999')
            get_stdin_mock.assert_has_calls([call("Do you want to delete all groups of agent '999'? [y/N]: ")])
            print_mock.assert_has_calls([call("a")])
            print_mock.reset_mock()

            await agent_groups.unset_group(agent_id='999', quiet=True)
            print_mock.assert_has_calls([call("a")])
            print_mock.reset_mock()


@pytest.mark.asyncio
@patch('builtins.print')
async def test_remove_group(print_mock):
    """Check that the specified group is removed."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'testing': ['a', 'b']}], failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            await agent_groups.remove_group(group_id='testing')
            forward_mock.assert_called_once_with(func=agent.delete_groups, f_kwargs={'group_list': ['testing']})
            get_stdin_mock.assert_has_calls([call("Do you want to remove the 'testing' group? [y/N]: ")])
            print_mock.assert_has_calls([call('Group testing removed.')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            await agent_groups.remove_group(group_id='testing', quiet=True)
            print_mock.assert_has_calls([call('a')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            await agent_groups.remove_group(group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_set_group(print_mock):
    """Check that it adds the specified group to the agent information."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            AffectedItems.called = True

    async def forward_function(func, f_kwargs, is_async):
        return AffectedItems(affected_items=[{'testing': ['agent0', 'agent1']}], failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            await agent_groups.set_group(agent_id=1, group_id='testing')
            forward_mock.assert_called_once_with(func=agent.assign_agents_to_group,
                                   f_kwargs={'group_list': ['testing'], 'agent_list': ['001'], 'replace': False},
                                   is_async=True)
            get_stdin_mock.assert_has_calls(
                [call("Do you want to add the group 'testing' to the agent '001'? [y/N]: ")])
            print_mock.assert_has_calls([call("Group 'testing' added to agent '001'.")])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

            await agent_groups.set_group(agent_id=2, group_id='testing', quiet=True)
            print_mock.assert_has_calls([call('a')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            await agent_groups.set_group(agent_id=3, group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@pytest.mark.asyncio
@patch('builtins.print')
async def test_create_group(print_mock):
    """Check the successful group creation."""
    class AffectedItems:
        called = False

        def __init__(self, affected_items, failed_items):
            self.affected_items = affected_items
            self.failed_items = failed_items
            self.total_affected_items = 0 if AffectedItems.called else len(affected_items)
            self.dikt = {'message': 'dikt_testing'}
            AffectedItems.called = True

    async def forward_function(func, f_kwargs):
        return AffectedItems(affected_items=[{'testing': ['agent0', 'agent1']}], failed_items={'a': 'b'})

    with patch('scripts.agent_groups.cluster_utils.forward_function', side_effect=forward_function) as forward_mock:
        with patch('scripts.agent_groups.get_stdin', return_value='y') as get_stdin_mock:
            group_id = 'testing'
            await agent_groups.create_group(group_id=group_id)
            forward_mock.assert_called_once_with(func=agent.create_group, f_kwargs={'group_id': group_id})
            get_stdin_mock.assert_has_calls([call(f"Do you want to create the group '{group_id}'? [y/N]: ")])
            print_mock.assert_has_calls([call('dikt_testing')])
            print_mock.reset_mock()
            get_stdin_mock.reset_mock()

        with patch('scripts.agent_groups.get_stdin', return_value='n'):
            await agent_groups.create_group(group_id='testing')
            print_mock.assert_has_calls([call('Cancelled.')])


@patch('builtins.print')
@patch('scripts.agent_groups.basename', return_value="mock basename")
def test_usage(basename_mock, print_mock):
    """Test if the usage is being correctly printed."""
    msg = """
    {0} [ -l [ -g group_id ] | -c -g group_id | -a (-i agent_id -g group_id | -g group_id) [-q] [-f] | -s -i agent_id | -S -i agent_id | -r (-g group_id | -i agent_id) [-q] ]

    Usage:
    \t-l                                    # List all groups
    \t-l -g group_id                        # List agents in group
    \t-c -g group_id                        # List configuration files in group
    \t
    \t-a -i agent_id -g group_id [-q] [-f]  # Add group to agent
    \t-r -i agent_id [-q] [-g group_id]     # Remove all groups from agent [or single group]
    \t-s -i agent_id                        # Show group of agent
    \t-S -i agent_id                        # Show sync status of agent
    \t
    \t-a -g group_id [-q]                   # Create group
    \t-r -g group_id [-q]                   # Remove group


    Params:
    \t-l, --list
    \t-c, --list-files
    \t-a, --add-group
    \t-f, --force-single-group
    \t-s, --show-group
    \t-S, --show-sync
    \t-r, --remove-group

    \t-i, --agent-id
    \t-g, --group

    \t-q, --quiet (no confirmation)
    \t-d, --debug
    """.format(basename_mock.return_value)

    agent_groups.usage()
    print_mock.assert_called_once_with(msg)

    basename_mock.assert_called_once_with(sys.argv[0])


@patch('scripts.agent_groups.exit')
@patch('builtins.print')
def test_invalid_option(print_mock, exit_mock):
    """Check the proper functioning of the function in charge of
    notifying the user in case of error with the CLI options."""
    agent_groups.invalid_option()
    print_mock.assert_has_calls([call('Invalid options.'), call("Try '--help' for more information.\n")])
    exit_mock.assert_called_once_with(1)
    print_mock.reset_mock()
    exit_mock.reset_mock()

    agent_groups.invalid_option(msg='test')
    print_mock.assert_has_calls([call('Invalid options: test'), call("Try '--help' for more information.\n")])
    exit_mock.assert_called_once_with(1)


@patch('scripts.agent_groups.invalid_option')
@patch('scripts.agent_groups.argparse.ArgumentParser')
def test_get_script_arguments(argument_parser_mock, invalid_option_mock):
    """Test the main function."""
    with patch('builtins.sum', return_value=1):
        agent_groups.get_script_arguments()
        argument_parser_mock.assert_called_once_with()
        argument_parser_mock.return_value.add_argument.assert_has_calls(
            [call('-l', '--list', action='store_true', dest='list', help='List the groups.'),
             call('-c', '--list-files', action='store_true', dest='list_files',
                  help="List the group's configuration files."),
             call('-a', '--add', action='store_true', dest='add', help='Add new group or new agent to group.'),
             call('-f', '--force', action='store_true', dest='force', help='Force single group.'),
             call('-s', '--show-group', action='store_true', dest='show_group', help='Show group of agent.'),
             call('-S', '--show-sync', action='store_true', dest='show_sync', help='Show sync status of agent.'),
             call('-r', '--remove', action='store_true', dest='remove', help='Remove group or agent from group.'),
             call('-i', '--agent-id', type=str, dest='agent_id', help='Specify the agent ID.'),
             call('-g', '--group-id', type=str, dest='group_id', help='Specify group ID.'),
             call('-q', '--quiet', action='store_true', dest='quiet', help='Silent mode (no confirmation).'),
             call('-d', '--debug', action='store_true', dest='debug', help='Debug mode.'),
             call('-u', '--usage', action='store_true', dest='usage', help='Show usage.')])

    with patch('builtins.sum', return_value=2):
        agent_groups.get_script_arguments()
        invalid_option_mock.assert_called_once_with("Bad argument combination.")


@pytest.mark.asyncio
@patch('scripts.agent_groups.exit', side_effect=exit)
@patch('scripts.agent_groups.remove_group')
@patch('scripts.agent_groups.unset_group')
@patch('scripts.agent_groups.show_synced_agent')
@patch('scripts.agent_groups.show_group')
@patch('scripts.agent_groups.invalid_option')
@patch('scripts.agent_groups.create_group')
@patch('scripts.agent_groups.set_group')
@patch('scripts.agent_groups.show_group_files')
@patch('scripts.agent_groups.show_agents_with_group')
@patch('scripts.agent_groups.show_groups')
@patch('scripts.agent_groups.usage')
@patch('builtins.print')
async def test_main(print_mock, usage_mock, show_groups_mock, show_agents_with_group_mock, show_group_files_mock,
                    set_group_mock, create_group_mock, invalid_option_mock, show_group_mock, show_synced_agent_mock,
                    unset_group_mock, remove_group_mock, exit_mock):
    """Test the main function."""
    class Arguments:
        def __init__(self, list=None, list_files=None, add=None, show_group=None, show_sync=None, force=False,
                     remove=None, agent_id=None, group_id=None, quiet=False, debug=False, usage=None):
            self.list = list
            self.list_files = list_files
            self.add = add
            self.force = force
            self.show_group = show_group
            self.show_sync = show_sync
            self.remove = remove
            self.agent_id = agent_id
            self.group_id = group_id
            self.quiet = quiet
            self.debug = debug
            self.usage = usage
            self.invalid = None

    agent_groups.args = Arguments()

    # No arguments
    await agent_groups.main()
    show_groups_mock.assert_called()
    show_groups_mock.reset_mock()

    with patch('scripts.agent_groups.usage') as usage_mock:
        agent_groups.args.usage = True
        await agent_groups.main()
        usage_mock.assert_called_once()

    # -l
    agent_groups.args.list = True
    await agent_groups.main()
    show_groups_mock.assert_called_once()

    # -l -g
    agent_groups.args.group_id = 'group'
    await agent_groups.main()
    show_agents_with_group_mock.assert_called_once_with(agent_groups.args.group_id)

    # -c --list-files
    agent_groups.args = Arguments(list_files=True)
    await agent_groups.main()
    invalid_option_mock.assert_called_once_with('Missing group.')
    invalid_option_mock.reset_mock()

    # -c -g
    agent_groups.args = Arguments(list_files=True, group_id='group')
    await agent_groups.main()
    show_group_files_mock.assert_called_once_with('group')

    # -a -i agent_id -g group_id
    agent_groups.args = Arguments(add=True, agent_id='001', group_id='group1')
    await agent_groups.main()
    set_group_mock.assert_called_once_with('001', 'group1', False, False)
    set_group_mock.reset_mock()

    # -a -i agent_id -g group_id -f
    agent_groups.args = Arguments(add=True, agent_id='001', group_id='group1', force=True)
    await agent_groups.main()
    set_group_mock.assert_called_once_with('001', 'group1', False, True)
    set_group_mock.reset_mock()

    # -a -i agent_id -g group_id -f -q
    agent_groups.args = Arguments(add=True, agent_id='001', group_id='group1', force=True, quiet=True)
    await agent_groups.main()
    set_group_mock.assert_called_once_with('001', 'group1', True, True)

    # -a -g group_id
    agent_groups.args = Arguments(add=True, group_id='group1')
    await agent_groups.main()
    create_group_mock.assert_called_once_with('group1', False)
    create_group_mock.reset_mock()

    # -a -g group_id -q
    agent_groups.args = Arguments(add=True, group_id='group1', quiet=True)
    await agent_groups.main()
    create_group_mock.assert_called_once_with('group1', True)

    # -a
    agent_groups.args = Arguments(add=True)
    await agent_groups.main()
    invalid_option_mock.assert_called_once_with("Missing agent ID or group.")
    invalid_option_mock.reset_mock()

    # -s
    agent_groups.args = Arguments(show_group=True)
    await agent_groups.main()
    invalid_option_mock.assert_called_once_with("Missing agent ID.")
    invalid_option_mock.reset_mock()

    # -s -i agent_id
    agent_groups.args = Arguments(show_group=True, agent_id='002')
    await agent_groups.main()
    show_group_mock.assert_called_once_with("002")

    # -S
    agent_groups.args = Arguments(show_sync=True)
    await agent_groups.main()
    invalid_option_mock.assert_called_once_with("Missing agent ID.")
    invalid_option_mock.reset_mock()

    # -S -i agent_id
    agent_groups.args = Arguments(show_sync=True, agent_id='003')
    await agent_groups.main()
    show_synced_agent_mock.assert_called_once_with("003")

    # -r -i agent_id
    agent_groups.args = Arguments(remove=True, agent_id='004')
    await agent_groups.main()
    unset_group_mock.assert_called_once_with('004', None, False)
    unset_group_mock.reset_mock()

    # -r -i agent_id -g group_id
    agent_groups.args = Arguments(remove=True, agent_id='004', group_id='group1')
    await agent_groups.main()
    unset_group_mock.assert_called_once_with('004', 'group1', False)
    unset_group_mock.reset_mock()

    # -r -i agent_id -q
    agent_groups.args = Arguments(remove=True, agent_id='004', quiet=True)
    await agent_groups.main()
    unset_group_mock.assert_called_once_with('004', None, True)

    # -r -g group_id
    agent_groups.args = Arguments(remove=True, group_id='group2')
    await agent_groups.main()
    remove_group_mock.assert_called_once_with('group2', False)
    remove_group_mock.reset_mock()

    # -r -g group_id -q
    agent_groups.args = Arguments(remove=True, group_id='group2', quiet=True)
    await agent_groups.main()
    remove_group_mock.assert_called_once_with('group2', True)

    # -r
    agent_groups.args = Arguments(remove=True)
    await agent_groups.main()
    invalid_option_mock.assert_called_once_with("Missing agent ID or group.")
    invalid_option_mock.reset_mock()
