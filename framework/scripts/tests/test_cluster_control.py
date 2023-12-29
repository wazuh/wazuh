# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import sys
import asyncio
from datetime import timedelta
from unittest.mock import patch, call, MagicMock
from uvloop import EventLoopPolicy, Loop

import pytest

import scripts.cluster_control as cluster_control

@pytest.fixture(scope="session")
def event_loop() -> Loop:
    asyncio.set_event_loop_policy(EventLoopPolicy())
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()

@patch('builtins.map')
@patch('builtins.print')
def test_print_table(print_mock, map_mock):
    """Test if the table is being properly printed."""
    data = ''
    headers = 'headers'
    cluster_control.__print_table(data=data, headers=headers, show_header=False)

    print_mock.assert_called_once_with(data)
    assert map_mock.call_count == 2

    print_mock.reset_mock()
    map_mock.reset_mock()

    cluster_control.__print_table(data=data, headers=headers, show_header=True)

    print_mock.assert_called_once_with(data)
    assert map_mock.call_count == 3


@pytest.mark.asyncio
@patch('builtins.map', return_value="")
@patch('operator.itemgetter', return_value="")
@patch('scripts.cluster_control.__print_table')
@patch('scripts.cluster_control.control.get_agents', return_value={'items': ''})
@patch('scripts.cluster_control.local_client.LocalClient', return_value='LocalClient return value')
async def test_print_agents(local_client_mock, get_agents_mock, print_table_mock, itemgetter_mock, map_mock):
    """Test if the function is properly printing the requested agents' information."""
    filter_status = 'active'
    filter_node = 'wazuh_worker'
    headers = {'id': 'ID', 'name': 'Name', 'ip': 'IP', 'status': 'Status', 'version': 'Version',
               'node_name': 'Node name'}

    await cluster_control.print_agents(filter_status=filter_status, filter_node=filter_node)

    local_client_mock.assert_called_once_with()
    get_agents_mock.assert_called_once_with(local_client_mock.return_value, filter_node=filter_node,
                                            filter_status=filter_status)
    print_table_mock.assert_called_once_with(map_mock.return_value, list(headers.values()), True)
    map_mock.assert_called_once_with(itemgetter_mock.return_value, get_agents_mock.return_value['items'])
    itemgetter_mock.assert_called_once_with(*headers.keys())


@pytest.mark.asyncio
@patch('builtins.map', return_value="")
@patch('scripts.cluster_control.__print_table')
@patch('scripts.cluster_control.control.get_nodes', return_value={'items': ''})
@patch('scripts.cluster_control.local_client.LocalClient', return_value='LocalClient return value')
async def test_print_nodes(local_client_mock, get_agents_mock, print_table_mock, map_mock):
    """Test if the function is properly printing the requested nodes' information."""
    filter_node = 'wazuh_worker'
    headers = ["Name", "Type", "Version", "Address"]

    await cluster_control.print_nodes(filter_node=filter_node)

    local_client_mock.assert_called_once_with()
    get_agents_mock.assert_called_once_with(local_client_mock.return_value, filter_node=filter_node)
    print_table_mock.assert_called_once_with(map_mock.return_value, headers, True)
    map_mock.assert_called_once()


@pytest.mark.asyncio
@patch('builtins.print')
@patch('scripts.cluster_control.get_utc_strptime')
@patch('scripts.cluster_control.local_client.LocalClient', return_value='LocalClient return value')
@patch('scripts.cluster_control.control.get_nodes', return_value={'items': [{'name': 'wazuh_worker'}]})
@patch('scripts.cluster_control.control.get_health',
       return_value={'n_connected_nodes': '1',
                     'nodes': {'wazuh_worker2': {
                         'info': {'ip': '0.0.0.0', 'version': '1.0', 'type': 'worker', 'n_active_agents': '0'},
                         'status': {'last_keep_alive': '11/02/1998',
                                    'last_check_integrity': {'date_start_master': 'n/a',
                                                             'date_end_master': 'n/a'},
                                    'last_sync_integrity': {'date_start_master': '1',
                                                            'date_end_master': '2',
                                                            'total_files': {'shared': 0, 'missing': 0, 'extra': 0,
                                                                            'extra_valid': 0},
                                                            'total_extra_valid': 0},
                                    'sync_integrity_free': 'True',
                                    'last_sync_agentinfo': {'date_start_master': '0', 'date_end_master': '0',
                                                            'n_synced_chunks': 0},
                                    'last_sync_agentgroup': {'date_start': 0, 'date_end': 0,
                                                             'n_synced_chunks': 0},
                                    'last_sync_full_agentgroup': {'date_start': 0, 'date_end': 0,
                                                                  'n_synced_chunks': 0},
                                    'sync_agent_info_free': 'True'}}}})
async def test_print_health(get_health_mock, get_nodes_mock, local_client_mock, get_utc_strptime_mock, print_mock):
    """Test if the current status of the cluster is properly printed."""

    def seconds_mock(time, format=None):
        """Auxiliary mock function."""
        return timedelta(seconds=int(time))

    # Common variables
    config = {'name': 'cluster_name'}
    more = True
    worker_status = get_health_mock.return_value['nodes']['wazuh_worker2']['status']
    worker_info = get_health_mock.return_value['nodes']['wazuh_worker2']['info']
    get_utc_strptime_mock.side_effect = seconds_mock

    # Test cases 1 and 2
    for filter_node in ['wazuh_worker', None]:
        # Reset mocks
        print_mock.reset_mock()
        local_client_mock.reset_mock()
        get_nodes_mock.reset_mock()
        get_health_mock.reset_mock()

        # Call print_health
        await cluster_control.print_health(config=config, more=more, filter_node=filter_node)
        print_mock.assert_has_calls([call(f"Cluster name: {config['name']}\n\n"
                                          f"Connected nodes ({get_health_mock.return_value['n_connected_nodes']}):"),
                                     call(f"\n    wazuh_worker2 ({worker_info['ip']})\n        "
                                          f"Version: {worker_info['version']}\n        "
                                          f"Type: {worker_info['type']}\n       "
                                          f" Active agents: {worker_info['n_active_agents']}\n        "
                                          f"Status:\n           "
                                          f" Last keep Alive:\n                Last received: "
                                          f"{worker_status['last_keep_alive']}.\n            "
                                          f"Integrity check:\n           "
                                          f"     Last integrity check: n/a "
                                          f"({worker_status['last_check_integrity']['date_end_master']} - "
                                          f"{worker_status['last_check_integrity']['date_start_master']})."
                                          f"\n                Permission to check integrity: "
                                          f"{worker_status['sync_integrity_free']}.\n            "
                                          f"Integrity sync:\n                Last integrity synchronization: 1.0s "
                                          f"({worker_status['last_sync_integrity']['date_start_master']} - "
                                          f"{worker_status['last_sync_integrity']['date_end_master']})."
                                          f"\n                Synchronized files: Shared: "
                                          f"{worker_status['last_sync_integrity']['total_files']['shared']} | Missing: "
                                          f"{worker_status['last_sync_integrity']['total_files']['missing']} | Extra: "
                                          f"{worker_status['last_sync_integrity']['total_files']['extra']}."
                                          f"\n            Agents-info:\n                Last synchronization: 0.001s ("
                                          f"{worker_status['last_sync_agentinfo']['date_start_master']} - "
                                          f"{worker_status['last_sync_agentinfo']['date_start_master']}).\n         "
                                          f"       Number of synchronized chunks: "
                                          f"{worker_status['last_sync_agentinfo']['n_synced_chunks']}."
                                          f"\n                Permission to synchronize agent-info: "
                                          f"{worker_status['sync_agent_info_free']}.\n"
                                          "            Agents-groups:\n"
                                          f"                Last synchronization: 0.001s "
                                          f"({worker_status['last_sync_agentgroup']['date_start']} - "
                                          f"{worker_status['last_sync_agentgroup']['date_end']}).\n"
                                          f"                Number of synchronized chunks: "
                                          f"{worker_status['last_sync_agentgroup']['n_synced_chunks']}.\n"
                                          "            Agents-groups full:\n"
                                          f"                Last synchronization: 0.001s "
                                          f"({worker_status['last_sync_full_agentgroup']['date_start']} - "
                                          f"{worker_status['last_sync_full_agentgroup']['date_end']}).\n"
                                          f"                Number of synchronized chunks: "
                                          f"{worker_status['last_sync_full_agentgroup']['n_synced_chunks']}.\n"
                                          )])

        # Common assertions
        local_client_mock.assert_called_once()
        get_utc_strptime_mock.assert_has_calls(
            [call(worker_status['last_sync_integrity']['date_end_master'], '%Y-%m-%dT%H:%M:%S.%fZ'),
             call(worker_status['last_sync_integrity']['date_start_master'], '%Y-%m-%dT%H:%M:%S.%fZ'),
             call(worker_status['last_sync_agentinfo']['date_end_master'], '%Y-%m-%dT%H:%M:%S.%fZ'),
             call(worker_status['last_sync_agentinfo']['date_start_master'], '%Y-%m-%dT%H:%M:%S.%fZ')])

        # filter_node dependant assertions
        filter_node and get_nodes_mock.assert_not_called()
        filter_node or get_nodes_mock.assert_called_once()
        get_health_mock.assert_called_once_with(
            local_client_mock.return_value,
            filter_node=filter_node or [get_nodes_mock.return_value['items'][0]['name']])

    # Test case 3
    more = False
    filter_node = 'wazuh_worker'
    print_mock.reset_mock()
    await cluster_control.print_health(config=config, more=more, filter_node=filter_node)
    print_mock.assert_called_once_with(f"Cluster name: {config['name']}\n\nLast completed synchronization for connected"
                                       f" nodes ({get_health_mock.return_value['n_connected_nodes']}):\n    "
                                       f"wazuh_worker2 "
                                       f"({get_health_mock.return_value['nodes']['wazuh_worker2']['info']['ip']}): "
                                       f"Integrity check: {worker_status['last_check_integrity']['date_end_master']} "
                                       f"| Integrity sync: {worker_status['last_sync_integrity']['date_end_master']} |"
                                       f" Agents-info: {worker_status['last_sync_agentinfo']['date_end_master']} | "
                                       f"Agent-groups: {worker_status['last_sync_agentgroup']['date_end']} | "
                                       f"Agent-groups full: {worker_status['last_sync_full_agentgroup']['date_end']} | "
                                       f"Last keep alive: {worker_status['last_keep_alive']}.\n")


@patch('builtins.print')
@patch('scripts.cluster_control.path.basename', return_value="mock basename")
def test_usage(basename_mock, print_mock):
    """Test if the usage is being correctly printed."""
    cluster_control.usage()

    msg = """
    {0} [-h] [-d] [-fn [FILTER_NODE ...]] [-fs [FILTER_STATUS ...]][-a | -l | -i [HEALTH]]
    Usage:
    \t-l                                    # List all nodes present in a cluster
    \t-l -fn <node_name>                    # List certain nodes that belong to the cluster
    \t-a                                    # List all agents connected to the cluster
    \t-a -fn <node_name>                    # Check which agents are reporting to certain nodes
    \t-a -fs <agent_status>                 # List agents with certain status
    \t-a -fn <node_name> <agent_status>     # List agents reporting to certain node and with certain status
    \t-i                                    # Check cluster health
    \t-i -fn <node_name>                    # Check certain node's health


    Params:
    \t-l, --list
    \t-d, --debug
    \t-h, --help
    \t-fn, --filter-node
    \t-fs, --filter-agent-status
    \t-a, --list-agents
    \t-i, --health

    """.format(basename_mock.return_value)
    print_mock.assert_called_once_with(msg)

    basename_mock.assert_called_once_with(sys.argv[0])


@pytest.mark.asyncio
@patch('scripts.cluster_control.sys.exit')
@patch('scripts.cluster_control.asyncio.run')
@patch('logging.error')
@patch('logging.basicConfig')
@patch('argparse.ArgumentParser')
@patch('wazuh.core.cluster.cluster.check_cluster_config')
@patch('wazuh.core.cluster.utils.read_config', return_value='')
@patch('wazuh.core.cluster.utils.get_cluster_status', return_value={'enabled': 'no', 'running': 'yes'})
async def test_main(get_cluster_status_mock, read_config_mock, check_cluster_config, parser_mock, logging_mock,
              logging_error_mock, asyncio_run_mock: MagicMock, exit_mock, event_loop):
    """Test the main function."""

    class ArgsMock:
        """Auxiliary class."""

        def __init__(self):
            self.filter_status = True
            self.list_agents = False
            self.list_nodes = False
            self.health = False
            self.usage = False
            self.debug = False
            self.filter_node = False

    class ExclusiveMock:
        """Auxiliary class."""

        def __init__(self):
            self.exclusive = []

        def add_argument(self, flag, name, action=None, nargs=None, const=None, type=None, dest=None, help=None):
            self.exclusive.append(
                {'flag': flag, 'name': name, 'action': action, 'nargs': nargs, 'const': const, 'type': type,
                 'dest': dest, 'help': help})

    class ParserMock:
        """Auxiliary class."""

        def __init__(self):
            self.storage = []
            self.exclusive = []
            self.called = False

        def add_argument(self, flag, name, action=None, nargs=None, const=None, type=None, dest=None, help=None):
            self.storage.append(
                {'flag': flag, 'name': name, 'action': action, 'nargs': nargs, 'const': const, 'type': type,
                 'dest': dest, 'help': help})

        def add_mutually_exclusive_group(self):
            return exclusive_mock

        def parse_args(self):
            return args_mock

        def print_help(self):
            self.called = True

    def run_mock(*args, **kwargs):
        asyncio.gather(args[0])

    asyncio_run_mock.side_effect = run_mock
    parser_mock.return_value = ParserMock()
    args_mock = ArgsMock()
    exclusive_mock = ExclusiveMock()

    with patch('scripts.cluster_control.usage', return_value='') as usage_mock:
        # Check if cluster is disabled and first condition
        cluster_control.main()
        logging_error_mock.assert_has_calls([call('Cluster is not running.'), call('Wrong arguments.')])
        usage_mock.assert_called_once_with()
        exit_mock.assert_called_with(1)
        read_config_mock.assert_called_once_with()
        check_cluster_config.assert_called_once_with(config=read_config_mock.return_value)
        logging_mock.assert_called_once_with(level=logging.ERROR, format='%(levelname)s: %(message)s')
        exit_mock.reset_mock()

        # Here we will check if the expected parameters were not modified
        assert parser_mock.return_value.storage == [
            {'flag': '-d', 'name': '--debug', 'action': 'store_true', 'nargs': None, 'const': None, 'type': None,
             'dest': 'debug', 'help': 'Enable debug mode'}, {'flag': '-fn', 'name': '--filter-node', 'action': None,
                                                             'nargs': '*', 'const': None, 'type': str,
                                                             'dest': 'filter_node', 'help': 'Filter by node name'},
            {'flag': '-fs', 'name': '--filter-agent-status', 'action': None, 'nargs': '*', 'const': None, 'type': str,
             'dest': 'filter_status', 'help': 'Filter by agent status'}]

        assert exclusive_mock.exclusive == [{'action': 'store_const', 'const': 'list_agents', 'dest': None,
                                             'flag': '-a', 'help': 'List agents', 'name': '--list-agents',
                                             'nargs': None, 'type': None}, {'action': 'store_const',
                                                                            'const': 'list_nodes',
                                                                            'dest': None, 'flag': '-l',
                                                                            'help': 'List nodes',
                                                                            'name': '--list-nodes', 'nargs': None,
                                                                            'type': None}, {'action': 'store',
                                                                                            'const': 'health',
                                                                                            'dest': None,
                                                                                            'flag': '-i',
                                                                                            'help': 'Show cluster '
                                                                                                    'health',
                                                                                            'name': '--health',
                                                                                            'nargs': '?',
                                                                                            'type': None},
                                            {'action': 'store_true', 'const': None, 'dest': None, 'flag': '-u',
                                             'help': 'Show usage', 'name': '--usage', 'nargs': None, 'type': None}]

        # Test the fifth condition
        get_cluster_status_mock.return_value['enabled'] = 'yes'
        args_mock.filter_status = False
        args_mock.usage = True

        cluster_control.main()
        exit_mock.assert_called_with(0)

        # Test the first exception
        usage_mock.side_effect = KeyboardInterrupt()
        cluster_control.main()

        logging_mock.reset_mock()

        # Test the second exception
        args_mock.debug = True
        usage_mock.side_effect = Exception()
        with pytest.raises(Exception):
            cluster_control.main()
            logging_error_mock.assert_called_with("local variable 'my_function' referenced before assignment")
            logging_mock.assert_called_once_with(level=logging.DEBUG, format='%(levelname)s: %(message)s')

    with patch('scripts.cluster_control.print_agents', return_value='') as print_agents_mock:
        # Test the second condition
        args_mock.usage = False
        args_mock.list_agents = True

        cluster_control.main()
        asyncio_run_mock.assert_called_once()

        asyncio_run_mock.reset_mock()
        print_agents_mock.assert_called_once()

    with patch('scripts.cluster_control.print_nodes', return_value='') as print_nodes_mock:
        # Test the third condition
        args_mock.list_agents = False
        args_mock.list_nodes = True

        cluster_control.main()
        asyncio_run_mock.assert_called_once()

        asyncio_run_mock.reset_mock()
        print_nodes_mock.assert_called_once()

    with patch('scripts.cluster_control.print_health', return_value='') as print_health_mock:
        # Test the fourth condition
        args_mock.list_nodes = False
        args_mock.health = 'MORE'

        cluster_control.main()
        asyncio_run_mock.assert_called_once()

        asyncio_run_mock.reset_mock()
        print_health_mock.assert_called_once()

    # Test the sixth condition
    args_mock.health = False
    args_mock.debug = False

    cluster_control.main()

    exit_mock.assert_called_with(0)
    assert parser_mock.called is True
