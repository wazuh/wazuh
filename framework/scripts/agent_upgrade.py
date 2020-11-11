#!/usr/bin/env python

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import concurrent.futures
import logging
from asyncio import run
from os.path import dirname
from signal import signal, SIGINT
from sys import exit, path, argv
from time import sleep

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    import wazuh.agent
    from api.util import raise_if_exc
    from wazuh.agent import upgrade_agents, get_upgrade_result
    from wazuh.core import common
    from wazuh.core.agent import Agent
    from wazuh.core.cluster.dapi.dapi import DistributedAPI
    from wazuh.core.exception import WazuhError
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logger = logging.getLogger('wazuh')


# Functions
def signal_handler(n_signal, frame):
    print("")
    exit(1)


def list_outdated():
    agents = wazuh.agent.get_outdated_agents()
    if agents.total_affected_items == 0:
        print("All agents are updated.")
    else:
        print("%-6s%-35s %-25s" % ("ID", "Name", "Version"))
        for agent in agents.affected_items:
            print("%-6s%-35s %-25s" % (agent['id'], agent['name'], agent['version']))
        print("\nTotal outdated agents: {0}".format(agents.total_affected_items))


def get_agents_versions(agents):
    """Get the current versions of the specified agents

    Parameters
    ----------
    agents : list
        List of agent's IDs

    Returns
    -------
    Dictionary with the current version (prev_version)
    """
    agents_versions = dict()
    for agent_id in agents:
        agent = Agent(agent_id)
        agent.load_info_from_db()
        if agent.version:
            agents_versions[agent_id] = {
                'prev_version': agent.version,
                'new_version': None
            }

    return agents_versions


def create_command():
    """Create a custom command based on the CLI arguments

    Returns
    -------
    Dictionary with upgrade command
    """
    if not args.file and not args.execute:
        f_kwargs = {'agent_list': args.agents, 'wpk_repo': args.repository, 'version': args.version,
                    'use_http': args.http, 'force': args.force}
    else:
        # Upgrade custom
        f_kwargs = {'agent_list': args.agents, 'installer': args.execute, 'file_path': args.file}

    return f_kwargs


def send_command(function, command, local_master=False):
    """Send the command to the specified function.
    If local_master is True, the request type must be local_master (upgrade_result)

    Parameters
    ----------
    function : func
        Upgrade function
    command : dict
        Arguments for the specified function
    local_master : bool
        True for get the upgrade results, False for send upgrade command

    Returns
    -------
    Distributed API request result
    """
    dapi = DistributedAPI(f=function, f_kwargs=command,
                          request_type='distributed_master' if not local_master else 'local_master',
                          is_async=False, wait_for_complete=True, logger=logger)
    pool = concurrent.futures.ThreadPoolExecutor()
    return raise_if_exc(pool.submit(run, dapi.distribute_function()).result())


def print_result(agents_versions, failed_agents):
    """Print the operation's result

    Parameters
    ----------
    agents_versions : dict
        Dictionary with the previous version an the new one
    failed_agents : dict
        Contain the error's information
    """
    len(agents_versions.keys()) > 0 and print('\nUpgraded agents:')
    for agent_id, versions in agents_versions.items():
        print(f"\tAgent {agent_id} upgraded: {versions['prev_version']} -> {versions['new_version']}")

    len(failed_agents.keys()) > 0 and print('\nFailed upgrades:')
    for agent_id, error in failed_agents.items():
        print(f"\tAgent {agent_id} status: {error}")


def check_status(affected_agents, result_dict, failed_agents, silent):
    """Check the agent's upgrade status

    Parameters
    ----------
    affected_agents : list
        Result of the upgrade task check
    result_dict : dict
        Dictionary with the previous version and the new one
    failed_agents : dict
        Contain the error's information
    silent : bool
        Do not show output if it is True
    """
    affected_agents = set(affected_agents)
    len(affected_agents) and print('\nUpgrading...')
    while len(affected_agents):
        task_results = send_command(function=get_upgrade_result, command={'agent_list': list(affected_agents)},
                                    local_master=True)
        for task_result in task_results.affected_items.copy():
            if task_result['status'] == 'Updated' or 'Legacy upgrade' in task_result['status']:
                agent = Agent(task_result['agent'])
                agent.load_info_from_db()
                result_dict[task_result['agent']]['new_version'] = args.version if args.version else agent.version
                affected_agents.discard(task_result['agent'])
            elif 'Error' in task_result['status'] or 'Timeout' in task_result['status'] or \
                    'cancelled' in task_result['status']:
                failed_agents[task_result['agent']] = task_result['error_msg'] if 'Error' in task_result['status'] \
                    else task_result['status']
                result_dict.pop(task_result['agent'])
                affected_agents.discard(task_result['agent'])
        sleep(3)

    not silent and print_result(agents_versions=result_dict, failed_agents=failed_agents)


def main():
    # Capture Ctrl + C
    signal(SIGINT, signal_handler)

    # Check arguments
    if args.list_outdated:
        list_outdated()
        exit(0)

    if not args.agents:
        arg_parser.print_help()
        exit(0)

    result = send_command(function=upgrade_agents, command=create_command())

    not args.silent and len(result.failed_items.keys()) > 0 and print("Agents that cannot be upgraded:")
    if not args.silent:
        for agent_result, agent_ids in result.failed_items.items():
            print(f"\tAgent {', '.join(agent_ids)} upgrade failed. Status: {agent_result}")

    result.affected_items = [task["agent"] for task in result.affected_items]
    agents_versions = get_agents_versions(agents=result.affected_items)

    failed_agents = dict()
    check_status(affected_agents=result.affected_items, result_dict=agents_versions,
                 failed_agents=failed_agents, silent=args.silent)


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a", "--agents", nargs='+', help="Agent IDs to upgrade.")
    arg_parser.add_argument("-r", "--repository", type=str, help="Specify a repository URL. [Default: {0}]".format(
        common.wpk_repo_url_4_x))
    arg_parser.add_argument("-v", "--version", type=str, help="Version to upgrade. [Default: latest Wazuh version]")
    arg_parser.add_argument("-F", "--force", action="store_true",
                            help="Allows reinstall same version and downgrade version.")
    arg_parser.add_argument("-s", "--silent", action="store_true", help="Do not show output.")
    arg_parser.add_argument("-l", "--list_outdated", action="store_true",
                            help="Generates a list with all outdated agents.")
    arg_parser.add_argument("-f", "--file", type=str, help="Custom WPK filename.")
    arg_parser.add_argument("-x", "--execute", type=str,
                            help="Executable filename in the WPK custom file. [Default: upgrade.sh]")
    arg_parser.add_argument("--http", action="store_true", help="Uses http protocol instead of https.")
    args = arg_parser.parse_args()

    try:
        main()
    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
        if args.debug:
            raise
    except Exception as e:
        print(f"Internal error: {str(e)}")
        if args.debug:
            raise
