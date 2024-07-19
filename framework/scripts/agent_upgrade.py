#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
from asyncio import run
import logging
from os.path import dirname
from signal import signal, SIGINT
from sys import exit, path, argv
from time import sleep
from connexion import ProblemException

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    import wazuh.agent
    from wazuh.agent import upgrade_agents, get_upgrade_result, get_agents
    from wazuh.core import common
    from wazuh.core.exception import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
    from wazuh.core.wlogging import CLIFilter
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logger = logging.getLogger('wazuh')
logger.addFilter(CLIFilter())


# Functions
def signal_handler(n_signal, frame):
    print("")
    exit(1)


def get_script_arguments() -> argparse.Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--agents", nargs='+', help="Agent IDs to upgrade.")
    parser.add_argument("-r", "--repository", type=str, help="Specify a repository URL. [Default: {0}]".format(
        common.WPK_REPO_URL_4_X))
    parser.add_argument("-v", "--version", type=str, help="Version to upgrade. [Default: latest Wazuh version]")
    parser.add_argument("-F", "--force", action="store_true",
                        help="Forces the agents to upgrade, ignoring version validations.")
    parser.add_argument("-s", "--silent", action="store_true", help="Do not show output.")
    parser.add_argument("-l", "--list_outdated", action="store_true", help="Generates a list with all outdated agents.")
    parser.add_argument("-f", "--file", type=str, help="Custom WPK filename.")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode.")
    parser.add_argument("-x", "--execute", type=str,
                        help="Executable filename in the WPK custom file. [Default: upgrade.sh]")
    parser.add_argument("--http", action="store_true", help="Uses http protocol instead of https.")
    parser.add_argument("--package_type", type=str, help="Use rpm or deb packages for linux platforms.")

    return parser


def list_outdated():
    """Print outdated agents."""
    agents = wazuh.agent.get_outdated_agents()
    if agents.total_affected_items == 0:
        print("All agents are updated.")
    else:
        print("%-6s%-35s %-25s" % ("ID", "Name", "Version"))
        for agent in agents.affected_items:
            print("%-6s%-35s %-25s" % (agent['id'], agent['name'], agent['version']))
        print("\nTotal outdated agents: {0}".format(agents.total_affected_items))


async def get_agents_versions(agents: list) -> dict:
    """Get the current versions of the specified agents.

    Parameters
    ----------
    agents : list
        List of agent's IDs.

    Returns
    -------
    dict
        Dictionary with the current version (prev_version).
    """
    f_kwargs = {
        "agent_list": agents,
        "select": ["version"],
        "limit": len(agents)
    }
    agent_versions = await cluster_utils.forward_function(get_agents, f_kwargs=f_kwargs)
    cluster_utils.raise_if_exc(agent_versions)
    return {agent['id']: {"prev_version": agent['version'], "new_version": None}
            for agent in agent_versions.affected_items}


async def get_agent_version(agent_id: str) -> str:
    """Get the given agent's current version.

    Parameters
    ----------
    agent_id : str
        Agent ID.

    Returns
    -------
    str
        Agent version.
    """
    f_kwargs = {
        "agent_list": [agent_id],
        "select": ["version"],
        "limit": 1
    }
    result = await cluster_utils.forward_function(get_agents, f_kwargs=f_kwargs)
    cluster_utils.raise_if_exc(result)
    return result.affected_items[0]['version']


def create_command() -> dict:
    """Create a custom command based on the CLI arguments.

    Returns
    -------
    dict
        Dictionary with upgrade command.
    """
    if not args.file and not args.execute:
        f_kwargs = {'agent_list': args.agents, 'wpk_repo': args.repository, 'version': args.version,
                    'use_http': args.http, 'force': args.force, 'package_type': args.package_type}
    else:
        # Upgrade custom
        f_kwargs = {'agent_list': args.agents, 'installer': args.execute, 'file_path': args.file}

    return f_kwargs


def print_result(agents_versions: dict, failed_agents: dict):
    """Print the operation's result.

    Parameters
    ----------
    agents_versions : dict
        Dictionary with the previous version and the new one.
    failed_agents : dict
        Contain the error's information.
    """
    len(agents_versions.keys()) > 0 and print('\nUpgraded agents:')
    for agent_id, versions in agents_versions.items():
        print(f"\tAgent {agent_id} upgraded: {versions['prev_version']} -> {versions['new_version']}")

    len(failed_agents.keys()) > 0 and print('\nFailed upgrades:')
    for agent_id, error in failed_agents.items():
        print(f"\tAgent {agent_id} status: {error}")


async def check_status(affected_agents: list, result_dict: dict, failed_agents: dict, silent: bool):
    """Check the agent's upgrade status.

    Parameters
    ----------
    affected_agents : list
        Result of the upgrade task check.
    result_dict : dict
        Dictionary with the previous version and the new one.
    failed_agents : dict
        Contain the error's information.
    silent : bool
        Whether to show output or not.
    """
    affected_agents = set(affected_agents)
    len(affected_agents) and print('\nUpgrading...')

    while len(affected_agents):
        task_results = await cluster_utils.forward_function(get_upgrade_result,
                                                            f_kwargs={'agent_list': list(affected_agents)})
        cluster_utils.raise_if_exc(task_results)

        for task_result in task_results.affected_items.copy():
            if task_result['status'] == 'Updated' or 'Legacy upgrade' in task_result['status']:
                result_dict[task_result['agent']]['new_version'] = args.version if args.version \
                    else await get_agent_version(task_result['agent'])
                affected_agents.discard(task_result['agent'])
            elif 'Error' in task_result['status'] or 'Timeout' in task_result['status'] or \
                    'cancelled' in task_result['status']:
                failed_agents[task_result['agent']] = task_result['error_msg'] if 'Error' in task_result['status'] \
                    else task_result['status']
                result_dict.pop(task_result['agent'])
                affected_agents.discard(task_result['agent'])
        sleep(3)

    not silent and print_result(agents_versions=result_dict, failed_agents=failed_agents)


async def main():
    try:
        # Capture Ctrl + C
        signal(SIGINT, signal_handler)

        # Check arguments
        if args.list_outdated:
            list_outdated()
            exit(0)

        if not args.agents:
            arg_parser.print_help()
            exit(0)

        result = await cluster_utils.forward_function(upgrade_agents, f_kwargs=create_command())
        cluster_utils.raise_if_exc(result)

        not args.silent and len(result.failed_items.keys()) > 0 and print("Agents that cannot be upgraded:")
        if not args.silent:
            for agent_result, agent_ids in result.failed_items.items():
                print(f"\tAgent {', '.join(agent_ids)} upgrade failed. Status: {agent_result}")

        result.affected_items = [task["agent"] for task in result.affected_items]
        agents_versions = await get_agents_versions(agents=result.affected_items)

        failed_agents = {}
        await check_status(affected_agents=result.affected_items, result_dict=agents_versions,
                           failed_agents=failed_agents, silent=args.silent)

    except WazuhError as wazuh_err:
        print(f"Error {wazuh_err.code}: {wazuh_err.message}")
        if args.debug:
            raise
    except ProblemException as e:
        print(f"Error {getattr(e, 'ext', {}).get('code', e.status)}: {str(e.detail)}")
        if args.debug:
            raise
    except Exception as unexpected_err:
        print(f"Internal error: {str(unexpected_err)}")
        if args.debug:
            raise


if __name__ == "__main__":
    arg_parser = get_script_arguments()
    args = arg_parser.parse_args()
    run(main())
