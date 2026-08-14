#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import warnings
from asyncio import run
from os.path import abspath, basename, dirname, isfile, join
from signal import signal, SIGINT
from sys import exit, path, argv
from time import sleep, time

from starlette.exceptions import StarletteDeprecationWarning

# Importing connexion pulls in `starlette.testclient`, which warns when `httpx2` is not
# installed. Starlette attributes the warning to the importer, so filter by message, not module.
warnings.filterwarnings(
    'ignore', category=StarletteDeprecationWarning,
    message=r'Using `httpx` with `starlette\.testclient` is deprecated',
)

from connexion import ProblemException

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    import wazuh.agent
    from wazuh.agent import upgrade_agents
    from wazuh.core import common
    from wazuh.core.exception import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()


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
    parser.add_argument("-f", "--file", type=str,
                        help="Custom WPK file. The file must already be placed in '{0}' (remoted "
                             "delivers custom WPKs from that directory by filename). A bare "
                             "filename or a path inside that directory are accepted.".format(
                                 join(common.WAZUH_PATH, 'var', 'upgrade')))
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


def resolve_wpk_file(file_arg: str) -> str:
    """Resolve and validate a custom WPK path before creating any task.

    Remoted delivers custom WPKs by reading '<WAZUH_PATH>/var/upgrade/<basename>' regardless
    of the path used at validation time, so the file must already live in that directory.
    Failing here avoids creating a task whose delivery step can only fail later.

    Parameters
    ----------
    file_arg : str
        Value of the -f/--file argument: a bare filename or a path inside var/upgrade.

    Returns
    -------
    str
        Absolute path of the WPK inside the upgrade directory.
    """
    upgrade_dir = join(common.WAZUH_PATH, 'var', 'upgrade')
    resolved = join(upgrade_dir, basename(file_arg))

    if dirname(file_arg) and abspath(dirname(file_arg)) != upgrade_dir:
        print("Error: custom WPK files are delivered from '{0}'. Move the file there and pass "
              "its filename (got: '{1}').".format(upgrade_dir, file_arg))
        exit(1)

    if not isfile(resolved):
        print("Error: WPK file not found: '{0}'. Place the file in '{1}' before launching the "
              "upgrade.".format(resolved, upgrade_dir))
        exit(1)

    return resolved


def create_command() -> dict:
    """Create a custom command based on the CLI arguments.

    Returns
    -------
    dict
        Dictionary with upgrade command.
    """
    # Generate request_time once for deterministic task IDs across all cluster nodes
    request_time = int(time())

    if not args.file and not args.execute:
        f_kwargs = {'agent_list': args.agents, 'wpk_repo': args.repository, 'version': args.version,
                    'use_http': args.http, 'force': args.force, 'package_type': args.package_type,
                    'request_time': request_time}
    else:
        # Upgrade custom
        f_kwargs = {'agent_list': args.agents, 'installer': args.execute,
                    'file_path': resolve_wpk_file(args.file) if args.file else args.file,
                    'request_time': request_time}

    return f_kwargs


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

        result = await cluster_utils.forward_function(upgrade_agents, f_kwargs=create_command(),
                                                      broadcasting=True)
        cluster_utils.raise_if_exc(result)

        # Fire-and-forget model: tasks are created but no status tracking in 5.x
        if not args.silent:
            if len(result.failed_items.keys()) > 0:
                print("Agents that cannot be upgraded:")
                for agent_result, agent_ids in result.failed_items.items():
                    print(f"\tAgent {', '.join(agent_ids)} upgrade failed. Status: {agent_result}")

            if result.total_affected_items > 0:
                print(f"\nUpgrade tasks created for {result.total_affected_items} agent(s).")
                print("Note: Agents will execute upgrades autonomously. Use agent logs to track progress.")

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
