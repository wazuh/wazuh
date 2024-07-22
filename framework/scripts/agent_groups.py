#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import logging
from os.path import basename
from signal import signal, SIGINT
from sys import exit, argv

# Global variables
debug = False

try:
    import wazuh.agent as agent
    from wazuh.core.exception import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
    from wazuh.core.wlogging import CLIFilter
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logger = logging.getLogger('wazuh')
logger.addFilter(CLIFilter())


# Functions
def get_stdin(msg: str) -> str:
    """Get an answer given by standard input.

    Parameters
    ---------
    msg : str
        Message to be printed.

    Returns
    -------
    str
        Answer given by standard input.
    """
    return input(msg)


def signal_handler(n_signal, frame):
    print("")
    exit(1)


async def show_groups():
    """Show all the groups and the number of agents that belong to each one."""
    groups = await cluster_utils.forward_function(func=agent.get_agent_groups, f_kwargs={})
    unassigned_agents = await cluster_utils.forward_function(func=agent.get_agents,
                                                             f_kwargs={'q': 'id!=000;group=null'})

    cluster_utils.raise_if_exc(groups)
    cluster_utils.raise_if_exc(unassigned_agents)

    print(f"Groups ({groups.total_affected_items}):")
    for items in groups.affected_items:
        print(f"  {items['name']} ({items['count']})")

    print(f"Unassigned agents: {unassigned_agents.total_affected_items}.")


async def show_group(agent_id: str):
    """Print the groups to which a specified agent belongs.

    Parameters
    ----------
    agent_id : str
        The agent we want to know the groups for.
    """
    agent_info = await cluster_utils.forward_function(func=agent.get_agents, f_kwargs={'agent_list': [agent_id]})

    cluster_utils.raise_if_exc(agent_info)

    if agent_info.total_affected_items == 0:
        msg = list(agent_info.failed_items.keys())[0]
    else:
        agent_info = agent_info.affected_items[0]
        str_group = ', '.join(agent_info['group']) if 'group' in agent_info else "Null"
        msg = f"The agent '{agent_info['name']}' with ID '{agent_info['id']}' belongs to groups: {str_group}."

    print(msg)


async def show_synced_agent(agent_id: str):
    """Show if a specified agent has its groups configuration synchronized.

    Parameters
    ----------
    agent_id : str
        ID of the agent.
    """
    result = await cluster_utils.forward_function(func=agent.get_agents_sync_group, f_kwargs={'agent_list': [agent_id]})
    cluster_utils.raise_if_exc(result)

    if result.total_affected_items == 0:
        msg = list(result.failed_items.keys())[0]
    else:
        msg = f"Agent '{agent_id}' is{'' if result.affected_items[0]['synced'] else ' not'} synchronized. "

    print(msg)


async def show_agents_with_group(group_id: str):
    """Print the ID and name of the agents belonging to a specified group.

    Parameters
    ----------
    group_id : str
        ID of the group.
    """
    result = await cluster_utils.forward_function(func=agent.get_agents_in_group,
                                                  f_kwargs={'group_list': [group_id], 'select': ['name'],
                                                            'limit': None})
    cluster_utils.raise_if_exc(result)

    if result.total_affected_items == 0:
        print(f"No agents found in group '{group_id}'.")
    else:
        print(f"{result.total_affected_items} agent(s) in group '{group_id}':")
        for a in result.affected_items:
            print(f"  ID: {a['id']}  Name: {a['name']}.")


async def show_group_files(group_id: str):
    """Print a specified group's files names and its respective hashes.

    Parameters
    ----------
    group_id : str
        ID of the group we want to check the configuration files from.
    """
    result = await cluster_utils.forward_function(func=agent.get_group_files, f_kwargs={'group_list': [group_id]})
    cluster_utils.raise_if_exc(result)

    print("{0} files for '{1}' group:".format(result.total_affected_items, group_id))

    longest_name = 0
    for item in result.affected_items:
        if len(item['filename']) > longest_name:
            longest_name = len(item['filename'])

    for item in result.affected_items:
        spaces = longest_name - len(item['filename']) + 2
        print("  {0}{1}[{2}]".format(item['filename'], spaces * ' ', item['hash']))


async def unset_group(agent_id: str, group_id: str = None, quiet: bool = False):
    """Remove a specified agent assignation with a single group or with all its groups.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    group_id : str
        ID of the group for which the agent will no longer be assigned. If no group_id is provided, all the group
        assignations will be removed.
    quiet : bool
        Show confirmation message waiting for a stdin answer.
    """
    if quiet:
        ans = 'y'

    elif group_id:
        ans = get_stdin(f"Do you want to delete the group '{group_id}' of agent '{agent_id}'? [y/N]: ")
    else:
        ans = get_stdin(f"Do you want to delete all groups of agent '{agent_id}'? [y/N]: ")
    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.remove_agent_from_groups,
                                                      f_kwargs={'agent_list': [agent_id], 'group_list': [group_id]})
        cluster_utils.raise_if_exc(result)

        if result.total_affected_items != 0:
            msg = f"Agent '{agent_id}' removed from {group_id}."
        else:
            msg = list(result.failed_items.keys())[0]
    else:
        msg = "Cancelled."

    print(msg)


async def remove_group(group_id: str, quiet: bool = False):
    """Remove a specified group.

    Parameters
    ----------
    group_id : str
        ID of the group to be removed.
    quiet : bool
        Show confirmation message waiting for a stdin answer.
    """
    ans = 'y' if quiet else get_stdin(f"Do you want to remove the '{group_id}' group? [y/N]: ")

    msg = ''
    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.delete_groups, f_kwargs={'group_list': [group_id]})
        cluster_utils.raise_if_exc(result)

        if result.total_affected_items == 0:
            msg = list(result.failed_items.keys())[0]
        else:
            msg = f'Group {group_id} removed.'
    else:
        msg = 'Cancelled.'

    print(msg)


async def set_group(agent_id: str, group_id: str, quiet: bool = False, replace: bool = False):
    """Assign a specified agent to a specified group.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    group_id : str
        Group ID.
    quiet : bool
        Show confirmation message waiting for a stdin answer.
    replace : bool
        Whether to append the new group to current agent's groups or to replace it.
    """
    agent_id = f"{int(agent_id)}".zfill(3)

    ans = 'y' if quiet else get_stdin(f"Do you want to add the group '{group_id}' to the agent '{agent_id}'? [y/N]: ")

    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.assign_agents_to_group,
                                                      f_kwargs={'group_list': [group_id], 'agent_list': [agent_id],
                                                                'replace': replace})
        cluster_utils.raise_if_exc(result)

        if result.total_affected_items != 0:
            msg = f"Group '{group_id}' added to agent '{agent_id}'."
        else:
            msg = list(result.failed_items.keys())[0]

    else:
        msg = 'Cancelled.'

    print(msg)


async def create_group(group_id: str, quiet: bool = False):
    """Create a group given its ID.

    Parameters
    ----------
    group_id : str
        ID of the group to be created
    quiet : bool
        Show confirmation message waiting for a stdin answer.
    """
    ans = 'y' if quiet else get_stdin(f"Do you want to create the group '{group_id}'? [y/N]: ")

    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.create_group, f_kwargs={'group_id': group_id})
        cluster_utils.raise_if_exc(result)

        msg = result.dikt['message']
    else:
        msg = "Cancelled."

    print(msg)


def usage():
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
    """.format(basename(argv[0]))
    print(msg)


def invalid_option(msg: str = None):
    """Exit with an invalid options message.

    Parameters
    ----------
    msg : str
        Extra information for the invalid options message.
    """
    if msg:
        print("Invalid options: {0}".format(msg))
    else:
        print("Invalid options.")

    print("Try '--help' for more information.\n")
    exit(1)


def get_script_arguments() -> argparse.Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", action='store_true', dest="list", help="List the groups.")
    parser.add_argument("-c", "--list-files", action='store_true', dest="list_files",
                        help="List the group's configuration files.")
    parser.add_argument("-a", "--add", action='store_true', dest="add", help="Add new group or new agent to group.")
    parser.add_argument("-f", "--force", action='store_true', dest="force", help="Force single group.")
    parser.add_argument("-s", "--show-group", action='store_true', dest="show_group", help="Show group of agent.")
    parser.add_argument("-S", "--show-sync", action='store_true', dest="show_sync",
                        help="Show sync status of agent.")
    parser.add_argument("-r", "--remove", action='store_true', dest="remove",
                        help="Remove group or agent from group.")
    parser.add_argument("-i", "--agent-id", type=str, dest="agent_id", help="Specify the agent ID.")
    parser.add_argument("-g", "--group-id", type=str, dest="group_id", help="Specify group ID.")
    parser.add_argument("-q", "--quiet", action='store_true', dest="quiet", help="Silent mode (no confirmation).")
    parser.add_argument("-d", "--debug", action='store_true', dest="debug", help="Debug mode.")
    parser.add_argument("-u", "--usage", action='store_true', dest="usage", help="Show usage.")

    args = parser.parse_args()
    if sum([args.list, args.list_files, args.add, args.show_group, args.show_sync, args.remove]) > 1:
        invalid_option("Bad argument combination.")

    return args


async def main():
    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    # ./agent_groups.py -l [ -g group_id ]
    if args.list:
        if args.group_id:
            await show_agents_with_group(args.group_id)
        else:
            await show_groups()
    # -c -g group_id
    elif args.list_files:
        await show_group_files(args.group_id) if args.group_id else invalid_option("Missing group.")
    # -a (-i agent_id -g groupd_id | -g group_id) [-q] [-e]
    elif args.add:
        if args.agent_id and args.group_id:
            await set_group(args.agent_id, args.group_id, args.quiet, args.force)
        elif args.group_id:
            await create_group(args.group_id, args.quiet)
        else:
            invalid_option("Missing agent ID or group.")
    # -s -i agent_id
    elif args.show_group:
        await show_group(args.agent_id) if args.agent_id else invalid_option("Missing agent ID.")
    # -S -i agent_id
    elif args.show_sync:
        await show_synced_agent(args.agent_id) if args.agent_id else invalid_option("Missing agent ID.")
    # -r (-g group_id | -i agent_id) [-q]
    elif args.remove:
        if args.agent_id:
            await unset_group(args.agent_id, args.group_id, args.quiet)
        elif args.group_id:
            await remove_group(args.group_id, args.quiet)
        else:
            invalid_option("Missing agent ID or group.")
    elif args.usage:
        usage()
    # ./agent_groups.py
    else:
        await show_groups()


if __name__ == "__main__":
    args = get_script_arguments()

    try:
        asyncio.run(main())

    except WazuhError as e:
        print("Error {0}: {1}".format(e.code, e.message))
        if args.debug:
            raise
    except Exception as e:
        print("Internal error: {0}".format(str(e)))
        if args.debug:
            raise
