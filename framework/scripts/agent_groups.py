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
    from api.util import raise_if_exc
    from wazuh.core import common
    from wazuh.core.agent import Agent
    from wazuh.core.cluster.dapi.dapi import DistributedAPI
    from wazuh.core.exception import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

logger = logging.getLogger('wazuh')


# Functions
def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin


def signal_handler(n_signal, frame):
    print("")
    exit(1)


async def show_groups():
    """Show all the groups and the number of agents that belong to each one."""
    groups = await cluster_utils.forward_function(func=agent.get_agent_groups,
                                                  f_kwargs={})
    unassigned_agents = await cluster_utils.forward_function(func=agent.get_agents,
                                                             f_kwargs={'q': 'id!=000;group=null'})
    check_if_exception(groups)
    check_if_exception(unassigned_agents)

    print(f"Groups ({groups.total_affected_items}):")
    for items in groups.affected_items:
        print(f"  {items['name']} ({items['count']})")

    print(f"Unassigned agens: {unassigned_agents.total_affected_items}.")


async def show_group(agent_id):
    """Show the groups an agent belong to.

    Parameters
    ----------
    agent_id : str
        The agent we want to know the groups for.
    """

    agent_id = agent_id.split(',')
    agent_info = await cluster_utils.forward_function(func=agent.get_agents, f_kwargs={'agent_list': agent_id})

    check_if_exception(agent_info)

    if agent_info.total_affected_items == 0:
        msg = list(agent_info.failed_items.keys())[0]
    else:
        agent_info = agent_info.affected_items[0]
        str_group = ', '.join(agent_info['group']) if 'group' in agent_info else "Null"
        msg = f"The agent '{agent_info['name']}' with ID '{agent_info['id']}' belongs to groups: {str_group}."

    print(msg)


async def show_synced_agent(agent_id):
    """Show if an agent is synchronized.

    Parameters
    ----------
    agent_id : str
        The agent we want to know if is synchronized.
    """
    result = await cluster_utils.forward_function(func=agent.get_agents_sync_group, f_kwargs={'agent_list': [agent_id]})
    check_if_exception(result)

    if result.total_affected_items == 0:
        msg = list(result.failed_items.keys())[0]
    else:
        msg = f"Agent '{agent_id}' is{'' if result.affected_items[0]['synced'] else ' not'} synchronized. "

    print(msg)


async def show_agents_with_group(group_id):
    """Show agents that belong to a specific group.

    Parameters
    ----------
    group_id : str
        The group we would like to see the agents for.
    """
    group_id = group_id.split(',')
    result = await cluster_utils.forward_function(func=agent.get_agents_in_group, f_kwargs={'group_list': group_id})
    check_if_exception(result)

    if result.total_affected_items == 0:
        print(f"No agents found in group '{group_id}'.")
    else:
        print(f"{result.total_affected_items} agent(s) in group '{group_id}':")
        for a in result.affected_items:
            print(f"  ID: {a['id']}  Name: {a['name']}.")


async def show_group_files(group_id):
    """Obtain the configuration files for certain group.

    Parameters
    ----------
    group_id : str
        The group we want to check the configuration files for.
    """
    group_id = group_id.split(',')
    result = await cluster_utils.forward_function(func=agent.get_group_files, f_kwargs={'group_list': group_id})
    check_if_exception(result)

    print("{0} files for '{1}' group:".format(result.total_affected_items, group_id))

    longest_name = 0
    for item in result.affected_items:
        if len(item['filename']) > longest_name:
            longest_name = len(item['filename'])

    for item in result.affected_items:
        spaces = longest_name - len(item['filename']) + 2
        print("  {0}{1}[{2}]".format(item['filename'], spaces * ' ', item['hash']))


async def unset_group(agent_id, group_id=None, quiet=False):
    """Function to te remove agents from groups.

    Parameters
    ----------
    agent_id : str
        The agent we want to unset.
    group_id : str
        The group we want to unset the agent from.
    quiet : bool
        No confirmation mode.
    """
    if not quiet:
        if group_id:
            ans = get_stdin(f"Do you want to delete the group '{group_id}' of agent '{agent_id}'? [y/N]: ")
        else:
            ans = get_stdin(f"Do you want to delete all groups of agent '{agent_id}'? [y/N]: ")
    else:
        ans = 'y'

    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.remove_agent_from_groups,
                                                      f_kwargs={'agent_list': [agent_id], 'group_list': [group_id]})
        check_if_exception(result)

        if result.total_affected_items != 0:
            msg = f"Agent '{agent_id}' removed from {group_id}."
        else:
            msg = list(result.failed_items.keys())[0]
    else:
        msg = "Cancelled."

    print(msg)


async def remove_group(group_id, quiet=False):
    """Remove a group.

    Parameters
    ----------
    group_id : str
        The group we want to remove.
    quiet : bool
        No confirmation mode.
    """
    if not quiet:
        ans = get_stdin(f"Do you want to remove the '{group_id}' group? [y/N]: ")
    else:
        ans = 'y'

    msg = ''
    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.delete_groups, f_kwargs={'group_list': [group_id]})
        check_if_exception(result)

        if result.total_affected_items == 0:
            msg = list(result.failed_items.keys())[0]
        else:
            for items in result.affected_items:
                affected_agents = items[group_id]
                msg = f"Group {group_id} removed."

                if not affected_agents:
                    msg += '\nNo affected agents.'
                else:
                    msg += f"\nAffected agents: {', '.join(affected_agents)}."
    else:
        msg = 'Cancelled.'

    print(msg)


async def set_group(agent_id, group_id, quiet=False, replace=False):
    """Function to add agents to certain groups.

    Parameters
    ----------
    agent_id : str
        List of agents we would like to add.
    group_id : str
        List of groups we would like to add them to.
    quiet : bool
        No confirmation mode.
    replace : bool
        Force only one group.
    """
    agent_id = agent_id.split(',')
    group_id = group_id.split(',')
    agent_id = [item.zfill(3) for item in agent_id]

    if not quiet:
        ans = get_stdin(f"Do you want to add the group '{group_id}' to the agent '{agent_id}'? [y/N]: ")
    else:
        ans = 'y'

    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.assign_agents_to_group,
                                                      f_kwargs={'group_list': group_id, 'agent_list': agent_id,
                                                                'replace': replace})
        check_if_exception(result)

        if result.total_affected_items != 0:
            msg = f"Group '{group_id}' added to agent '{agent_id}'."
        else:
            msg = list(result.failed_items.keys())[0]

    else:
        msg = 'Cancelled.'

    print(msg)


async def create_group(group_id, quiet=False):
    """Create a group.

    Parameters
    ----------
    group_id : str
        The name of the group we want to create.
    quiet : bool
        No confirmation mode.
    """
    if not quiet:
        ans = get_stdin(f"Do you want to create the group '{group_id}'? [y/N]: ")
    else:
        ans = 'y'

    if ans.lower() == 'y':
        result = await cluster_utils.forward_function(func=agent.create_group, f_kwargs={'group_id': group_id})
        check_if_exception(result)

        msg = result.dikt['message']
    else:
        msg = "Cancelled."

    print(msg)


def check_if_exception(result):
    """Check if the value return is an exception.

    Parameters
    ----------
    result : value returned by function
    """
    if isinstance(result, Exception):
        raise result


def usage():
    msg = """
    {0} [ -l [ -g group_id ] | -c -g group_id | -a (-i agent_id -g groupd_id | -g group_id) [-q] [-f] | -s -i agent_id | -S -i agent_id | -r (-g group_id | -i agent_id) [-q] ]

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


def invalid_option(msg=None):
    if msg:
        print("Invalid options: {0}".format(msg))
    else:
        print("Invalid options.")

    print("Try '--help' for more information.\n")
    exit(1)


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

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-l", "--list", action='store_true', dest="list", help="List the groups.")
    arg_parser.add_argument("-c", "--list-files", action='store_true', dest="list_files",
                            help="List the group's configuration files.")
    arg_parser.add_argument("-a", "--add", action='store_true', dest="add", help="List the groups.")
    arg_parser.add_argument("-f", "--force", action='store_true', dest="force", help="Force single group.")
    arg_parser.add_argument("-s", "--show-group", action='store_true', dest="show_group", help="Show group of agent.")
    arg_parser.add_argument("-S", "--show-sync", action='store_true', dest="show_sync",
                            help="Show sync status of agent.")
    arg_parser.add_argument("-r", "--remove", action='store_true', dest="remove",
                            help="Remove group or agent from group.")
    arg_parser.add_argument("-i", "--agent-id", type=str, dest="agent_id", help="Specify the agent ID.")
    arg_parser.add_argument("-g", "--group-id", type=str, dest="group_id", help="Specify group ID.")
    arg_parser.add_argument("-q", "--quiet", action='store_true', dest="quiet", help="Silent mode (no confirmation).")
    arg_parser.add_argument("-d", "--debug", action='store_true', dest="debug", help="Debug mode.")
    arg_parser.add_argument("-u", "--usage", action='store_true', dest="usage", help="Show usage.")
    args = arg_parser.parse_args()

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
