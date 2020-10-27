#!/usr/bin/env python

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from getopt import GetoptError, getopt
from os.path import basename
from signal import signal, SIGINT
from sys import exit, argv

from wazuh import agent
from wazuh.agent import remove_agent_from_groups
from wazuh.core import agent as core_agent
from wazuh.core.cluster.utils import read_config
from wazuh.core.exception import WazuhError

# Global variables
debug = False


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


def show_groups():
    groups_data = agent.get_agent_groups().to_dict()
    print("Groups ({0}):".format(groups_data['total_affected_items']))
    for g in groups_data['affected_items']:
        print("  {0} ({1})".format(g['name'], g['count']))

    print("Unassigned agents: {0}.".format(agent.get_agents(q='id!=000;group=null').to_dict()['total_affected_items']))


def show_group(agent_id):
    agent_info = agent.get_agents(agent_list=[agent_id]).to_dict()
    if agent_info['total_affected_items'] == 0:
        print(list(agent_info['failed_items'].keys())[0])
    else:
        agent_info = agent_info['affected_items'][0]
        str_group = ', '.join(agent_info['group']) if 'group' in agent_info else "Null"
        print("The agent '{0}' with ID '{1}' belongs to groups: {2}.".format(agent_info['name'], agent_info['id'],
                                                                             str_group))


def show_synced_agent(agent_id):
    result = agent.get_agents_sync_group(agent_list=[agent_id]).to_dict()
    if result['total_affected_items'] == 0:
        print(list(result['failed_items'].keys())[0])
    else:
        print(
            "Agent '{}' is{} synchronized. ".format(agent_id, '' if result['affected_items'][0]['synced'] else ' not'))


def show_agents_with_group(group_id):
    agents_data = agent.get_agents_in_group(group_list=[group_id], limit=None).to_dict()

    if agents_data['total_affected_items'] == 0:
        print("No agents found in group '{0}'.".format(group_id))
    else:
        print("{0} agent(s) in group '{1}':".format(agents_data['total_affected_items'], group_id))
        for a in agents_data['affected_items']:
            print("  ID: {0}  Name: {1}.".format(a['id'], a['name']))


def show_group_files(group_id):
    data = agent.get_group_files(group_list=[group_id]).to_dict()
    print("{0} files for '{1}' group:".format(data['total_affected_items'], group_id))

    longest_name = 0
    for item in data['affected_items']:
        if len(item['filename']) > longest_name:
            longest_name = len(item['filename'])

    for item in data['affected_items']:
        spaces = longest_name - len(item['filename']) + 2
        print("  {0}{1}[{2}]".format(item['filename'], spaces * ' ', item['hash']))


def unset_group(agent_id, group_id=None, quiet=False):
    if not quiet:
        if group_id:
            ans = get_stdin("Do you want to delete the group '{0}' of agent '{1}'? [y/N]: ".format(group_id, agent_id))
        else:
            ans = get_stdin("Do you want to delete all groups of agent '{0}'? [y/N]: ".format(agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        if group_id:
            msg = core_agent.Agent.unset_single_group_agent(agent_id, group_id)
        else:
            groups_agent_removed = remove_agent_from_groups(agent_list=[agent_id])._affected_items
            if len(groups_agent_removed) == 0:
                msg = f"Agent '{agent_id}' is only assigned to group default."
            else:
                msg = f"Agent '{agent_id}' removed from '{', '.join(groups_agent_removed)}'. Agent reassigned to group default."
    else:
        msg = "Cancelled."

    print(msg)


def remove_group(group_id, quiet=False):
    if not quiet:
        ans = get_stdin("Do you want to remove the '{0}' group? [y/N]: ".format(group_id))
    else:
        ans = 'y'

    msg = ''
    if ans.lower() == 'y':
        data = agent.delete_groups(group_list=[group_id]).to_dict()
        if data['total_affected_items'] == 0:
            print(list(data['failed_items'].keys())[0])
        else:
            affected_agents = data['dikt']['affected_agents']
            msg = f'Group {group_id} removed.'
            if not affected_agents:
                msg += "\nNo affected agents."
            else:
                msg += "\nAffected agents: {0}.".format(', '.join(affected_agents))
    else:
        msg = "Cancelled."

    print(msg)


def set_group(agent_id, group_id, quiet=False, replace=False):
    agent_id = "{}".format(int(agent_id)).zfill(3)
    if not quiet:
        ans = get_stdin("Do you want to add the group '{0}' to the agent '{1}'? [y/N]: ".format(group_id, agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        data = agent.assign_agents_to_group(agent_list=[agent_id], group_list=[group_id], replace=replace).to_dict()
        if data['total_affected_items'] == 0:
            print(list(data['failed_items'].keys())[0])
        else:
            print("Group '{0}' added to agent '{1}'.".format(group_id, agent_id))
    else:
        print("Cancelled.")


def create_group(group_id, quiet=False):
    if not quiet:
        ans = get_stdin("Do you want to create the group '{0}'? [y/N]: ".format(group_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = agent.create_group(group_id).dikt['message']
    else:
        msg = "Cancelled."

    print(msg)


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


def main():
    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    # Parse arguments
    arguments = {'n_args': 0, 'n_actions': 0, 'group': None, 'agent-id': None, 'list': False, 'list-files': False,
                 'add-group': False, 'replace-group': False, 'show-group': False, 'show-sync': False,
                 'remove-group': False, 'quiet': False}
    try:
        opts, args = getopt(argv[1:], "lcafsSri:g:qdh",
                            ["list", "list-files", "add-group", "replace-group", "show-group", "show-sync",
                             "remove-group", "agent-id=", "group=", "quiet", "debug", "help"])
        arguments['n_args'] = len(opts)
    except GetoptError as err:
        print(str(err) + "\n" + "Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-l", "--list"):
            arguments['list'] = True
            arguments['n_actions'] += 1
        elif o in ("-c", "--list-files"):
            arguments['list-files'] = True
            arguments['n_actions'] += 1
        elif o in ("-a", "--add-group"):
            arguments['add-group'] = True
            arguments['n_actions'] += 1
        elif o in ("-f", "--replace-group"):
            arguments['replace-group'] = True
        elif o in ("-s", "--show-group"):
            arguments['show-group'] = True
            arguments['n_actions'] += 1
        elif o in ("-S", "--show-sync"):
            arguments['show-sync'] = True
            arguments['n_actions'] += 1
        elif o in ("-r", "--remove-group"):
            arguments['remove-group'] = True
            arguments['n_actions'] += 1
        elif o in ("-i", "--agent-id"):
            arguments['agent-id'] = a
        elif o in ("-g", "--group"):
            arguments['group'] = a
        elif o in ("-q", "--quiet"):
            arguments['quiet'] = True
        elif o in ("-d", "--debug"):
            global debug
            debug = True
        elif o in ("-h", "--help"):
            usage()
            exit(0)
        else:
            invalid_option()

    # Actions
    if arguments['n_args'] > 5 or arguments['n_actions'] > 1:
        invalid_option("Bad argument combination.")

    # ./agent_groups.py
    if arguments['n_args'] == 0:
        show_groups()
    # ./agent_groups.py -l [ -g group_id ]
    elif arguments['list']:
        if arguments['group']:
            show_agents_with_group(arguments['group'])
        else:
            show_groups()
    # -c -g group_id
    elif arguments['list-files']:
        show_group_files(arguments['group']) if arguments['group'] else invalid_option("Missing group.")
    # -a (-i agent_id -g groupd_id | -g group_id) [-q] [-e]
    elif arguments['add-group']:
        if arguments['agent-id'] and arguments['group']:
            set_group(arguments['agent-id'], arguments['group'], arguments['quiet'], arguments['replace-group'])
        elif arguments['group']:
            create_group(arguments['group'], arguments['quiet'])
        else:
            invalid_option("Missing agent ID or group.")
    # -s -i agent_id
    elif arguments['show-group']:
        show_group(arguments['agent-id']) if arguments['agent-id'] else invalid_option("Missing agent ID.")
    # -S -i agent_id
    elif arguments['show-sync']:
        show_synced_agent(arguments['agent-id']) if arguments['agent-id'] else invalid_option("Missing agent ID.")
    # -r (-g group_id | -i agent_id) [-q]
    elif arguments['remove-group']:
        if arguments['agent-id']:
            unset_group(arguments['agent-id'], arguments['group'], arguments['quiet'])
        elif arguments['group']:
            remove_group(arguments['group'], arguments['quiet'])
        else:
            invalid_option("Missing agent ID or group.")
    else:
        invalid_option("Bad argument combination.")


if __name__ == "__main__":
    logger = logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    try:
        cluster_config = read_config()
        executable_name = "agent_groups"
        master_ip = cluster_config['nodes'][0]
        if cluster_config['node_type'] != 'master' and not cluster_config['disabled']:
            raise WazuhError(3019, {"EXECUTABLE_NAME": executable_name, "MASTER_IP": master_ip})
        main()

    except WazuhError as e:
        print("Error {0}: {1}".format(e.code, e.message))
        if debug:
            raise
    except Exception as e:
        print("Internal error: {0}".format(str(e)))
        if debug:
            raise
