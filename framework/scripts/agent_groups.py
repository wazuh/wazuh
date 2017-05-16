#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import exit, path, argv
from os.path import dirname
from getopt import GetoptError, getopt
from signal import signal, SIGINT

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.agent import Agent
    from wazuh.exception import WazuhException
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

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
    groups_data = Agent.get_all_groups(limit=None)

    print("Groups ({0}):".format(groups_data['totalItems']))
    for g in groups_data['items']:
        print("  {0} ({1})".format(g['name'], g['count']))


def show_group(agent_id):
    agent_info = Agent(id=agent_id).get_basic_information()

    str_group = agent_info['group'] if 'group' in agent_info else "Null"
    print("The agent '{0}' with ID '{1}' has the group: '{2}'.".format(agent_info['name'], agent_info['id'], str_group))


def show_agents_with_group(group_id):
    agents_data = Agent.get_agent_group(group_id, limit=0)

    if agents_data['totalItems'] == 0:
        print("Any agent with group '{0}'.".format(group_id))
    else:
        print("{0} agent(s) in group '{1}':".format(agents_data['totalItems'], group_id))
        for agent in agents_data['items']:
            print("  ID: {0}  Name: {1}.".format(agent['id'], agent['name']))


def show_group_files(group_id):
    data = Agent.get_group_files(group_id)
    print("{0} files for '{1}' group:".format(data['totalItems'], group_id))

    longest_name = 0
    for item in data['items']:
        if len(item['filename']) > longest_name:
            longest_name = len(item['filename'])

    for item in data['items']:
        spaces = longest_name - len(item['filename']) + 2
        print("  {0}{1}[{2}]".format(item['filename'], spaces*' ', item['hash']))


def unset_group(agent_id, quiet=False):
    ans = 'n'
    if not quiet:
         ans = get_stdin("Do you want to unset the current group of agent '{0}'? [y/N]: ".format(agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = Agent.unset_group(agent_id)
    else:
        msg = "Cancelled."

    print(msg)


def remove_group(group_id, quiet=False):
    ans = 'n'
    if not quiet:
         ans = get_stdin("Do you want to remove the '{0}' group? [y/N]: ".format(group_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        data = Agent.remove_group(group_id)
        msg = data['msg']
        if not data['affected_agents']:
            msg += "\nNo affected agents."
        else:
            msg += "\nAffected agents: {0}.".format(', '.join(data['affected_agents']))
    else:
        msg = "Cancelled."

    print(msg)


def set_group(agent_id, group_id, quiet=False):
    ans = 'n'
    if not quiet:
         ans = get_stdin("Do you want to set the group '{0}' to the agent '{1}'? [y/N]: ".format(group_id, agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = Agent.set_group(agent_id, group_id)
    else:
        msg = "Cancelled."

    print(msg)


def create_group(group_id, quiet=False):
    ans = 'n'
    if not quiet:
         ans = get_stdin("Do you want to create the group '{0}'? [y/N]: ".format(group_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = Agent.create_group(group_id)
    else:
        msg = "Cancelled."

    print(msg)


def usage():
    msg = """
    ./agent_groups.py [ -l [ -g group_id ] | -c -g group_id | -a (-i agent_id -g groupd_id | -g group_id) [-q] | -s -i agent_id | -r (-g group_id | -i agent_id) [-q] ]

    Usage:
    ./agent_groups.py [-l]                                  # List all groups
    ./agent_groups.py -l -g group_id                        # List agents in group
    ./agent_groups.py -c -g group_id                        # List configuration files in group

    ./agent_groups.py -a -i agent_id -g group_id [-q]       # Set agent group
    ./agent_groups.py -r -i agent_id [-q]                   # Unset agent group
    ./agent_groups.py -s -i agent_id                        # Show group of agent

    ./agent_groups.py -a -g group_id [-q]                   # Create group
    ./agent_groups.py -r -g group_id [-q]                   # Remove group


    Params:
    \t-l, --list
    \t-c, --list-files
    \t-a, --add-group
    \t-s, --show-group
    \t-r, --remove-group

    \t-i, --agent-id
    \t-g, --group

    \t-q, --quiet (no confirmation)
    \t-d, --debug
    """
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

    # Initialize framework
    myWazuh = Wazuh(get_init=True)

    # Parse arguments
    arguments = {'n_args': 0, 'n_actions': 0, 'group': None, 'agent-id': None, 'list': False, 'list-files': False, 'add-group': False, 'show-group': False, 'remove-group': False, 'quiet': False }
    try:
        opts, args = getopt(argv[1:], "lcasri:g:qfdh", ["list", "list-files", "add-group", "show-group", "remove-group", "agent-id=", "group=", "quiet", "debug", "help"])
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
        elif o in ("-s", "--show-group"):
            arguments['show-group'] = True
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
    # -a (-i agent_id -g groupd_id | -g group_id) [-q]
    elif arguments['add-group']:
        if arguments['agent-id'] and arguments['group']:
            set_group(arguments['agent-id'], arguments['group'], arguments['quiet'])
        elif arguments['group']:
            create_group(arguments['group'], arguments['quiet'])
        else:
            invalid_option("Missing agent ID or group.")
    # -s -i agent_id
    elif arguments['show-group']:
        show_group(arguments['agent-id']) if arguments['agent-id'] else invalid_option("Missing agent ID.")
    # -r (-g group_id | -i agent_id) [-q]
    elif arguments['remove-group']:
        if arguments['agent-id']:
            unset_group(arguments['agent-id'], arguments['quiet'])
        elif arguments['group']:
            remove_group(arguments['group'], arguments['quiet'])
        else:
            invalid_option("Missing agent ID or group.")
    else:
        invalid_option("Bad argument combination.")


if __name__ == "__main__":

    try:
        main()
    except WazuhException as e:
        print("Error {0}: {1}".format(e.code, e.message))
        if debug:
            raise
    except Exception as e:
        print("Internal error: {0}".format(str(e)))
        if debug:
            raise
