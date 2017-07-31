#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import exit, path, argv, stdout
from os.path import dirname
from signal import signal, SIGINT
from time import sleep
import argparse
import os

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.agent import Agent
    from wazuh.exception import WazuhException
    from wazuh import common
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()


# Functions
def signal_handler(n_signal, frame):
    print("")
    exit(1)

def print_progress(value):
    stdout.write("Sending WPK: [%-25s] %d%%   \r" % ('='*int(value/4), value))
    stdout.flush()

def list_outdated():
    agents = Agent.get_outdated_agents()
    if agents['totalItems'] == 0:
        print("All agents are updated.")
    else:
        print("%-6s%-35s %-25s" % ("ID", "Name", "Version"))
        for agent in agents['items']:
            print("%-6s%-35s %-25s" % (agent['id'], agent['name'], agent['version']))
        print("\nTotal outdated agents: {0}".format(agents['totalItems']))

def main():
    # Check arguments
    if args.list_outdated:
        list_outdated()
        exit(0)

    if not args.agent:
        arg_parser.print_help()
        exit(0)

    if args.silent:
        args.debug = False

    # Capture Ctrl + C
    signal(SIGINT, signal_handler)

    # Initialize framework
    myWazuh = Wazuh(get_init=True)

    agent = Agent(id=args.agent)
    agent._load_info_from_DB()

    timeout = 60
    agent_info = "{0}/queue/agent-info/{1}-{2}".format(common.ossec_path, agent.name, agent.ip)
    agent_info_stat = os.stat(agent_info).st_mtime

    # Custom WPK file
    if args.file:
        if args.execute:
            upgrade_command_result = agent.upgrade_custom(file_path=args.file, installer=args.execute, debug=args.debug, show_progress=print_progress if not args.silent else None)
            if not args.silent:
                if not args.debug:
                    print("\n{0}... Please wait.".format(upgrade_command_result))
                else:
                    print(upgrade_command_result)
            counter = 0
            while agent_info_stat == os.stat(agent_info).st_mtime and counter < timeout:
                sleep(1)
                counter = counter + 1
            upgrade_result = agent.upgrade_result(debug=args.debug)
            if not args.silent:
                print(upgrade_result)
        else:
            print("Error: Need executable filename.")

    # WPK upgrade file
    else:
        prev_ver = agent.version
        upgrade_command_result = agent.upgrade(wpk_repo=args.repository, debug=args.debug, version=args.version, force=args.force, show_progress=print_progress if not args.silent else None)
        if not args.silent:
            if not args.debug:
                print("\n{0}... Please wait.".format(upgrade_command_result))
            else:
                print(upgrade_command_result)
        counter = 0
        while agent_info_stat == os.stat(agent_info).st_mtime and counter < timeout:
            sleep(1)
            counter = counter + 1
        upgrade_result = agent.upgrade_result(debug=args.debug)
        if not args.silent:
            if not args.debug:
                agent._load_info_from_DB()
                print("Agent upgraded: {0} -> {1}".format(prev_ver, agent.version))
            else:
                print(upgrade_result)



if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-a", "--agent", type=str, help="Agent ID to upgrade.")
    arg_parser.add_argument("-r", "--repository", type=str, help="Specify a repository URL.")
    arg_parser.add_argument("-v", "--version", type=str, help="Version to upgrade. [Default: latest Wazuh version]")
    arg_parser.add_argument("-F", "--force", action="store_true", help="Allows reinstall same version and downgrade version.")
    arg_parser.add_argument("-s", "--silent", action="store_true", help="Do not show output.")
    arg_parser.add_argument("-d", "--debug", action="store_true", help="Debug mode.")
    arg_parser.add_argument("-l", "--list_outdated", action="store_true", help="Generates a list with all outdated agents.")
    arg_parser.add_argument("-f", "--file", type=str, help="Custom WPK filename.")
    arg_parser.add_argument("-x", "--execute", type=str, help="Executable filename in the WPK custom file.")
    args = arg_parser.parse_args()

    try:
        main()
    except WazuhException as e:
        print("Error {0}: {1}".format(e.code, e.message))
        if args.debug:
            raise
    except Exception as e:
        print("Internal error: {0}".format(str(e)))
        if args.debug:
            raise
