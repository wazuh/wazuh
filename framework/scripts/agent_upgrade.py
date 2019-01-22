#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import exit, path, argv, stdout
from os.path import dirname
from signal import signal, SIGINT
from time import sleep
import argparse
import os
import re

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
    # Capture Ctrl + C
    signal(SIGINT, signal_handler)

    # Initialize framework
    myWazuh = Wazuh(get_init=True)

    # Check arguments
    if args.list_outdated:
        list_outdated()
        exit(0)

    if not args.agent:
        arg_parser.print_help()
        exit(0)

    if args.silent:
        args.debug = False

    use_http = False
    if args.http:
        use_http = True

    agent = Agent(id=args.agent)
    agent._load_info_from_DB()

    agent_info = "{0}/queue/agent-info/{1}-{2}".format(common.ossec_path, agent.name, agent.ip)
    if not os.path.isfile(agent_info):
        raise WazuhException(1720)

    # Evaluate if the version is correct
    if args.version is not None:
        pattern = re.compile("v[0-9]+\.[0-9]+\.[0-9]+")
        if not pattern.match(args.version):
            raise WazuhException(1733, "Version received: {0}".format(args.version))

    # Custom WPK file
    if args.file:
        upgrade_command_result = agent.upgrade_custom(file_path=args.file,
                                                      installer=args.execute if args.execute else "upgrade.sh",
                                                      debug=args.debug,
                                                      show_progress=print_progress if not args.silent else None,
                                                      chunk_size=args.chunk_size,
                                                      rl_timeout=-1 if args.timeout == None else args.timeout)
        if not args.silent:
            if not args.debug:
                print("\n{0}... Please wait.".format(upgrade_command_result))
            else:
                print(upgrade_command_result)

        counter = 0
        agent_info_stat = os.stat(agent_info).st_mtime

        sleep(10)
        while agent_info_stat == os.stat(agent_info).st_mtime and counter < common.agent_info_retries:
            sleep(common.agent_info_sleep)
            counter = counter + 1

        if agent_info_stat == os.stat(agent_info).st_mtime:
            raise WazuhException(1716, "Timeout waiting for agent reconnection.")

        upgrade_result = agent.upgrade_result(debug=args.debug)
        if not args.silent:
            print(upgrade_result)

    # WPK upgrade file
    else:
        prev_ver = agent.version
        upgrade_command_result = agent.upgrade(wpk_repo=args.repository, debug=args.debug, version=args.version,
                                               force=args.force,
                                               show_progress=print_progress if not args.silent else None,
                                               chunk_size=args.chunk_size,
                                               rl_timeout=-1 if args.timeout == None else args.timeout, use_http=use_http)
        if not args.silent:
            if not args.debug:
                print("\n{0}... Please wait.".format(upgrade_command_result))
            else:
                print(upgrade_command_result)

        counter = 0
        agent_info_stat = os.stat(agent_info).st_mtime

        while agent_info_stat == os.stat(agent_info).st_mtime and counter < common.agent_info_retries:
            sleep(common.agent_info_sleep)
            counter = counter + 1

        if agent_info_stat == os.stat(agent_info).st_mtime:
            raise WazuhException(1716, "Timeout waiting for agent reconnection.")

        sleep(10)
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
    arg_parser.add_argument("-r", "--repository", type=str, help="Specify a repository URL. [Default: {0}]".format(common.wpk_repo_url))
    arg_parser.add_argument("-v", "--version", type=str, help="Version to upgrade. [Default: latest Wazuh version]")
    arg_parser.add_argument("-F", "--force", action="store_true", help="Allows reinstall same version and downgrade version.")
    arg_parser.add_argument("-s", "--silent", action="store_true", help="Do not show output.")
    arg_parser.add_argument("-d", "--debug", action="store_true", help="Debug mode.")
    arg_parser.add_argument("-l", "--list_outdated", action="store_true", help="Generates a list with all outdated agents.")
    arg_parser.add_argument("-c", "--chunk_size", type=int, help="Chunk size sending WPK file. [Default: {0}]".format(common.wpk_chunk_size))
    arg_parser.add_argument("-t", "--timeout", type=int, help="Timeout until agent restart is unlocked.")
    arg_parser.add_argument("-f", "--file", type=str, help="Custom WPK filename.")
    arg_parser.add_argument("-x", "--execute", type=str, help="Executable filename in the WPK custom file. [Default: upgrade.sh]")
    arg_parser.add_argument("--http", action="store_true", help="Uses http protocol instead of https.")
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
