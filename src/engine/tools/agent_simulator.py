#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import yaml
from yaml import Loader

WRITE_MESSAGE_GO_PATH = '/var/ossec/queue/sockets/queue'
WRITE_MESSAGE_GO_PATH_ARGUMENTS = ''
SOURCES_LIST_PATH = '/home/vagrant/workspace/wazuh/src/engine/tools/sources-list.yml'

def load_file(path_str) -> dict:
    path = Path(path_str)
    content = path.read_text()
    readed = yaml.load(content, Loader=Loader)
    if not readed:
        raise Exception(f'Failed to read {full_name}')
    return readed

def create_event(agent, modules, sources):
    # TODO: pending loop for several sources and several events
    modules_queue = {
        'windowsEventChannel' : 102,
        'windowsEventLog' : 49,
        'syscollector' : 100
        }

    # According to source gets queue
    protocol_queue = modules_queue[modules]

    # fill fixed fields for agent
    agent_name = 'agent_name'
    agent_IP = '192.168.150.120'
    origin = modules
    protocol_location = '[' + agent + '] ('+ agent_name +') ' + agent_IP + '->'+origin

    #look into yaml SOURCES_LIST_PATH from [module][source]
    source_list_content = load_file(SOURCES_LIST_PATH)
    if not source_list_content:
        print('File must not be empty.')
        exit(1)

    if sources in source_list_content:
        for sources_block in source_list_content[sources]:
            if modules in sources_block:
                for entry in sources_block[modules]:
                    base_event = entry

    final_event = chr(protocol_queue) + ":" + protocol_location + base_event
    print(final_event)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--agent-id', help=f'Agent ID for filling events',
                        type=str, dest='agent', default='001')
    parser.add_argument(
        '-m', '--module', help=f'Module or list of modules (separated by comma) of events', type=str, dest='modules')
    parser.add_argument(
        '-s', '--source', help=f'Source or list of sources (separated by comma) of events', type=str, dest='sources')
    # '-p', '--path', help=f'Path to localfile', type=str, dest='path'

    subcommands = parser.add_subparsers(dest="subcommand_name")

    # 'Creates and send a sample event based on configurations'
    create_and_send_command = subcommands.add_parser('create_and_send')
    create_and_send_command.add_argument(
        '-t', '--timeout', help=f'After which the communication will stop', type=str, dest='timeout')
    create_and_send_command.add_argument(
        '-E', '--eps', help=f'Repeat all possible events to send undefinetly respecting the EPS', type=str, dest='eps')
    create_and_send_command.add_argument(
        '-e', '--engine-socket', help=f'Where the engine is listening to events', type=str, dest='engine-socket')

    # 'Creates a sample event based on configurations'
    create_event_command = subcommands.add_parser('create_event')
    create_event_command.add_argument(
            '-o', '--output', help=f'File where to store events created', type=str, dest='output', default='out.txt')
    args = parser.parse_args()

    if not args.agent or not args.modules or not args.sources:
        logger.critical("agent-id modules and sources are mandatory parameters.")
        exit(1)

    if args.subcommand_name == 'create_and_send':
        logger.critical("Not yet implemented.")
        exit(1)
    elif args.subcommand_name == 'create_event':
        agent_name = args.agent
        modules = args.modules
        sources = args.sources
        create_event(agent_name, modules, sources)



if __name__ == "__main__":
    main()
