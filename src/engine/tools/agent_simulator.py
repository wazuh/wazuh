#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import yaml
import datetime
from yaml import Loader
import subprocess

WRITE_MESSAGE_GO_PATH = '/home/vagrant/workspace/wazuh/src/engine/tools/'
WRITE_MESSAGE_GO_PATH_ARGUMENTS = ''
FILE_NAME_SAVING = 'test_logs_base.txt'

SOURCES_LIST_PATH = '/home/vagrant/workspace/wazuh/src/engine/tools/sources-list.yml'

# TODO: check fallback value for hostname
FALLBACK_VALUE_AGENT = 'hostname'

def load_file(path_str) -> dict:
    path = Path(path_str)
    content = path.read_text()
    read = yaml.load(content, Loader=Loader)
    if not read:
        raise Exception(f'Failed to read {path_str}')
    return read


def replace_fields(base_event, agent_name):
    # TODO: option for dynamic timestamp (watchout how to get the format right)
    # today = datetime.datetime.now()
    # print(today.strftime('%b %d %X'))
    replaceable_fields = {'%AGENT_NAME%': agent_name}
    for key, value in replaceable_fields.items():
        base_event = base_event.replace(key, value)
    return base_event


def create_events(agent_id, module, source, agent_name, agent_ip, file_path, labels):
    modules_queue = {
        'audit': 49,
        'command': 49,
        'djb-multilog': 00,
        'eventchannel': 102,
        'eventlog': 49,
        'full_command': 49,
        'iis': 49,
        'json': 49,
        'macos': 49,
        'multi-line-regex': 49,
        'multi-line': 49,
        'mysql_log': 49,
        'nmapg': 49,
        'postgresql_log': 49,
        'snort-full': 49,
        'squid': 49,
        'syslog': 49,
        'aws-s3': 49,
        'Azure': 00,
        'cis-cat': 00,
        'docker-listener': 00,
        'github': 00,
        'office_365': 00,
        'open-scap': 00,
        'osquery': 00,
        'virustotal': 00,
        'dbsync': 53,
        'fim': 50,
        'hostinfo': 50,
        'rootcheck': 50,
        'sca': 112,
        'syscollector': 100,
        'upgrade': 117
    }

    # Getting queue according to source
    protocol_queue = modules_queue[module]

    #  There are two possible formats of events:
    #  1st:
    #   <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Origin>:<Log>
    #  2nd:
    #   <Queue_ID>:<Syslog_Client_IP>:<Log>

    # fill fields for agent
    if not agent_name or not agent_id:
        # if not agent_name available then assumed resumed location
        protocol_location = file_path
        agent_name = FALLBACK_VALUE_AGENT
    else:
        if not agent_ip:
            agent_ip = 'any'

    protocol_location = '[' + agent_id + '] (' + agent_name + ') ' + agent_ip + '->' + module

    # Getting messages from yaml
    source_list_content = load_file(SOURCES_LIST_PATH)
    if not source_list_content:
        print('File must not be empty.')
        exit(1)

    final_events = []
    if source in source_list_content:
        for sources_block in source_list_content[source]:
            if module in sources_block and sources_block[module]:
                for single_message in sources_block[module]:
                    if not single_message:
                        break
                    else:
                        event = chr(
                            protocol_queue) + ':' + protocol_location + ':' + replace_fields(single_message, agent_name)
                        print(event)
                        final_events.append(event)

    return final_events

# TODO: not yet implemented
def send_event(event_string):
    full_script = "go run " + WRITE_MESSAGE_GO_PATH + \
        "write_message.go -m '" + event_string + "' -r \"true\""
    print(full_script)
    exit_code = subprocess.call(full_script)
    print(exit_code)


def save_to_file(events_list):
    # Should I append content ?
    text_file = open(FILE_NAME_SAVING, "w")
    for event in events_list:
        text_file.write(event + '\n')
    text_file.close()


def main():
    parser = argparse.ArgumentParser()

    # Mandatory fields
    parser.add_argument(
        '-m', '--module', help=f'Module of events', type=str, dest='module')
    parser.add_argument(
        '-s', '--source', help=f'Source of events', type=str, dest='source')

    # Agent specific fields
    parser.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                        type=str, dest='agent_id')
    parser.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                        type=str, dest='agent_name')
    parser.add_argument('-a', '--agent-ip', help=f'Agent ip address for events filling',
                        type=str, dest='agent_ip')

    # Module specific fields
    parser.add_argument('-p', '--file_path', help=f'filepath for localfile',
                        type=str, dest='file_path')
    parser.add_argument('-l', '--labels', help=f'labels added to localfile event',
                        type=str, dest='labels')

    subcommands = parser.add_subparsers(dest="subcommand_name")

    # Creates and send a sample event based on configurations
    create_and_send_command = subcommands.add_parser('create_and_send')
    create_and_send_command.add_argument(
        '-t', '--timeout', help=f'After which the communication will stop', type=str, dest='timeout')
    create_and_send_command.add_argument(
        '-E', '--eps', help=f'Repeat all possible events to send undefinetly respecting the EPS', type=str, dest='eps')
    create_and_send_command.add_argument(
        '-e', '--engine-socket', help=f'Where the engine is listening to events', type=str, dest='engine-socket')

    # Creates a sample event based on configurations
    create_event_command = subcommands.add_parser('create_event')
    create_event_command.add_argument(
        '-o', '--output', help=f'File where to store events created', type=str, dest='output', default='out.txt')
    args = parser.parse_args()

    if not args.agent_id and not args.file_path:
        print("agent-id or file_path parameter must be present.")
        exit(1)
    if not args.module or not args.source:
        print("agent-id module and source are mandatory parameters.")
        exit(1)

    if args.subcommand_name == 'create_and_send':
        agent_id = args.agent_id
        module = args.module
        source = args.source
        agent_name = args.agent_name
        agent_ip = args.agent_ip
        file_path = args.file_path
        labels = args.labels
        events_list = create_events(agent_id, module, source,
                             agent_name, agent_ip, file_path, labels)
        save_to_file(events_list)
        # result = send_event(events_list)
        print('not yet implemented, meanwhile saving it to file')
        exit(1)
    elif args.subcommand_name == 'create_event':
        agent_id = args.agent_id
        module = args.module
        source = args.source
        agent_name = args.agent_name
        agent_ip = args.agent_ip
        file_path = args.file_path
        labels = args.labels
        events_list = create_events(agent_id, module, source,
                              agent_name, agent_ip, file_path, labels)
    else:
        print("Subcommand unavailable or empty.")
        exit(1)


if __name__ == "__main__":
    main()
