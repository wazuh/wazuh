#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import yaml
from yaml import Loader
import json
import socket
import sys

DUMP_FILE_NAME = 'test_logs_base.txt'
SOURCES_LIST_PATH = '/home/vagrant/workspace/wazuh/src/engine/tools/sources-list.yml'
DEFAULT_ENGINE_SOCKET = '/var/ossec/queue/sockets/queue'


def load_file(path_str) -> dict:
    path = Path(path_str)
    content = path.read_text()
    read = yaml.load(content, Loader=Loader)
    if not read:
        raise Exception(f'Failed to read {path_str}')
    return read


def replace_fields(base_event, agent_name, location):
    # is it neccesary to set a dynamic timestamp ?
    replaceable_fields = {'%AGENT_NAME%': agent_name,
                          '%LOCATION%': location}
    for key, value in replaceable_fields.items():
        base_event = base_event.replace(key, value)
    return base_event


def add_event_object(message_modified, labels):
    # Creating labels object for json
    labels_object = json.loads(labels)  # breaks on malformed json
    if not labels_object:
        print('Wrong json format for labels.')
        exit(1)
    events_object = labels_object

    message_modified_json = json.loads(message_modified)
    if not message_modified_json:
        print("wrong json formated event")  # This scenario shouldn't happend
        exit(1)

    if "event" in message_modified_json:
        for key in events_object:
            message_modified_json["event"][key] = events_object[key]
    else:
        message_modified_json["event"] = events_object

    return json.dumps(message_modified_json)


def create_events(agent_id, module, source, agent_name, agent_ip, location, labels):
    modules_queue = {
        'audit': 49,
        'command': 49,
        'djb-multilog': 49,
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
        'Azure': 00,            # TODO check queue
        'cis-cat': 101,
        'docker-listener': 00,  # TODO check queue
        'github': 00,           # TODO check queue
        'office_365': 00,       # TODO check queue
        'open-scap': 00,        # TODO check queue
        'osquery': 00,          # TODO check queue
        'virustotal': 00,       # TODO check queue
        'dbsync': 53,
        'fim': 56,
        'hostinfo': 51,
        'rootcheck': 57,
        'sca': 112,
        'syscollector': 100,
        'upgrade': 117,
        'rsyslog': 50
    }

    # Getting queue according to source
    protocol_queue = modules_queue[module]

    # Scaping the ':' is made with '|' and without checking if it was already scaped (it shouldn't be)
    if source == 'logcollector' and location and module != 'eventchannel' and module != 'eventlog':
        location = location.replace(':', '|:')
    else:
        location = module

    if not agent_ip:
        agent_ip = 'any'
    else:
        agent_ip = agent_ip.replace(':', '|:')

    # There are two possible formats of events:
    # 1st:
    # <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Origin>:<Log>
    # 2nd: -> for remote syslog events
    # <Queue_ID>:<Syslog_Client_IP>:<Log>
    if source == 'remote-syslog' or module == 'rsyslog':
        protocol_location = agent_ip
    else:
        protocol_location = '[' + agent_id + \
            '] (' + agent_name + ') ' + agent_ip + '->' + location

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
                    message_modified = replace_fields(
                        single_message, agent_name, location)
                    if module == 'json' and labels:
                        message_modified = add_event_object(
                            message_modified, labels)
                    event = chr(protocol_queue) + ':' + \
                        protocol_location + ':' + message_modified
                    print(event)
                    final_events.append(event)

    return final_events


def send_event(event_list, socket_address):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # print('connecting to {}'.format(socket_address))

    try:
        sock.connect(socket_address)
    except socket.error as msg:
        print(msg)
        sys.exit(1)

    try:
        for event in event_list:
            print('sending {!r}'.format(event))
            sock.sendall(event.encode())

    finally:
        print('closing socket')
        sock.close()


def save_to_file(events_list, output_file_name):
    # append content and creates file if it doesn't exist
    with open(output_file_name, 'a+') as f:
        for event in events_list:
            f.write(event + '\n')
        f.close()


def main():
    parser = argparse.ArgumentParser()

    # Mandatory fields
    parser.add_argument(
        '-m', '--module', help=f'Module of events', type=str, dest='module')
    parser.add_argument(
        '-s', '--source', help=f'Source of events', type=str, dest='source')

    # Agent specific fields
    parser.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                        type=str, default='001', dest='agent_id')
    parser.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                        type=str, default='agent-001', dest='agent_name')
    parser.add_argument('-a', '--agent-ip', help=f'Agent ip address for events filling',
                        type=str, default='any', dest='agent_ip')

    subcommands = parser.add_subparsers(dest="subcommand_name")

    # Creates and send a sample event based on configurations
    create_and_send_command = subcommands.add_parser('send_event')
    create_and_send_command.add_argument(
        '-e', '--engine-socket', help=f'Where the engine is listening to events',
        default=DEFAULT_ENGINE_SOCKET, type=str, dest='engine_socket')

    # Creates a sample event based on configurations
    saves_event_command = subcommands.add_parser('save_event')
    saves_event_command.add_argument(
        '-O', '--Output', help=f'File where to store created events', type=str, default=DUMP_FILE_NAME, dest='output')

    # Module specific fields
    parser.add_argument('-L', '--location', help=f'logcollector location wether file path or command',
                        type=str, default="", dest='location')
    parser.add_argument('-l', '--labels', help=f'json object added to logcollector json event',
                        type=str, default="", dest='labels')

    args = parser.parse_args()

    if not args.module or not args.source:
        print("module and source are mandatory parameters.")
        exit(1)

    if args.subcommand_name == 'send_event':
        agent_id = args.agent_id
        module = args.module
        source = args.source
        agent_name = args.agent_name
        agent_ip = args.agent_ip
        location = args.location
        labels = args.labels
        events_list = create_events(agent_id, module, source,
                                    agent_name, agent_ip, location, labels)
        socket = args.engine_socket
        send_event(events_list, socket)
    elif args.subcommand_name == 'save_event':
        agent_id = args.agent_id
        module = args.module
        source = args.source
        agent_name = args.agent_name
        agent_ip = args.agent_ip
        location = args.location
        labels = args.labels
        output_file = args.output
        print(output_file)
        events_list = create_events(agent_id, module, source,
                                    agent_name, agent_ip, location, labels)
        save_to_file(events_list, output_file)
    else:
        print("Subcommand unavailable or empty.")
        exit(1)


if __name__ == "__main__":
    main()
