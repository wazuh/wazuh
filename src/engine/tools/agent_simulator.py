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
DEFAULT_ENGINE_SOCKET = '/var/ossec/queue/sockets/queue'
JSON_BASE_EVENT = '{"event" : {"original" : {}}}'


def add_to_event_object(events_list, labels):
    # Creating labelsjson object
    try:
        labels_object = json.loads(labels)
        if not labels_object:
            print('Wrong json format for labels.')
            exit(1)
    except ValueError:  # includes simplejson.decoder.JSONDecodeError
        print('Wrong json format for labels.')
        exit(1)
    events_object = labels_object

    modified_event_list = []
    for single_event in events_list:
        try:
            events_json = json.loads(single_event)
        except ValueError:
            events_json = json.loads(JSON_BASE_EVENT)
            events_json['event']['original'] = single_event

        if "event" in events_json:
            for key in events_object:
                events_json["event"][key] = events_object[key]
        else:
            events_json["event"] = events_object

        modified_event_list.append(json.dumps(events_json))

    return modified_event_list


def create_header(protocol_queue, agent_id, agent_name, agent_ip, location):
    # Scaping the ':' is made with '|' and without checking if it was already scaped (it shouldn't be)
    location = location.replace(':', '|:')
    agent_ip = agent_ip.replace(':', '|:')

    # respect filling with zeros
    if len(agent_id) < 3:
        agent_id = agent_id.zfill(3)

    # There are two possible formats of events:
    # 1st:
    # <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Origin>:<Log>
    # 2nd: -> for remote syslog events
    # <Queue_ID>:<Syslog_Client_IP>:<Log>
    if agent_id and agent_name and agent_ip:
        protocol_location = '[' + agent_id + \
            '] (' + agent_name + ') ' + agent_ip + '->' + location
    else:
        protocol_location = location

    event_header = chr(protocol_queue) + ':' + protocol_location + ':'

    return event_header


def get_queue_from_module(module):
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
        'virustotal': 00,       # TODO check queue
        'dbsync': 53,
        'fim': 56,
        'hostinfo': 51,
        'rootcheck': 57,
        'sca': 112,
        'syscollector': 100,
        'upgrade': 117,
        'remote-syslog': 50
    }

    # Getting queue according to module
    return modules_queue[module]


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
            # print('sending {!r}'.format(event))
            sock.sendall(event.encode())

    # closing socket
    finally:
        sock.close()


def save_to_file(list_events, output_file_name):
    # append content and creates file if it doesn't exist
    with open(output_file_name, 'a+') as f:
        for event in list_events:
            f.write(event + '\n')
        f.close()


def append_header_to_events(header, list_events):
    final_events = []
    for single_event in list_events:
        event = header + single_event
        final_events.append(event)
    return final_events


def get_events():
    final_events = []
    for line in sys.stdin.read().splitlines():
        if len(line) == 0:
            break
        final_events.append(line)
    return final_events


def main():
    parser = argparse.ArgumentParser()

    # Agent specific fields
    parser.add_argument('-i', '--agent-id', help=f'Agent ID for event filling',
                        type=str, default='001', dest='agent_id')
    parser.add_argument('-n', '--agent-name', help=f'Agent name for events filling',
                        type=str, default='agent-001', dest='agent_name')
    parser.add_argument('-a', '--agent-ip', help=f'Agent ip address for events filling',
                        type=str, default='any', dest='agent_ip')

    parser.add_argument(
        '--dry-run', help=f'events wont be sent to the engine socket', action='store_false', dest='must_send')
    parser.add_argument(
        '-e', '--engine-socket', help=f'Where the engine is listening to events',
        default=DEFAULT_ENGINE_SOCKET, type=str, dest='engine_socket')

    parser.add_argument(
        '-o', '--output', help=f'Output file where the events will be stored, if empty events wont be saved', type=str, default='', dest='output_file')

    subcommands = parser.add_subparsers(dest="source")

    logcollector_command = subcommands.add_parser('logcollector')
    # This should be set on each module, but to avoid repetition
    logcollector_command.add_argument('-L', '--location', help=f'logcollector location wether file path or command',
                                      type=str, dest='location')

    logcollector_subcommand = logcollector_command.add_subparsers(
        dest="module_name")
    # TODO: all the subcommands when implementing more scenarios should register the callbacks
    audit_subcommand = logcollector_subcommand.add_parser('audit')
    command_subcommand = logcollector_subcommand.add_parser('command')
    eventchannel_subcommand = logcollector_subcommand.add_parser(
        'eventchannel')
    eventlog_subcommand = logcollector_subcommand.add_parser('eventlog')
    full_command_subcommand = logcollector_subcommand.add_parser(
        'full_command')
    json_subcommand = logcollector_subcommand.add_parser('json')
    json_subcommand.add_argument('-l', '--labels', help=f'json object added to logcollector json event',
                                 type=str, default="", dest='labels')

    macos_subcommand = logcollector_subcommand.add_parser('macos')
    multi_line_subcommand = logcollector_subcommand.add_parser('multi_line')
    multi_line_regex_subcommand = logcollector_subcommand.add_parser(
        'multi_line_regex')
    mysql_log_subcommand = logcollector_subcommand.add_parser('mysql_log')
    syslog_subcommand = logcollector_subcommand.add_parser('syslog')

    remote_syslog_command = subcommands.add_parser('remote-syslog')
    remote_syslog_command.add_argument('-R', '--remote_ip', help=f'remote-syslog remote IP, random IP as default',
                                       type=str, dest='remote_ip')
    remote_syslog_subcommand = remote_syslog_command.add_subparsers(
        dest="module_name")

    args = parser.parse_args()

    add_labels = False
    if args.source == 'logcollector':
        if args.module_name == 'eventlog' or args.module_name == 'eventchannel':
            module_name = args.module_name
            location = args.module_name
        elif args.module_name == 'json':
            if not args.location:
                print("When using module '{}' location cannot be empty.".format(
                    args.module_name))
                exit(1)
            module_name = args.module_name
            location = args.location
            if len(args.labels) != 0:
                add_labels = True
        elif args.module_name == 'audit' or args.module_name == 'command' or args.module_name == 'full_command' or args.module_name == 'macos' or args.module_name == 'multi_line' or args.module_name == 'multi_line_regex' or args.module_name == 'mysql_log' or args.module_name == 'syslog':
            if not args.location:
                print("When using module '{}' location cannot be empty.".format(
                    args.module_name))
                exit(1)
            location = args.location
            module_name = args.module_name
        elif len(args.module_name) == 0:
            print("module is a mandatory parameter.")
            exit(1)
        else:
            print("Non available module.")
            exit(1)
    elif args.source == 'remote-syslog':
        args.agent_id = ''
        args.agent_name = ''
        args.agent_ip = ''
        if not args.remote_ip:
            print("When using module '{}' remote_ip cannot be empty.".format(
                args.module_name))
            exit(1)
        location = args.remote_ip
        module_name = 'remote-syslog'
    elif len(args.source) == 0:
        print("source is a mandatory parameter.")
        exit(1)
    else:
        print("Not Yet Implemented.")
        exit(1)

    list_events = get_events()
    if add_labels:
        list_events = add_to_event_object(list_events, args.labels)
    header = create_header(get_queue_from_module(
        module_name), args.agent_id, args.agent_name, args.agent_ip, location)
    list_events = append_header_to_events(header, list_events)

    if len(list_events) != 0:
        if args.must_send:
            socket = args.engine_socket
            send_event(list_events, socket)
        if len(args.output_file) != 0:
            save_to_file(list_events, args.output_file)
        else:
            for event in list_events:
                print(event)


if __name__ == "__main__":
    main()
