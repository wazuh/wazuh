#!/usr/bin/env python

# Database support for Wazuh HIDS.
# Copyright 2018 Wazuh, Inc. <info@wazuh.com>
# September 28, 2018.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

import sys
import sqlite3
from getopt import getopt, GetoptError
from os.path import isfile
import socket
import struct
import logging

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', \
                    level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

_ossec_path = '/var/ossec'
_verbose = True
_force = False

# Check minimum version of SQLite module: 2.6.0

if sqlite3.version < '2.6.0':
    if __name__ == '__main__':
        sys.stderr.write("ERROR: Required minimal version of SQLite module 2.6.0\n" + \
                         "Please update the module version or get Python 2.7\n")
        sys.exit(1)
    else:
        raise ImportError("Minimal version of SQLite module 2.6.0 required")


def _get_agents():
    try:
        agents = open(_keys_path)
    except IOError:
        return

    agents_list = []
    for agent in agents:
        try:
            agent_id, name, ip, key = agent.split()
        except ValueError:
            sys.stderr.write("ERROR: Corrupt line at 'client.keys'.\n")
            continue

        if agent_id[0] in '# ' or name[0] == '!':
            continue

        try:
            int(agent_id)
        except ValueError:
            continue

        agents_list.append([int(agent_id), name, ip])

    agents.close()

    return agents_list


def _fim_decode(fline):
    # Decode a line from syscheck into a tuple
    readed = fline
    fline = fline[3:-1].split('!')
    if len(fline) == 2:
        fim = fline[0][:-1]
        parsed = fline[1].split(' ', 1)
        if len(parsed) == 2:
            timestamp = parsed[0]
            path = parsed[1]
        else:
            logging.debug("Error parsing line: {0}".format(readed))
            logging.error("Couldn't decode line at syscheck database.")
    else:
        logging.error("Couldn't decode line at syscheck database.")

    return fim, timestamp, path


def check_file_entry(agent, cfile, wdb_socket):
    # Send message
    msg = "agent {0} syscheck load {1}".format(str(agent).zfill(3), cfile)
    try:
        msg = msg.encode().decode('utf-8')
    except UnicodeDecodeError:
        msg = msg.decode('utf-8')

    logging.debug(msg)
    msg = msg.encode('utf-8')
    msg = struct.pack('<I', len(msg)) + msg
    wdb_socket.send(msg)

    # Receive response
    try:
        # Receive data length
        data_size = wdb_socket.recv(4)
        data_size = struct.unpack('<I', data_size[0:4])[0]
        data = wdb_socket.recv(data_size, socket.MSG_WAITALL).decode()
    except IndexError:
        raise Exception("Data could not be received")

    if data.startswith('ok'):
        return True
    else:
        return False


def insert_fim(agent, fim_array, stype, wdb_socket):
    # Send message
    msg = "agent {0} syscheck save {1} {2}!0:{3} {4}".format(str(agent).zfill(3), stype, fim_array[0], fim_array[1], fim_array[2])
    try:
        msg = msg.encode().decode('utf-8')
    except UnicodeDecodeError:
        msg = msg.decode('utf-8')

    logging.debug(msg)
    msg = msg.encode('utf-8')
    msg = struct.pack('<I', len(msg)) + msg
    wdb_socket.send(msg)

    # Receive response
    try:
        # Receive data length
        data_size = wdb_socket.recv(4)
        data_size = struct.unpack('<I', data_size[0:4])[0]
        data = wdb_socket.recv(data_size, socket.MSG_WAITALL).decode()
    except IndexError:
        raise Exception("Data could not be received")

    if data.startswith('ok'):
        return 1, 'ok'
    else:
        return 0, data


def _print_help():
    print('''
    FIM database upgrade tool for Wazuh

    Options:
        -p <path>   Change the default installation path.
        -f          Force insertion.
        -q          Quiet mode.
        -d          Debug mode.
        -h          Prints this help.

    Copyright 2018 Wazuh, Inc. <info@wazuh.com>
    ''')


if __name__ == '__main__':

    try:
        for opt in getopt(sys.argv[1:], 'p:dfqh', '')[0]:
            if opt[0] == '-f':
                _force = True
            elif opt[0] == '-d':
                logging.getLogger().setLevel(logging.DEBUG)
            elif opt[0] == '-p':
                _ossec_path = opt[1]
            elif opt[0] == '-h':
                _print_help()
                sys.exit(0)
            elif opt[0] == '-q':
                _verbose = False

    except GetoptError as error:
        sys.stderr.write("ERROR: {0}.\n".format(error.msg))
        _print_help()
        sys.exit(1)

    _wdb_socket = _ossec_path + '/queue/db/wdb'
    _syscheck_dir = _ossec_path + '/queue/syscheck'
    _keys_path = _ossec_path + '/etc/client.keys'

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(_wdb_socket)
    except Exception as e:
        logging.error("Cannot connect to socket: {0}".format(str(e)))
        sys.exit(1)

    if _verbose:
        logging.info("Connected to WazuhDB socket ({0})".format(_wdb_socket))

    # Manager DB
    count = 0
    mandbfile = "{0}/syscheck".format(_syscheck_dir)
    if isfile(mandbfile):
        if _verbose:
            logging.info("Upgrading FIM database for manager...")
        with open(mandbfile, 'r') as syscheck:
            for line in syscheck:
                if not line.startswith('#'):
                    decoded = _fim_decode(line)
                    if not _force:
                        if not check_file_entry(0, decoded[2], s):
                            res = insert_fim(0, decoded, 'file', s)
                    else:
                        res = insert_fim(0, decoded, 'file', s)
                        if res[0]:
                            count = count + 1
                        else:
                            logging.error("{0}".format(res[1]))
        if _verbose:
            logging.info("Added {0} file entries in manager database.".format(count))

    agents = _get_agents()
    total_agents = len(agents)
    pos = 1
    for agt in agents:
        # Monitorized files
        count = 0
        dbfile = "{0}/({1}) {2}->syscheck".format(_syscheck_dir, agt[1], agt[2])
        if isfile(dbfile):
            if _verbose:
                logging.info("[{0}/{1}] Upgrading FIM dabase for agent '{2}'...".format(pos, total_agents, str(agt[0]).zfill(3)))
            with open(dbfile, 'r') as syscheck:
                for line in syscheck:
                    if not line.startswith('#'):
                        decoded = _fim_decode(line)
                        if not _force:
                            if not check_file_entry(agt[0], decoded[2], s):
                                res = insert_fim(agt[0], decoded, 'file', s)
                        else:
                            res = insert_fim(agt[0], decoded, 'file', s)
                            if res[0]:
                                count = count + 1
                            else:
                                logging.error("{0}".format(res[1]))
            if _verbose:
                logging.info("[{0}/{1}] Added {2} file entries in agent '{3}' database.".format(pos, total_agents, count, str(agt[0]).zfill(3)))

        # Registry files
        count = 0
        regfile = "{0}/({1}) {2}->syscheck-registry".format(_syscheck_dir, agt[1], agt[2])
        if isfile(regfile):
            if _verbose:
                logging.info("[{0}/{1}] Upgrading FIM dabase (syscheck-registry) for agent '{2}'...".format(pos, total_agents, str(agt[0]).zfill(3)))
            with open(regfile, 'r') as syscheck:
                for line in syscheck:
                    if not line.startswith('#'):
                        decoded = _fim_decode(line)
                        if not _force:
                            if not check_file_entry(agt[0], decoded[2], s):
                                res = insert_fim(agt[0], decoded, 'registry', s)
                        else:
                            res = insert_fim(agt[0], decoded, 'registry', s)
                            if res[0]:
                                count = count + 1
                            else:
                                logging.error("{0}".format(res[1]))
            if _verbose:
                logging.info("[{0}/{1}] Added {2} registry entries in agent '{3}' database.".format(pos, total_agents, count, str(agt[0]).zfill(3)))
        pos = pos + 1

    s.close()
    if _verbose:
        logging.info("Finished.")
