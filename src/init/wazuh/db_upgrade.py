#!/usr/bin/env python

# Database support for Wazuh HIDS.
# Copyright 2018 Wazuh, Inc. <info@wazuh.com>
# September 28, 2018.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

import os
import sys
import pwd
import sqlite3
from getopt import getopt, GetoptError
from os.path import isfile
import socket
import struct

_ossec_path = '/var/ossec'
_verbose = False
_debug = False
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

    for agent in agents:
        try:
            id, name, ip, key = agent.split()
        except ValueError:
            sys.stderr.write("ERROR: Corrupt line at 'client.keys'.\n")
            continue

        if id[0] in '# ' or name[0] == '!':
            continue

        try:
            int(id)
        except ValueError:
            continue

        yield (int(id), name, ip)

    agents.close()


def _fim_decode(line):
    '''Decode a line from syscheck into a tuple'''

    line = line[:-1].split('!')
    if len(line) == 2:
        fim = line[0][3:-1]
        parsed = line[1][1:].split(' ', 1)
        if len(parsed) == 2:
            timestamp = parsed[0]
            path = parsed[1]
        else:
            raise Exception("Couldn't decode line at syscheck database.")
    else:
        raise Exception("Couldn't decode line at syscheck database.")

    return fim, timestamp, path


def check_file_entry(agent, file, wdb_socket):
    # Send message
    msg = "agent {0} syscheck load {1}".format(str(agent).zfill(3), file)
    msg = struct.pack('<I', len(msg)) + msg.encode()
    s.send(msg)

    # Receive response
    try:
        # Receive data length
        data_size = s.recv(4)
        data_size = struct.unpack('<I',data_size[0:4])[0]
        data = s.recv(data_size,socket.MSG_WAITALL).decode()

    except IndexError:
        raise Exception("Data could not be received")

    if data.startswith('ok'):
        return True
    else:
        return False


def insert_fim(agent, fim_array, wdb_socket):

    # Send message
    msg = "agent {0} syscheck save file {1}!{2}:0 {3}".format(str(agent).zfill(3), fim_array[0], fim_array[1], fim_array[2])
    if _debug:
        print(msg)
    msg = struct.pack('<I', len(msg)) + msg.encode()
    s.send(msg)

    # Receive response
    try:
        # Receive data length
        data_size = s.recv(4)
        data_size = struct.unpack('<I',data_size[0:4])[0]
        data = s.recv(data_size,socket.MSG_WAITALL).decode()

    except IndexError:
        raise Exception("Data could not be received")

    if data.startswith('ok'):
        return 1, 'ok'
    else:
        return 0, rec_msg


def _print_help():
    print('''
    FIM database upgrade utility for Wazuh

    Options:
        -p <path>   Changes the default installation path.
        -f          Force file insertion if it already exists.
        -h, --help  Prints this help.
        -v          Verbose mode.
        -d          Debug mode.

    Copyright 2018 Wazuh, Inc. <info@wazuh.com>
    ''')

if __name__ == '__main__':

    try:
        for opt in getopt(sys.argv[1:], 'p:dfh:v', '')[0]:
            if opt[0] == '-f':
                _force = True
            elif opt[0] == '-d':
                _debug = True
                _verbose = True
            elif opt[0] == '-p':
                _ossec_path = opt[1]
            elif opt[0] in ('-h', '--help'):
                _print_help()
                sys.exit(0)
            elif opt[0] == '-v':
                _verbose = True

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
        raise Exception("Cannot connect to socket: {0}".format(str(e)))

    if _verbose:
        print("Connected to WazuhDB socket ({0})".format(_wdb_socket))

    for agt in _get_agents():
        count = 0
        dbfile = "{0}/({1}) {2}->syscheck".format(_syscheck_dir,agt[1],agt[2])
        if _verbose:
            print("Reading agent ({0}) syscheck DB.".format(str(agt[0]).zfill(3)))
        with open(dbfile, 'r') as syscheck:
            for line in syscheck:
                if not line.startswith('#'):
                    decoded = _fim_decode(line)
                    if not _force:
                        if not check_file_entry(agt[0], decoded[2], s):
                            res = insert_fim(agt[0], decoded, s)
                    else:
                        res = insert_fim(agt[0], decoded, s)
                        if res[0]:
                            count = count + 1
                        else:
                            print("ERR: {0}".format(res[1]))
        if _verbose:
            print("Added {0} file entries for agent {1}.".format(count, str(agt[0]).zfill(3)))

        # Registry files
        regfile = "{0}/({1}) {2}->syscheck-registry".format(_syscheck_dir,agt[1],agt[2])
        if os.path.isfile(regfile):
            if _verbose:
                print("Reading agent ({0}) syscheck-registry DB.".format(str(agt[0]).zfill(3)))
            with open(dbfile, 'r') as syscheck:
                for line in syscheck:
                    if not line.startswith('#'):
                        decoded = _fim_decode(line)
                        if not _force:
                            if not check_file_entry(agt[0], decoded[2], s):
                                res = insert_fim(agt[0], decoded, s)
                        else:
                            res = insert_fim(agt[0], decoded, s)
                            if res[0]:
                                count = count + 1
                            else:
                                print("ERR: {0}".format(res[1]))
            if _verbose:
                print("Added {0} registry entries for agent {1}.".format(count, str(agt[0]).zfill(3)))

    s.close()
