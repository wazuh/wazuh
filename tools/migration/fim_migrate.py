#!/usr/bin/env python

# Database support for Wazuh HIDS.
# Copyright (C) 2015, Wazuh Inc. <info@wazuh.com>
# September 28, 2018.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.
# Revision 11/13/2018

# Import modules for command-line parsing, file I/O, socket communication, logging, and JSON parsing.
import sys
from getopt import getopt, GetoptError
from os.path import isfile
import os
import socket
import struct
import logging
from json import loads

# Configure logging to display timestamp, log level, and message in a consistent format
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', \
                    level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

# If the terminal supports 256 colors, use colored log levels; otherwise, use plain text.
if os.environ['TERM'] == "xterm-256color":
    logging.addLevelName(logging.ERROR, '[\033[31mERROR\033[0m]')
    logging.addLevelName(logging.WARNING, '[\033[33mWARNING\033[0m]')
    logging.addLevelName(logging.INFO, '[\033[32mINFO\033[0m]')
    logging.addLevelName(logging.DEBUG, '[\033[34mDEBUG\033[0m]')
else:
    logging.addLevelName(logging.ERROR, '[ERROR]')
    logging.addLevelName(logging.WARNING, '[WARNING]')
    logging.addLevelName(logging.INFO, '[INFO]')
    logging.addLevelName(logging.DEBUG, '[DEBUG]')

# Default paths and flags
_ossec_path = '/var/ossec'
_verbose = True
_force = False

# Function to retrieve the list of agents from the client.keys file.
def _get_agents():
    try:
        agents_file = open(_keys_path)
    except IOError:
        return

    # Read the agents from the client.keys file
    agents_list = []
    for agent in agents_file:
        try:
            agent_id, name, ip, key = agent.split()
        except ValueError:
            sys.stderr.write("ERROR: Corrupt line at 'client.keys'.\n")
            continue

        # Skip comments and invalid entries
        if agent_id[0] in '# ' or name[0] == '!':
            continue

        # Validate agent_id is an integer
        try:
            int(agent_id)
        except ValueError:
            continue

        # Append the agent information to the list
        agents_list.append([int(agent_id), name, ip])

    agents_file.close()

    return agents_list

# Function to decode a line from the syscheck database into a tuple.
def _fim_decode(fline):
    fim = None
    timestamp = None
    path = None
    read = fline
    fline = fline[3:-1].split(b' !')
    # Check if the line has two parts: fim and the rest
    if len(fline) == 2:
        fim = fline[0]
        # Delete invalid content "!:::::::"
        fim = fim.split(b'!')[0]
        parsed = fline[1].split(b' ', 1)
        # Check if the line has a timestamp and path
        if len(parsed) == 2:
            timestamp = parsed[0]
            path = parsed[1]
        # If the line has no timestamp, assume it is the current time
        else:
            logging.error("Couldn't decode line at syscheck database.")
            logging.debug("Error parsing line: {0}".format(read))
            return None
    # If the line has no fim, it is invalid
    else:
        logging.error("Couldn't decode line at syscheck database.")
        logging.debug("Error parsing line: {0}".format(read))
        return None

    return fim, timestamp, path

# Function to check if a file entry exists in the database.
def check_file_entry(agent, cfile, wdb_socket):
    # Send message
    msg = "agent {0} sql select count(*) from fim_entry where file='".format(str(agent).zfill(3)).encode()
    msg = msg + cfile + b"';"
    logging.debug(msg)
    msg = struct.pack('<I', len(msg)) + msg
    wdb_socket.send(msg)

    # Receive response
    try:
        # Receive data length
        data_size = wdb_socket.recv(4)
        data_size = struct.unpack('<I', data_size[0:4])[0]
        data = wdb_socket.recv(data_size, socket.MSG_WAITALL).decode()
        response=data.split(' ')[1]
        if not data.startswith('ok'):
            logging.debug(response)
            return True
        json_data = loads(response)
    # Handle case where data could not be received
    except IndexError:
        raise Exception("Data could not be received")

    # Check if the response indicates success and if the count is zero
    if data.startswith('ok'):
        if json_data[0]['count(*)'] == 0:
            return False
        else:
            return True
    else:
        return False

# Function to insert a file entry into the database.
def insert_fim(agent, fim_array, stype, wdb_socket):
    # Send message
    msg = "agent {0} syscheck save {1} ".format(str(agent).zfill(3), stype).encode()
    msg = msg + fim_array[0] + "!0:".encode() + fim_array[1] + " ".encode() + fim_array[2]
    logging.debug(msg)
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

    # Check if the response indicates success
    if data.startswith('ok'):
        return 1, 'ok'
    else:
        return 0, data

# Function to check if the database has been completed for a specific agent.
def check_db_completed(agent, wdb_socket):
    msg = 'agent {0:03d} syscheck scan_info_get end_scan'.format(agent).encode()
    logging.debug(msg)
    wdb_socket.send(struct.pack('<I', len(msg)) + msg)

    # Receive response
    try:
        size = struct.unpack('<I', wdb_socket.recv(4, socket.MSG_WAITALL))[0]
        data = wdb_socket.recv(size, socket.MSG_WAITALL).decode()
    # Handle case where data could not be received
    except IndexError:
        raise Exception("Data could not be received")

    # Split the response into parts and check if it indicates success
    parts = data.split()
    logging.debug("Received: " + data)
    return len(parts) == 2 and parts[0] == 'ok' and int(parts[1]) != 0

# Function to set the database as completed for a specific agent.
def set_db_completed(agent, mtime, wdb_socket):
    msg = 'agent {0:03d} syscheck scan_info_update first_end {1}'.format(agent, int(mtime)).encode()
    logging.debug(msg)
    wdb_socket.send(struct.pack('<I', len(msg)) + msg)

    # Receive response
    try:
        size = struct.unpack('<I', wdb_socket.recv(4, socket.MSG_WAITALL))[0]
        data = wdb_socket.recv(size, socket.MSG_WAITALL).decode()
    except IndexError:
        raise Exception("Data could not be received")

    # Check if the response indicates success
    logging.debug("Received: " + data)
    return data.startswith('ok')

# Function to print the help message for the script.
def _print_help():
    print('''
    FIM database upgrade tool for Wazuh

    Options:
        -p <path>   Change the default installation path.
        -f          Force insertion.
        -q          Quiet mode.
        -d          Debug mode.
        -h          Prints this help.

    Copyright (C) 2015 Wazuh, Inc. <info@wazuh.com>
    ''')

# Main function to execute the script.
if __name__ == '__main__':

    # Parse command-line arguments
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

    # Handle errors in command-line arguments
    except GetoptError as error:
        sys.stderr.write("ERROR: {0}.\n".format(error.msg))
        _print_help()
        sys.exit(1)

    # Check if the specified path exists
    _wdb_socket = _ossec_path + '/queue/db/wdb'
    _syscheck_dir = _ossec_path + '/queue/syscheck'
    _keys_path = _ossec_path + '/etc/client.keys'

    # Check if the WazuhDB socket exists
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(_wdb_socket)
    except Exception as e:
        logging.error("Cannot connect to socket: {0}".format(str(e)))
        sys.exit(1)

    if _verbose:
        logging.debug("Connected to WazuhDB socket ({0})".format(_wdb_socket))

    # Manager DB
    count = 0
    error = 0
    mandbfile = "{0}/syscheck".format(_syscheck_dir)
    # Check if the manager syscheck database file exists
    if isfile(mandbfile):
        if _verbose:
            logging.info("Upgrading FIM database for manager...")
        with open(mandbfile, 'rb') as syscheck:
            for line in syscheck:
                if not line[0] == b'#':
                    decoded = _fim_decode(line)
                    if not decoded:
                        continue
                    if not _force:
                        if not check_file_entry(0, decoded[2], s):
                            res = insert_fim(0, decoded, 'file', s)
                            if res[0]:
                                count = count + 1
                            else:
                                error = error + 1
                    else:
                        res = insert_fim(0, decoded, 'file', s)
                        if res[0]:
                            count = count + 1
                        else:
                            error = error + 1
                if not count == 0 and count % 10000 == 0:
                    logging.info("{0} file entries processed...".format(count))
        # Log the results of the file entries processing
        if _verbose:
            if error == 0 or count > 0:
                logging.info("Added {0} file entries in manager database.".format(count))
            if error > 0:
                logging.warn("[{0} file entries were not added.".format(error))

    # Check if the checkpoint file exists
    mancptfile = '{0}/.syscheck.cpt'.format(_syscheck_dir)

    # If the checkpoint file exists, set the database as completed
    try:
        mtime = os.stat(mancptfile).st_mtime
        if _verbose:
            logging.info("Setting FIM database for manager as completed...")

        if _force or not check_db_completed(0, s):
            if not set_db_completed(0, mtime, s):
                logging.warn("Cannot set manager database as completed.")
        else:
            logging.debug("Scan end mark already set.")

    # Handle case where the checkpoint file does not exist
    except OSError:
        pass

    # Get the list of agents from the client.keys file
    agents = _get_agents()
    total_agents = len(agents)
    pos = 1
    for agt in agents:
        # Monitorized files
        count = 0
        error = 0
        dbfile = "{0}/({1}) {2}->syscheck".format(_syscheck_dir, agt[1], agt[2])
        # Check if the agent syscheck database file exists
        if isfile(dbfile):
            if _verbose:
                logging.info("[{0}/{1}] Upgrading FIM database for agent '{2}'...".format(pos, total_agents, str(agt[0]).zfill(3)))
            with open(dbfile, 'rb') as syscheck:
                for line in syscheck:
                    if not line[0] == b'#':
                        decoded = _fim_decode(line)
                        if not decoded:
                            continue
                        if not _force:
                            if not check_file_entry(agt[0], decoded[2], s):
                                res = insert_fim(agt[0], decoded, 'file', s)
                                if res[0]:
                                    count = count + 1
                                else:
                                    error = error + 1
                        else:
                            res = insert_fim(agt[0], decoded, 'file', s)
                            if res[0]:
                                count = count + 1
                            else:
                                error = error + 1
                    if not count == 0 and count % 10000 == 0:
                        logging.info("[{0}/{1}] {2} file entries processed...".format(pos, total_agents, count))
            # Log the results of the file entries processing
            if _verbose:
                if error == 0 or count > 0:
                    logging.info("[{0}/{1}] Added {2} file entries in agent '{3}' database.".format(pos, total_agents, count, str(agt[0]).zfill(3)))
                if error > 0:
                    logging.warn("[{0}/{1}] {2} file entries were not added.".format(pos, total_agents, error))
        else:
            logging.warn("[{0}/{1}] Cannot find agent '{2}' FIM database.".format(pos, total_agents, str(agt[0]).zfill(3)))
        # Registry files
        count = 0
        error = 0
        regfile = "{0}/({1}) {2}->syscheck-registry".format(_syscheck_dir, agt[1], agt[2])
        # Check if the agent syscheck-registry database file exists
        if isfile(regfile):
            if _verbose:
                logging.info("[{0}/{1}] Upgrading FIM database (syscheck-registry) for agent '{2}'...".format(pos, total_agents, str(agt[0]).zfill(3)))
            with open(regfile, 'rb') as syscheck:
                for line in syscheck:
                    if not line[0] == b'#':
                        decoded = _fim_decode(line)
                        if not decoded:
                            continue
                        if not _force:
                            if not check_file_entry(agt[0], decoded[2], s):
                                res = insert_fim(agt[0], decoded, 'registry', s)
                                if res[0]:
                                    count = count + 1
                                else:
                                    error = error + 1
                        # If force is enabled, insert the entry regardless of its existence
                        else:
                            res = insert_fim(agt[0], decoded, 'registry', s)
                            if res[0]:
                                count = count + 1
                            else:
                                error = error + 1
                    if not count == 0 and count % 10000 == 0:
                        logging.info("[{0}/{1}] {2} registry entries processed...".format(pos, total_agents, count))
            # Log the results of the registry entries processing
            if _verbose:
                if error == 0 or count > 0:
                    logging.info("[{0}/{1}] Added {2} registry entries in agent '{3}' database.".format(pos, total_agents, count, str(agt[0]).zfill(3)))
                if error > 0:
                    logging.warn("[{0}/{1}] {2} registry entries were not added.".format(pos, total_agents, error))

        # DB complete file
        cptfile = "{0}/.({1}) {2}->syscheck.cpt".format(_syscheck_dir, agt[1], agt[2])

        # Check if the checkpoint file exists
        try:
            mtime = os.stat(cptfile).st_mtime

            # If the checkpoint file exists, set the database as completed
            if _verbose:
                logging.info("Setting FIM database for agent '{0:03d}' as completed...".format(agt[0]))

            # Check if the database is already completed
            if _force or not check_db_completed(agt[0], s):
                if not set_db_completed(agt[0], mtime, s):
                    logging.warn("Cannot set agent '{0:03d}' database as completed.".format(agt[0]))
            else:
                logging.debug("Scan end mark already set.")

        except OSError:
            pass

        # Increment the position counter for the next agent
        pos = pos + 1

    # Close the socket connection
    s.close()
    if _verbose:
        logging.info("Finished.")
