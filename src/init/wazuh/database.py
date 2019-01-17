#!/usr/bin/env python

# Database support for Wazuh HIDS.
# Copyright (C) 2015-2019, Wazuh Inc. <info@wazuh.com>
# June 30, 2016.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

import os
import sys
import pwd
import sqlite3
from getopt import getopt, GetoptError
from socket import gethostname
from os.path import isfile

_ossec_user = 'ossec'
_ossec_path = '/var/ossec'
_src_dir = 'src/wazuh_db'
_dest_dir = _ossec_path + '/var/db'
_keys_path = _ossec_path + '/etc/client.keys'
_prof_name = '/.profile.db'
_agent_dir = '/agents'
_agent_pattern = '/{0:03}-{1}.db'

_db_perm = 0660
_dir_mode = 0770
_verbose = False

# Check minimum version of SQLite module: 2.6.0

if sqlite3.version < '2.6.0':
    if __name__ == '__main__':
        sys.stderr.write("ERROR: Required minimal version of SQLite module 2.6.0\n" + \
                         "Please update the module version or get Python 2.7\n")
        sys.exit(1)
    else:
        raise ImportError("Minimal version of SQLite module 2.6.0 required")

# Get ID of group ossec

try:
    _ossec_gid = pwd.getpwnam(_ossec_user).pw_gid
except KeyError:
    if __name__ == '__main__':
        sys.stderr.write("ERROR: OSSEC group not found. Please install OSSEC before run this module.\n")
        sys.exit(1)
    else:
        raise ImportError("OSSEC group not found.")

def create_profile(destdir=_dest_dir, srcdir=_src_dir, force=False):
    sqlagents = srcdir + '/schema_agents.sql'
    destprofile = destdir + _prof_name

    if os.path.isfile(destprofile):
        if force:
            os.remove(destprofile)
        else:
            sys.stderr.write("WARN: Agent profile already exists.\n")
            return False

    try:
        script = open(sqlagents, 'r').read()
        conn = sqlite3.connect(destprofile)
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(sqlagents, error.strerror))
        return False
    except sqlite3.OperationalError as error:
        sys.stderr.write("ERROR: Creating '{0}': {1}.\n".format(destprofile, error))
        return False

    cursor = conn.cursor()
    cursor.executescript(script)
    conn.close()
    os.chmod(destprofile, _db_perm)
    os.chown(destprofile, 0, _ossec_gid)
    return True

def get_agents():
    try:
        agents = open(_keys_path)
    except IOError:
        return

    yield (0, gethostname(), None)

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

def create_agent(id, name, destdir, force):
    profile = destdir + _prof_name
    destagent = destdir + _agent_dir + _agent_pattern.format(id, 'localhost' if id == 0 else name)

    if isfile(destagent):
        if force:
            os.remove(destagent)
        else:
            sys.stderr.write("WARN: File '{0}' already exists.\n".format(destagent))
            return False

    try:
        source = open(profile, 'rb')
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(profile, error.strerror))
        return False

    try:
        dest = open(destagent, 'wb')
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(destagent, error.strerror))
        return False

    dest.write(source.read())
    source.close()
    dest.close()
    os.chmod(destagent, _db_perm)
    os.chown(destagent, 0, _ossec_gid)

    return True


def _fim_decode(line):
    '''Decode a line from syscheck into a tuple'''

    event = 'added' if line[:3] == '+++' else 'modified'
    parts = line[3:].split(' ', 2)
    date = parts[1][1:]
    path = parts[2].decode('utf_8')

    if parts[0] == '-1':
        return path, 'deleted', date, None, None, None, None, None, None, None, None, None, None

    csum = parts[0].split(':')

    if len(csum) >= 6:
        size, perm, uid, gid = [int(x) for x in csum[:4]]
        md5, sha1 = csum[4:6]
        perm = '{0:06o}'.format(perm)

        if len(csum) == 6:
            uname = gname = mtime = inode = None
        elif len(csum) == 10:
            uname, gname = csum[6:8]
            mtime, inode = [int(x) for x in csum[8:10]]
        else:
            raise Exception("Couldn't decode line at syscheck database.")

    else:
        raise Exception("Couldn't decode line at syscheck database.")

    if size < 0:
        event = 'deleted'

    return path, event, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode

def _fim_insert_file(cursor, dbfile, filetype):
    '''Inserts one file from syscheck into the database'''

    try:
        with open(dbfile, 'r') as syscheck:
            for line in syscheck:
                path, event, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode = _fim_decode(line[:-1])
                row = cursor.execute('SELECT id FROM fim_file WHERE type = ? AND path = ?', (filetype, path)).fetchone()

                if row:
                    id_file = row[0]
                else:
                    cursor.execute('INSERT INTO fim_file (path, type) VALUES (?, ?)', (path, filetype))
                    id_file = cursor.lastrowid

                cursor.execute("INSERT INTO fim_event (id_file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode) VALUES (?, ?, datetime(?, 'unixepoch', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch', 'localtime'), ?)", (id_file, event, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode))
    except IOError:
        sys.stderr.write("WARN: No such file '{0}'.\n".format(dbfile))

def insert_fim(cursor, id, name, ip):
    '''Insert the file integrity monitoring events into database.'''

    path = _ossec_path + '/queue/syscheck/'
    path += '({0}) {1}->syscheck'.format(name, ip) if id else 'syscheck'

    if _verbose:
        print("INFO: Inserting syscheck database of agent '{0}'.".format(id_agent))

    _fim_insert_file(cursor, path, 'file')
    path = '{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(_ossec_path, name, ip)

    if isfile(path):
        _fim_insert_file(cursor, path, 'registry')

def _pm_pcidss(string):
    '''Get PCI_DSS requirement from log string '''

    i = string.find('{PCI_DSS: ')

    if i >= 0:
        string = string[i + 10:]
        i = string.find('}')

        if i >= 0:
            return string[:i]

    return None

def _pm_cis(string):
    '''Get CIS requirement from log string '''

    i = string.find('{CIS: ')

    if i >= 0:
        string = string[i + 6:]
        i = string.find('}')

        if i >= 0:
            return string[:i]

    return None

def insert_pm(cursor, id, name, ip):
    '''Insert the policy monitoring events into database.'''

    path = _ossec_path + '/queue/rootcheck/'
    path += '({0}) {1}->rootcheck'.format(name, ip) if id else 'rootcheck'

    if _verbose:
        print("INFO: Inserting rootcheck database of agent '{0}'.".format(id_agent))

    try:
        with open(path, 'r') as rootcheck:
            for line in rootcheck:
                if line[0] == '!':
                    line = line[1:]
                    i = line.find('!')
                    j = line.find(' ')
                    date_last = line[:i]
                    date_first = line[i+1:j]
                    log = line[j+1:-1].decode('utf_8')
                else:
                    date_first = date_last = None
                    log = line

                cursor.execute("INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (datetime(?, 'unixepoch', 'localtime'), datetime(?, 'unixepoch', 'localtime'), ?, ?, ?)", (date_first, date_last, log, _pm_pcidss(log), _pm_cis(log)))

    except IOError:
        sys.stderr.write("WARN: No such file '{0}'.\n".format(path))

def create_db(destdir=_dest_dir, srcdir=_src_dir, force=False):
    create_profile(destdir, srcdir, force)
    destagents = destdir + _agent_dir + _agent_pattern

    for id, name, ip in get_agents():
        if create_agent(id, 'localhost' if id == 0 else name, destdir, force):
            destagent = destagents.format(id, 'localhost' if id == 0 else name)
            conn = sqlite3.connect(destagent)
            cursor = conn.cursor()
            cursor.execute('BEGIN')

            insert_fim(cursor, id, name, ip)
            insert_pm(cursor, id, name, ip)

            if _verbose:
                print("INFO: Committing changes...")

            conn.commit()

            if _verbose:
                print("INFO: Data commited.")

            conn.close()

def _print_help():
    print '''
    FIM/PM database creation utility for Wazuh HIDS

    Options:
        -d <path>   Changes the default destination path for database.
        -f          Remove database if it exists.
        -h, --help  Prints this help.
        -s <path>   Changes the default path of the source SQL files.
        -v          Verbose mode.

    Copyright 2016 Wazuh, Inc. <info@wazuh.com>
    '''

if __name__ == '__main__':
    destdir = _dest_dir
    srcdir = _src_dir
    force = False

    try:
        for opt in getopt(sys.argv[1:], 'd:fhs:v', '')[0]:
            if opt[0] == '-d':
                destdir = opt[1]
            elif opt[0] == '-f':
                force = True
            elif opt[0] == '-s':
                srcdir = opt[1]
            elif opt[0] in ('-h', '--help'):
                _print_help()
                sys.exit(0)
            elif opt[0] == '-v':
                _verbose = True

    except GetoptError as error:
        sys.stderr.write("ERROR: {0}.\n".format(error.msg))
        _print_help()
        sys.exit(1)

    if create_db(destdir, srcdir, force):
        insert_fim(destdir)
        insert_pm(destdir)
    else:
        sys.exit(1)
