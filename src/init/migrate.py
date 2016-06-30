#!/usr/bin/env python

# Data migration utility for Wazuh HIDS.
# Copyright 2016 Wazuh, Inc. <info@wazuh.com>
# June 30, 2016.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

import sys
import os
import sqlite3
from getopt import getopt, GetoptError

OSSEC_PATH = '/var/ossec'
SQL_PATH = 'ossec.sql'
DB_PATH = OSSEC_PATH + '/var/db/database.sqlite'
KEYS_PATH = OSSEC_PATH + '/etc/client.keys'

def create(dbpath=DB_PATH, sqlpath=SQL_PATH, force=False):
    '''Create database file, if it doesn't exists.
       If force=True and the DB already exists, it is first deleted.
       Returns True if the database was successfully created.'''

    if os.path.isfile(dbpath):
        if force:
            print("INFO: Removing database '{0}'.".format(dbpath))
            os.remove(dbpath)

            try:
                os.remove(dbpath + '-shm')
            except OSError:
                pass

            try:
                os.remove(dbpath + '-wal')
            except OSError:
                pass
        else:
            sys.stderr.write("ERROR: Database '{0}' already exists.\n".format(dbpath))
            return False

    try:
        script = open(sqlpath, 'r')
        conn = sqlite3.connect(dbpath)
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(sqlpath, error.strerror))
        return False
    except sqlite3.OperationalError as error:
        sys.stderr.write("ERROR: Creating '{0}': {1}.\n".format(dbpath, error))
        return False

    cur = conn.cursor()
    cur.executescript(script.read())
    conn.close()
    return True

def insert_agents(dbpath=DB_PATH):
    '''Insert the registered agents into the database.'''

    agents = open(KEYS_PATH, 'r')
    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()
    sql = "INSERT INTO agent (id, name, ip, key, os, version, enabled) values (?, ?, ?, ?, ?, ?, ?)"
    cur.execute('BEGIN')

    for agent in agents:
        id, name, ip, key = agent.split()

        if id[0] in '# ':
            id = id[1:]

            try:
                int(id)
            except ValueError:
                continue

        if name[0] in '!#':
            name = name[1:]
            enabled = 0
        else:
            enabled = 1

        try:
            with open('{0}/queue/agent-info/{1}-{2}'.format(OSSEC_PATH, name, ip), 'r') as f:
                os, version = f.read().split(' - ')
        except IOError:
            os = version = None

        try:
            cur.execute(sql, (id, name, ip, key, os, version,enabled))
        except sqlite3.IntegrityError:
            sys.stderr.write("WARN: Agent '{0}' already exists.\n".format(id))

    conn.commit()
    conn.close()

def _fim_decode(line):
    '''Decode a line from syscheck into a tuple'''

    event = 'added' if line[:3] == '+++' else 'modified'
    parts = line[3:].split(' ', 2)
    date = parts[1][1:]
    path = parts[2].decode('utf_8')

    if parts[0] == '-1':
        return path, 'deleted', date, None, None, None, None, None, None

    size, perm, uid, gid, md5, sha1 = parts[0].split(':')

    size = int(size)
    perm = int(perm)
    uid = int(uid)
    gid = int(gid)

    if size < 0:
        event = 'deleted'

    return path, event, date, size, perm, uid, gid, md5, sha1

def _fim_insert_file(cursor, id_agent, dbfile, filetype):
    '''Inserts one file from syscheck into the database'''

    try:
        with open(dbfile, 'r') as syscheck:
            for line in syscheck:
                path, event, date, size, perm, uid, gid, md5, sha1 = _fim_decode(line)
                row = cursor.execute('SELECT id FROM fim_file WHERE id_agent = ? AND path = ?', (id_agent, path)).fetchone()

                if row:
                    id_file = row[0]
                else:
                    cursor.execute('INSERT INTO fim_file (id_agent, path, type) VALUES (?, ?, ?)', (id_agent, path, filetype))
                    id_file = cursor.lastrowid

                cursor.execute('INSERT INTO fim_event (id_file, event, date, size, perm, uid, gid, md5, sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (id_file, event, date, size, perm, uid, gid, md5, sha1))
    except IOError:
        sys.stderr.write("WARN: No such file '{0}'.\n".format(dbfile))

def insert_fim(dbpath=DB_PATH):
    '''Insert the file integrity monitoring events into database.
       It requires that table agents has been filled'''

    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    cursor.execute('BEGIN')

    for id_agent, name, ip, os in conn.cursor().execute('SELECT id, name, ip, os FROM agent WHERE enabled = 1'):
        path = OSSEC_PATH + '/queue/syscheck/'
        path += '({0}) {1}->syscheck'.format(name, ip) if name else 'syscheck'
        _fim_insert_file(cursor, id_agent, path, 'file')

        if os and 'Windows' in os:
            path = '{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(OSSEC_PATH, name, ip)
            _fim_insert_file(cursor, id_agent, path, 'registry')

    conn.commit()
    conn.close()

def insert_pm(dbpath=DB_PATH):
    '''Insert the policy monitoring events into database.
       It requires that table agents has been filled.'''

    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()
    cursor.execute('BEGIN')

    for id_agent, name, ip, os in conn.cursor().execute('SELECT id, name, ip, os FROM agent WHERE enabled = 1'):
        path = OSSEC_PATH + '/queue/rootcheck/'
        path += '({0}) {1}->rootcheck'.format(name, ip) if name else 'rootcheck'

        try:
            with open(path, 'r') as rootcheck:
                for line in rootcheck:
                    if line[0] == '!':
                        line = line[1:]
                        i = line.find('!')
                        j = line.find(' ')
                        date_last = line[:i]
                        date_first = line[i+1:j]
                        log = line[j+1:]
                    else:
                        date_first = date_last = None
                        log = line

                    cursor.execute("INSERT INTO pm_event (id_agent, date_first, date_last, log) VALUES (?, ?, ?, ?)", (id_agent, date_first, date_last, log))

        except IOError:
            sys.stderr.write("WARN: No such file '{0}'.\n".format(path))

    conn.commit()
    conn.close()

def _print_help():
    print '''
    Data migration utility for Wazuh HIDS

    Options:
        -f          Remove database if it exists.
        -h, --help  Prints this help.
        -p <path>   Changes the default path for database.
        -s <path>   Changes the default path of the source SQL file.

    Copyright 2016 Wazuh, Inc. <info@wazuh.com>
    '''

if __name__ == '__main__':
    dbpath = DB_PATH
    sqlpath = SQL_PATH
    force = False

    try:
        for opt in getopt(sys.argv[1:], 'fhp:s:', '')[0]:
            if opt[0] == '-p':
                dbpath = opt[1]
            elif opt[0] == '-f':
                force = True
            elif opt[0] == '-s':
                sqlpath = opt[1]
            elif opt[0] in ('-h', '--help'):
                _print_help()
                sys.exit(0)

    except GetoptError as error:
        sys.stderr.write("ERROR: {0}.\n".format(error.msg))
        _print_help()
        sys.exit(1)

    if create(dbpath, sqlpath, force):
        insert_agents(dbpath)
        insert_fim(dbpath)
        insert_pm(dbpath)
    else:
        sys.exit(1)
