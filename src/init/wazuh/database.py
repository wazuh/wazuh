#!/usr/bin/env python

# Database support for Wazuh HIDS.
# Copyright 2016 Wazuh, Inc. <info@wazuh.com>
# June 30, 2016.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

import os
import sys
import pwd
import sqlite3
from getopt import getopt, GetoptError

_ossec_user = 'ossec'
_ossec_path = '/var/ossec'
_src_dir = 'src/wazuh_db'
_dest_dir = _ossec_path + '/var/db'
_keys_path = _ossec_path + '/etc/client.keys'
_prof_name = '/.profile.db'
_agent_dir = '/agents'
_agent_pattern = '/{0}-{1}.db'
_ossec_gid = pwd.getpwnam(_ossec_user).pw_gid
_db_perm = 0660
_dir_mode = 0770
_verbose = False

def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass

def _create_profile(destdir=_dest_dir, srcdir=_src_dir, force=False):
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

def create(destdir=_dest_dir, srcdir=_src_dir, force=False):
    '''Create database file, if it doesn't exists.
       If force=True and the DB already exists, it is first deleted.
       Returns True if the database was successfully created.'''

    agentdir = destdir + _agent_dir
    destglob = destdir + '/global.db'
    sqlglobal = srcdir +'/schema_global.sql'

    if os.path.isfile(destglob) or (os.path.isdir(agentdir) and os.listdir(agentdir)):
        if force:
            print("INFO: Removing database.")

            if os.path.isfile(destglob):
                os.remove(destglob)

            if os.path.isdir(agentdir):
                for path in os.listdir(agentdir):
                    _remove(agentdir + '/' + path)

        else:
            sys.stderr.write("WARN: Database already exists.\n")
            return False

    if _verbose:
        print("INFO: Creating database schema.")

    if not os.path.isdir(agentdir):
        os.mkdir(agentdir, _dir_mode)
        os.chown(agentdir, 0, _ossec_gid)

    try:
        script = open(sqlglobal, 'r')
        conn = sqlite3.connect(destglob)
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(sqlglobal, error.strerror))
        return False
    except sqlite3.OperationalError as error:
        sys.stderr.write("ERROR: Creating '{0}': {1}.\n".format(destglob, error))
        return False

    cur = conn.cursor()
    cur.executescript(script.read())
    conn.close()
    os.chmod(destglob, _db_perm)
    os.chown(destglob, 0, _ossec_gid)
    _create_profile(destdir, srcdir, force)
    return True

def _insert_agent(destdir, cursor, id, name, ip, key, osname, version, enabled):
    sql = "INSERT INTO agent (id, name, ip, key, os, version, enabled) values (?, ?, ?, ?, ?, ?, ?)"
    profile = destdir + _prof_name

    if _verbose:
        print("INFO: Inserting agent '{0}'.".format(id))

    try:
        cursor.execute(sql, (id, name, ip, key, osname, version, enabled))
    except sqlite3.IntegrityError:
        sys.stderr.write("WARN: Agent '{0}' already exists.\n".format(id))
        return

    destagent = destdir + _agent_dir + _agent_pattern.format(id, name)

    try:
        source = open(profile, 'rb')
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(profile, error.strerror))
        return False

    try:
        dest = open(destagent, 'wb')
    except IOError as error:
        sys.stderr.write("ERROR: Opening '{0}': {1}.\n".format(cursor, error.strerror))
        return False

    dest.write(source.read())
    source.close()
    dest.close()
    os.chmod(destagent, _db_perm)
    os.chown(destagent, 0, _ossec_gid)
    return True

def insert_agents(destdir=_dest_dir, srcdir=_src_dir, keyspath=_keys_path):
    '''Insert the registered agents into the global database and creates
       one empty database for each one.'''

    destglob = destdir + '/global.db'
    agents = open(keyspath, 'r')
    conn = sqlite3.connect(destglob)
    cursor = conn.cursor()

    cursor.execute('BEGIN')
    _insert_agent(destdir, cursor, 0, 'localhost', None, None, None, None, 1)

    for agent in agents:
        try:
            id, name, ip, key = agent.split()
        except ValueError:
            sys.stderr.write("ERROR: Corrupt line at 'client.keys'.\n")
            continue

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
            with open('{0}/queue/agent-info/{1}-{2}'.format(_ossec_path, name, ip), 'r') as f:
                osname, version = f.read().split(' - ')
        except IOError:
            osname = version = None

        _insert_agent(destdir, cursor, int(id), name, ip, key, osname, version, enabled)

    if _verbose:
        print("INFO: Committing changes...")

    conn.commit()

    if _verbose:
        print("INFO: Data commited.")

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

def _fim_insert_file(cursor, dbfile, filetype):
    '''Inserts one file from syscheck into the database'''

    try:
        with open(dbfile, 'r') as syscheck:
            for line in syscheck:
                path, event, date, size, perm, uid, gid, md5, sha1 = _fim_decode(line[:-1])
                row = cursor.execute('SELECT id FROM fim_file WHERE type = ? AND path = ?', (filetype, path)).fetchone()

                if row:
                    id_file = row[0]
                else:
                    cursor.execute('INSERT INTO fim_file (path, type) VALUES (?, ?)', (path, filetype))
                    id_file = cursor.lastrowid

                cursor.execute('INSERT INTO fim_event (id_file, type, date, size, perm, uid, gid, md5, sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (id_file, event, date, size, perm, uid, gid, md5, sha1))
    except IOError:
        sys.stderr.write("WARN: No such file '{0}'.\n".format(dbfile))

def insert_fim(destdir=_dest_dir):
    '''Insert the file integrity monitoring events into database.
       It requires that table agents has been filled'''

    destagents = destdir + _agent_dir + _agent_pattern
    destglob = destdir + '/global.db'
    connglob = sqlite3.connect(destglob)

    for id_agent, name, ip, os in connglob.cursor().execute('SELECT id, name, ip, os FROM agent WHERE enabled = 1'):
        path = _ossec_path + '/queue/syscheck/'
        path += '({0}) {1}->syscheck'.format(name, ip) if id_agent else 'syscheck'
        destagent = destagents.format(id_agent, name)
        conn = sqlite3.connect(destagent)
        cursor = conn.cursor()
        cursor.execute('BEGIN')

        if _verbose:
            print("INFO: Inserting syscheck database of agent '{0}'.".format(id_agent))

        _fim_insert_file(cursor, path, 'file')

        if os and 'Windows' in os:
            path = '{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(_ossec_path, name, ip)
            _fim_insert_file(cursor, id_agent, path, 'registry')

        if _verbose:
            print("INFO: Committing changes...")

        conn.commit()

        if _verbose:
            print("INFO: Data commited.")

        conn.close()

def insert_pm(destdir=_dest_dir):
    '''Insert the policy monitoring events into database.
       It requires that table agents has been filled.'''

    destagents = destdir + _agent_dir + _agent_pattern
    destglob = destdir + '/global.db'
    connglob = sqlite3.connect(destglob)

    for id_agent, name, ip, os in connglob.cursor().execute('SELECT id, name, ip, os FROM agent WHERE enabled = 1'):
        path = _ossec_path + '/queue/rootcheck/'
        path += '({0}) {1}->rootcheck'.format(name, ip) if id_agent else 'rootcheck'
        destagent = destagents.format(id_agent, name)
        conn = sqlite3.connect(destagent)
        cursor = conn.cursor()
        cursor.execute('BEGIN')

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

                    cursor.execute("INSERT INTO pm_event (date_first, date_last, log) VALUES (?, ?, ?)", (date_first, date_last, log))

        except IOError:
            sys.stderr.write("WARN: No such file '{0}'.\n".format(path))

        if _verbose:
            print("INFO: Committing changes...")

        conn.commit()

        if _verbose:
            print("INFO: Data commited.")

        conn.close()

def _print_help():
    print '''
    Database creation utility for Wazuh HIDS

    Options:
        -c          Only create global database and agents (do not insert FIM or PM).
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
    insert = True

    try:
        for opt in getopt(sys.argv[1:], 'cd:fhs:v', '')[0]:
            if opt[0] == '-c':
                insert = False
            elif opt[0] == '-d':
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

    if create(destdir, srcdir, force):
        insert_agents(destdir, srcdir)

        if insert:
            insert_fim(destdir)
            insert_pm(destdir)
    else:
        sys.exit(1)
