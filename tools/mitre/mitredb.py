#!/usr/bin/env python

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
#
# Example:
#
# python mitredb.py -> install mitre.db in /var/ossec/var/db
# python mitredb.py -d /other/directory/mitre.db  -> install mitre.db in other directory
# python mitredb.py -h -> Help 

import json
import sqlite3
from sqlite3 import Error
import os
import pwd
import grp
import argparse
import sys


def create_connection(db_file):
    """ 
    Create a database connection to the SQLite database specified by db_file.

    :param db_file: Database file. Examples: ('example.db'), ("/var/ossec/var/db/example.db"), etc.
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file, isolation_level=None)
        return conn
    except Error as e:
        print(e)

    return conn


def table_stmt(conn, sql_stmt):
    """ 
    Create or delete a table from the sql statement.

    :param conn: Connection object
    :param sql_stmt: a CREATE TABLE or DELETE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(sql_stmt)
    except Error as e:
        print(e)


def create_delete_tables(conn):
    """ 
    First it deletes attack, has_phase and has_platform tables and then it creates them.

    :return:
    """
    sql_delete_attack = """DROP TABLE IF EXISTS attack;"""

    sql_delete_has_phase = """DROP TABLE IF EXISTS has_phase;"""

    sql_delete_has_platform = """DROP TABLE IF EXISTS has_platform;"""

    sql_create_attack = """CREATE TABLE IF NOT EXISTS attack (
                                    id TEXT PRIMARY KEY,
                                    json TEXT,
                                    name TEXT
                                );"""

    sql_create_has_phase = """CREATE TABLE IF NOT EXISTS has_phase (
                                    attack_id TEXT,
                                    phase_name TEXT,
                                    FOREIGN KEY(attack_id) REFERENCES attack(id),
                                    PRIMARY KEY (attack_id, phase_name)
                                );"""

    sql_create_has_platform = """CREATE TABLE IF NOT EXISTS has_platform (
                                    attack_id TEXT,
                                    platform_name TEXT,
                                    FOREIGN KEY(attack_id) REFERENCES attack(id),
                                    PRIMARY KEY (attack_id, platform_name)
                                );"""

    # Delete attack table if exists
    table_stmt(conn, sql_delete_attack)

    # Delete has_phase table if exists
    table_stmt(conn, sql_delete_has_phase)

    # Delete has_platform table if exists
    table_stmt(conn, sql_delete_has_platform)

    # Create attack table
    table_stmt(conn, sql_create_attack)

    # Create has_phase table
    table_stmt(conn, sql_create_has_phase)

    # Create has_platform table
    table_stmt(conn, sql_create_has_platform)


def insert_attack_table(conn, id, json_object, name, database):
    """ 
    Insert to Mitre 'attack' table from Mitre ID technique and its JSON object. 

    :param conn: Connection object
    :param id: Mitre ID technique (e.g. 'T1122')
    :param json_object: JSON object with ID 'id' taken from the JSON file
    :param name: MITRE Technique's name
    :param database: path of MITRE database
    :return:
    """
    attack_sql = """INSERT INTO attack ('id', 'json', 'name') VALUES (?, ?, ?);"""
    args = (id, json_object, name)

    try:
        c = conn.cursor()
        c.execute(attack_sql, args)
        conn.commit()
    except Error as e:
        print(e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)


def insert_phase_table(conn, attack_id, phase_name, database):
    """ 
    Insert to Mitre 'phase' table from Mitre ID technique and its phase/tactic. It is posible that one ID has more than one phase/tactic associated.

    :param conn: Connection object
    :param attack_id: Mitre ID technique (e.g. 'T1122')
    :param phase_name: A phase/tactic name ('persistence ', 'privilege-escalation', etc)
    :param database: path of MITRE database
    :return:
    """
    phase_sql = """INSERT INTO has_phase ('attack_id', 'phase_name') VALUES (?, ?);"""
    args = (attack_id, phase_name)

    try:
        c = conn.cursor()
        c.execute(phase_sql, args)
        conn.commit()
    except Error as e:
        print(e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)


def insert_platform_table(conn, attack_id, platform_name, database):
    """ 
    Insert to Mitre 'plaftform' table from Mitre ID technique and its platform. It is posible that one ID has more than one platform associated.

    :param conn: Connection object
    :param attack_id: Mitre ID technique (e.g. 'T1122')
    :param platform_name: A platform name (e.g. Windows, Linux, macOs)
    :param database: path of MITRE database
    :return:
    """
    platform_sql = """INSERT INTO has_platform ('attack_id', 'platform_name') VALUES (?, ?);"""
    args = (attack_id, platform_name)

    try:
        c = conn.cursor()
        c.execute(platform_sql, args)
        conn.commit()
    except Error as e:
        print(e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)


def parse_json(pathfile, conn, database):
    """ 
    Parse enterprise-attack.json and fill mitre.db's tables.

    :param pathfile: Path directory where enterprise-attack.json file is
    :param conn: SQLite connection
    :param database: path of MITRE database
    :return:
    """
    try:
        with open(pathfile) as json_file:
            datajson = json.load(json_file)
            data = json.dumps(datajson)
            data = data.replace(': "persistence"', ': "Persistence"')
            data = data.replace(': "privilege-escalation"', ': "Privilege Escalation"')
            data = data.replace(': "defense-evasion"', ': "Defense Evasion"')
            data = data.replace(': "discovery"', ': "Discovery"')
            data = data.replace(': "credential-access"', ': "Credential Access"')
            data = data.replace(': "execution"', ': "Execution"')
            data = data.replace(': "lateral-movement"', ': "Lateral Movement"')
            data = data.replace(': "collection"', ': "Collection"')
            data = data.replace(': "exfiltration"', ': "Exfiltration"')
            data = data.replace(': "command-and-control"', ': "Command and Control"')
            data = data.replace(': "initial-access"', ': "Initial Access"')
            data = data.replace(': "impact"', ': "Impact"')
            datajson = json.loads(data)
            for data_object in datajson['objects']:
                if data_object['type'] == 'attack-pattern' and \
                        data_object['external_references'][0]['source_name'] == 'mitre-attack':
                    string_id = json.dumps(data_object['external_references'][0]['external_id']).replace('"', '')
                    string_object = json.dumps(data_object)
                    string_name = json.dumps(data_object['name']).replace('"', '')

                    # Fill the attack table
                    insert_attack_table(conn, string_id, string_object, string_name, database)

                    # Fill the phase table
                    n = len(data_object['kill_chain_phases'])
                    for i in range(0, n):
                        string_phase = json.dumps(data_object['kill_chain_phases'][i]['phase_name']).replace('"', '')
                        insert_phase_table(conn, string_id, string_phase, database)

                    # Fill the platform table
                    for platform in data_object['x_mitre_platforms']:
                        string_platform = json.dumps(platform).replace('"', '')
                        insert_platform_table(conn, string_id, string_platform, database)

    except TypeError as t_e:
        print(t_e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)
    except KeyError as k_e:
        print(k_e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)
    except NameError as n_e:
        print(n_e)
        print("Deleting " + database)
        conn.close()
        os.remove(database)
        sys.exit(1)


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def main(database=None):
    """
    Main function that creates the mitre database in a chosen directory. It deletes, creates and fills the mitre tables.

    :param database: Directory where mitre.db is. Default: /var/ossec/var/db/mitre.db
    :return:
    """
    if database is None:
        database = "/var/ossec/var/db/mitre.db"
    else:
        if not os.path.isdir('/'.join((str(database).split('/')[0:-1]))):
            raise Exception('Error: Directory not found.')

    pathfile = find('enterprise-attack.json', '../..')

    # Create a database connection
    conn = create_connection(database)

    # Delete and create tables
    if conn is not None:
        create_delete_tables(conn)
    else:
        print("Error! Cannot create the database connection.")

    # Parse enterprise-attack.json file:
    parse_json(pathfile, conn, database)

    # User and group permissions        
    os.chmod(database, 0o660)
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("ossec").gr_gid
    os.chown(database, uid, gid)

    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script installs mitre.db in a directory.')
    parser.add_argument('--database', '-d', help='-d /your/directory/mitre.db (default: /var/ossec/var/db/mitre.db')
    args = parser.parse_args()
    main(args.database)
