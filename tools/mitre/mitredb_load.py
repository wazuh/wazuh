import json
import sqlite3
from sqlite3 import Error
 
 
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
 
    return conn
 
 
def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

def insert_attack_table(conn, id, json_object):
    """ insert to Mitre 'attack' table from id techniquec and json object 
    :param conn: Connection object
    :param id: Mitre External id
    :param value: It can be a json object, a phase (Persistence, Evasion, etc) or platform (Windows, Linux, macOs)
    :return:
    """
    attack_sql = """INSERT INTO attack ('id', 'json') VALUES (?, ?);"""
    args = (id, json_object)
    
    try:
        c = conn.cursor()
        c.execute(attack_sql, args)
        conn.commit()
    except Error as e:
        print(e)

def insert_phase_table(conn, attack_id, phase_name):
    """ insert to a table from the insert_sql statement
    :param conn: Connection object
    :param id: Mitre External id
    :param value: It can be a json object, a phase (Persistence, Evasion, etc) or platform (Windows, Linux, macOs)
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
        
def insert_platform_table(conn, attack_id, platform_name):
    """ insert to a table from the insert_sql statement
    :param conn: Connection object
    :param id: Mitre External id
    :param value: It can be a json object, a phase (Persistence, Evasion, etc) or platform (Windows, Linux, macOs)
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
 
 
def main():
    database = r"/var/ossec/var/db/mitre.db"

    sql_delete_attack = """DROP TABLE IF EXISTS attack;"""
 
    sql_delete_has_phase = """DROP TABLE IF EXISTS has_phase;"""

    sql_delete_has_platform = """DROP TABLE IF EXISTS has_platform;"""
 
    sql_create_attack = """CREATE TABLE attack (
                                        id TEXT PRIMARY KEY, 
                                        json TEXT
                                    );"""
 
    sql_create_has_phase = """CREATE TABLE has_phase (
                                    attack_id TEXT, 
                                    phase_name TEXT,
                                    FOREIGN KEY(attack_id) REFERENCES attack(id),
                                    PRIMARY KEY (attack_id, phase_name)
                                );"""

    sql_create_has_platform = """CREATE TABLE has_platform (
                                    attack_id TEXT, 
                                    platform_name TEXT,
                                    FOREIGN KEY(attack_id) REFERENCES attack(id),
                                    PRIMARY KEY (attack_id, platform_name)
                                );"""                            
 
    # Create a database connection
    conn = create_connection(database)

    # Delete tables
    if conn is not None:
        # Delete attack table
        create_table(conn, sql_delete_attack)
 
        # Delete has_phase table
        create_table(conn, sql_delete_has_phase)

        # Delete has_platform table
        create_table(conn, sql_delete_has_platform)
    else:
        print("Error! cannot create the database connection.")

    # Create tables
    if conn is not None:
        # Create attack table
        create_table(conn, sql_create_attack)
 
        # Create has_phase table
        create_table(conn, sql_create_has_phase)

        # Create has_platform table
        create_table(conn, sql_create_has_platform)
    else:
        print("Error! cannot create the database connection.")
    
    # Parse enterprise-attack.json file:
    with open('enterprise-attack.json') as json_file:
        data = json.load(json_file)
        for data_object in data['objects']:
            if data_object['type'] == 'attack-pattern' and data_object['external_references'][0]['source_name'] == 'mitre-attack':
                string_id = json.dumps(data_object['external_references'][0]['external_id'])
                string_object = json.dumps(data_object)

                # Fill the attack table 
                insert_attack_table(conn, string_id, string_object)
                
                # Fill the phase table
                n = len(data_object['kill_chain_phases'])
                for i in range (0,n):
                    string_phase = json.dumps(data_object['kill_chain_phases'][i]['phase_name'])
                    insert_phase_table(conn, string_id, string_phase)
                
                # Fill the platform table
                for platform in data_object['x_mitre_platforms']:
                    string_platform = json.dumps(platform)
                    insert_platform_table(conn,string_id, string_platform)
                
    conn.close()

if __name__ == '__main__':
    main()
