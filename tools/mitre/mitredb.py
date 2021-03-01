#!/usr/bin/env python

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
#
# Example:
#
# python mitredb.py -> install mitre.db in /var/ossec/var/db
# python mitredb.py -d /other/directory/mitre.db  -> install mitre.db in other directory
# python mitredb.py -h -> Help

import json
import os
import pwd
import grp
import argparse
import sys
from datetime import datetime
from sqlalchemy import create_engine, Column, DateTime, String, Integer, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Metadata(Base):
    """
    In this table are stored the metadata of json file
    The information stored:
        version: version of json (PK)
        name: name
        description: description
    """
    __tablename__ = "metadata"

    version = Column('version', String, primary_key=True)
    name = Column('name', String, nullable=False)
    description = Column('description', String)

    def __init__(self, version="", name="", description="") :
        self.version = version
        self.name = name
        self.description = description


def parse_json(pathfile, session, database):
    """
    Parse enterprise-attack.json and fill mitre.db's tables.

    :param pathfile: Path directory where enterprise-attack.json file is
    :param session: SQLAlchemy session
    :param database: path to mitre.db
    :return:
    """
    try:
        metadata = Metadata()
        with open(pathfile) as json_file:
            datajson = json.load(json_file)
            metadata.version = datajson['spec_version']
            for data_object in datajson['objects']:
                if data_object['type'] == 'identity':
                    metadata.name = data_object['name']
                elif data_object['type'] == 'marking-definition':
                    metadata.description = data_object['definition']['statement']
        session.add(metadata)
        session.commit()

    except TypeError as t_e:
        print(t_e)
        print("Deleting " + database)
        os.remove(database)
        sys.exit(1)
    except KeyError as k_e:
        print(k_e)
        print("Deleting " + database)
        os.remove(database)
        sys.exit(1)
    except NameError as n_e:
        print(n_e)
        print("Deleting " + database)
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

    engine = create_engine('sqlite:///' + database, echo=False)

    # Create a database connection
    Session = sessionmaker(bind=engine)
    session = Session()

    # Delete and create tables
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    # Parse enterprise-attack.json file:
    parse_json(pathfile, session, database)

    # User and group permissions
    os.chmod(database, 0o660)
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("ossec").gr_gid
    os.chown(database, uid, gid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script installs mitre.db in a directory.')
    parser.add_argument('--database', '-d', help='-d /your/directory/mitre.db (default: /var/ossec/var/db/mitre.db')
    args = parser.parse_args()
    main(args.database)
