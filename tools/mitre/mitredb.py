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
import copy
import const
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

    version = Column(const.VERSION_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String)

    def __init__(self, version="", name="", description="") :
        self.version = version
        self.name = name
        self.description = description

class Groups(Base):
    """
    In this table are stored the groups of json file
    The information stored:
        id: Used to identify the group (PK)
        name: Name of the group
        description: Detailed description of the group
        created_time: Publish date
        modified_time: Last modification date
        mitre_version: Version of MITRE when created
        revoked_by: ID of the group that revokes this one, NULL otherwise
        deprecated: Boolean indicating if this group is deprecated
    """
    __tablename__ = "groups"

    Id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String)
    created_time = Column(const.CREATED_t, DateTime)
    modified_time = Column(const.MODIFIED_t, DateTime)
    mitre_version = Column(const.MITRE_VERSION_t, String)
    revoked_by = Column(const.REVOKED_BY_t, String)
    deprecated = Column(const.DEPRECATED_t, Boolean)

    def __init__(self, Id="", name="", description="", created_time="", modified_time="", mitre_version="", revoked_by="", deprecated="") :
        self.Id = Id
        self.name = name
        self.description = description
        self.created_time = created_time
        self.modified_time = modified_time
        self.mitre_version = mitre_version
        self.revoked_by = revoked_by
        self.deprecated = deprecated

class Software(Base):
    """
    In this table are stored the software of json file
    The information stored:
        id: Used to identify the software (PK)
        name: Name of the software
        description: Detailed description of the software
        created_time: Publish date
        modified_time: Last modification date
        mitre_version: Version of MITRE when created
        revoked_by: ID of the software that revokes this one, NULL otherwise
        deprecated: Boolean indicating if this software is deprecated
    """
    __tablename__ = "software"

    Id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String)
    created_time = Column(const.CREATED_t, DateTime)
    modified_time = Column(const.MODIFIED_t, DateTime)
    mitre_version = Column(const.MITRE_VERSION_t, String)
    revoked_by = Column(const.REVOKED_BY_t, String)
    deprecated = Column(const.DEPRECATED_t, Boolean)

    def __init__(self, Id="", name="", description="", created_time="", modified_time="", mitre_version="", revoked_by="", deprecated="") :
        self.Id = Id
        self.name = name
        self.description = description
        self.created_time = created_time
        self.modified_time = modified_time
        self.mitre_version = mitre_version
        self.revoked_by = revoked_by
        self.deprecated = deprecated

class Mitigations(Base):
    """
    In this table are stored the mitigations of json file
    The information stored:
        id: Used to identify the mitigation (PK)
        name: Name of the mitigation
        description: Detailed description of the mitigation
        created_time: Publish date
        modified_time: Last modification date
        mitre_version: Version of MITRE when created
        revoked_by: ID of the mitigation that revokes this one, NULL otherwise
        deprecated: Boolean indicating if this mitigation is deprecated
    """
    __tablename__ = "mitigations"

    Id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String)
    created_time = Column(const.CREATED_t, DateTime)
    modified_time = Column(const.MODIFIED_t, DateTime)
    mitre_version = Column(const.MITRE_VERSION_t, String)
    revoked_by = Column(const.REVOKED_BY_t, String)
    deprecated = Column(const.DEPRECATED_t, Boolean)

    def __init__(self, Id="", name="", description="", created_time="", modified_time="", mitre_version="", revoked_by="", deprecated="") :
        self.Id = Id
        self.name = name
        self.description = description
        self.created_time = created_time
        self.modified_time = modified_time
        self.mitre_version = mitre_version
        self.revoked_by = revoked_by
        self.deprecated = deprecated

def parse_table_(function, pathfile, session):
    with open(pathfile) as json_file:
        datajson = json.load(json_file)
        for data_object in datajson[const.OBJECT_j]:
            if function.__name__ == const.GROUPS:
                if data_object[const.TYPE_j] != const.INSTRUSION_SET_j:
                    continue
            elif function.__name__ == const.MITIGATION:
                if data_object[const.TYPE_j] != const.COURSE_OF_ACTION_j:
                    continue
            elif function.__name__ == const.SOFTWARE:
                if data_object[const.TYPE_j] != const.MALWARE_j and data_object[const.TYPE_j] != const.TOOL_j:
                    continue
            else:
                continue

            table = function()
            table.Id = data_object[const.ID_j]
            table.name = data_object[const.NAME_j]
            if const.DESCRIPTION_j in data_object:
                table.description = data_object[const.DESCRIPTION_j]
            else:
                table.description = None

            table.created_time = datetime.strptime(data_object[const.CREATED_j], '%Y-%m-%dT%H:%M:%S.%fZ')
            table.modified_time = datetime.strptime(data_object[const.MODIFIED_j], '%Y-%m-%dT%H:%M:%S.%fZ')

            if const.MITRE_VERSION_j in data_object:
                table.mitre_version = data_object[const.MITRE_VERSION_j]
            else:
                table.mitre_version = None

            if const.REVOKED_j in data_object:
                for data_object_1 in datajson[const.OBJECT_j]:
                    if const.SORUCE_REF_j in data_object_1:
                        if data_object_1[const.SORUCE_REF_j] == table.Id and data_object_1[const.RELATIONSHIP_TYPE_j] == const.REVOKED_BY_j:
                            table.revoked_by = data_object_1[const.TARGET_REF_j]
            else:
                table.revoked_by = None

            if const.DEPRECATED_j in data_object:
                table.deprecated = True
            else:
                table.deprecated = False
            session.add(table)

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

        parse_table_(Groups, pathfile, session)
        parse_table_(Software, pathfile, session)
        parse_table_(Mitigations, pathfile, session)

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
