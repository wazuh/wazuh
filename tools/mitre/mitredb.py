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
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError

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

class Technique(Base):
    """
    In this table are stored the techniques of json file
    The information stored:
        id: Used to identify the technique
        name: Name of the technique
        description: Detailed description of the technique
        created_time: Publish date
        modified_time: Last modification date
        mitre_version: Version of MITRE when created
        mitre_detection: Detection information
        network_requirements:Boolean indicationg network requirements
        remote_support: Boolean indicationg remote support
        revoked_by: ID of the technique that revokes this one, NULL otherwise. 
        deprecated: Boolean indicating if this technique is deprecated
        subtechnique_of: ID of the parent technique, NULL otherwise
    """
    __tablename__ = "techniques"

    id = Column('id', String, primary_key=True)
    name = Column('name', String, nullable=False)
    description = Column('description', String)
    created_time = Column('created_time', DateTime)
    modified_time = Column('modified_time' ,DateTime)
    mitre_version = Column('mitre_version', String)
    mitre_detection = Column('mitre_detection', String)
    network_requirements = Column('network_requirements', Boolean, default=False)
    remote_support = Column('remote_support', Boolean, default=False)
    revoked_by = Column('revoked_by', String)
    deprecated = Column('deprecated', Boolean, default=False)
    subtechnique_of = Column('subtechnique_of', String)

    data_sources = relationship("DataSource", backref="techniques")
    defenses_bypassed = relationship("DefenseByPasses", backref="techniques")
    effective_permissions = relationship("EffectivePermission", backref="techniques")
    impacts = relationship("Impact", backref="techniques")
    permissions = relationship("Permission", backref="techniques")
    requirements = relationship("SystemRequirement", backref="techniques")


class DataSource(Base):
    """
    In this table are stored the Sources for each technique identified
    with key x_mitre_data_sources on json file
    The information stored:
        id: Used to identify the technique (FK)
        source: Data source for this technique
    """
    __tablename__ = "data_source"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    source = Column('source', String, primary_key=True)


class DefenseByPasses(Base):
    """
    In this table are stored the Defenses bypassed for each technique identified
    with key x_mitre_defense_bypassed on json file
    The information stored:
        id: Used to identify the technique (FK)
        defense: Defense bypassed for this technique
    """
    __tablename__ = "defense_bypassed"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    defense = Column('defense', String, primary_key=True)


class EffectivePermission(Base):
    """
    In this table are stored the Effective permissions for each technique identified
    with key x_mitre_effective_permissions on json file
    The information stored:
        id: Used to identify the technique (FK)
        permission: Effective permission for this technique
    """
    __tablename__ = "effective_permission"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    permission = Column('permission', String, primary_key=True)


class Impact(Base):
    """
    In this table are stored the Impacts of each technique identified with
    key x_mitre_impact_type on json file
    The information stored:
        id: Used to identify the technique (FK)
        impact: Impact of this technique
    """
    __tablename__ = "impact"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    impact = Column('impact', String, primary_key=True)


class Permission(Base):
    """
    In this table are stored the Permissions for each technique identified
    with key x_mitre_permissions_required on json file
    The information stored:
        id: Used to identify the technique (FK)
        permission: Permission for this technique
    """
    __tablename__ = "permission"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    permission = Column('permission', String, primary_key=True)


class SystemRequirement(Base):
    """
    In this table are stored the Requirements for each technique identified
    with key x_mitre_system_requirements on json file
    The information stored:
        id: Used to identify the technique (FK)
        requirements: System requirement for this technique
    """
    __tablename__ = "system_requirement"

    id = Column('id', String, ForeignKey("techniques.id", ondelete='CASCADE'), primary_key=True)
    requirement = Column('requirement', String, primary_key=True)


def parse_json_techniques(technique_json):
    technique = Technique()

    if technique_json.get('id'):
        technique.id = technique_json['id']
    if technique_json.get('name'):
        technique.name = technique_json['name']
    if technique_json.get('description'):
        technique.description = technique_json['description']
    if technique_json.get('created'):
        technique.created_time = datetime.strptime(technique_json['created'], '%Y-%m-%dT%H:%M:%S.%fZ')
    if technique_json.get('modified'):
        technique.modified_time = datetime.strptime(technique_json['modified'], '%Y-%m-%dT%H:%M:%S.%fZ')
    if technique_json.get('x_mitre_version'):
        technique.mitre_version = technique_json['x_mitre_version']
    if technique_json.get('x_mitre_detection'):
        technique.mitre_detection = technique_json['x_mitre_detection']
    if technique_json.get('x_mitre_network_requirements'):
        technique.network_requirements = technique_json['x_mitre_network_requirements']
    if technique_json.get('x_mitre_remote_support'):
        technique.remote_support = technique_json['x_mitre_remote_support']
    if technique_json.get('revoked_by'):
        technique.revoked_by = technique_json['revoked_by']
    if technique_json.get('x_mitre_deprecated'):
        technique.deprecated = technique_json['x_mitre_deprecated']
    if technique_json.get('subtechnique_of'):
        technique.subtechnique_of = technique_json['subtechnique_of']
    if technique_json.get('x_mitre_data_sources'):
        for data_source in list(set(technique_json['x_mitre_data_sources'])):
            technique.data_sources.append(DataSource(techniques=technique, source=data_source))
    if technique_json.get('x_mitre_defense_bypassed'):
        for defense in list(set(technique_json['x_mitre_defense_bypassed'])):
            technique.defenses_bypassed.append(DefenseByPasses(techniques=technique, defense=defense))
    if technique_json.get('x_mitre_effective_permissions'):
        for permission in list(set(technique_json['x_mitre_effective_permissions'])):
            technique.effective_permissions.append(EffectivePermission(techniques=technique, permission=permission))
    if technique_json.get('x_mitre_impact_type'):
        for impact in list(set(technique_json['x_mitre_impact_type'])):
            technique.impacts.append(Impact(techniques=technique, impact=impact))
    if technique_json.get('x_mitre_permissions_required'):
        for permission in list(set(technique_json['x_mitre_permissions_required'])):
            technique.permissions.append(Permission(techniques=technique, permission=permission))
    if technique_json.get('x_mitre_system_requirements'):
        for requirement in list(set(technique_json['x_mitre_system_requirements'])):
            technique.requirements.append(SystemRequirement(techniques=technique, requirement=requirement))
    return technique


def parse_json_relationships(relationships_json, session):
    if relationships_json.get('relationship_type') == 'subtechnique-of':
        technique = session.query(Technique).get(relationships_json['source_ref'])
        technique.subtechnique_of = relationships_json['target_ref']
        session.commit()
    elif relationships_json.get('relationship_type') == 'revoked-by' and \
            relationships_json['source_ref'].startswith("attack-pattern"):
        technique = session.query(Technique).get(relationships_json['source_ref'])
        technique.revoked_by = relationships_json['target_ref']
        session.commit()


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
                elif data_object['type'] == 'attack-pattern':
                    technique = parse_json_techniques(data_object)
                    session.add(technique)
                    session.commit()
                elif data_object['type'] == 'relationship':
                    parse_json_relationships(data_object, session)
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
