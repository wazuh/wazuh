#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
#
# Example:
#
# python mitredb.py -> install mitre.db
# python mitredb.py -d /other/directory/mitre.db  -> install mitre.db in other directory
# python mitredb.py -h -> Help

import argparse
import grp
import json
import os
import pwd
import sys

from sqlalchemy import create_engine, Column, DateTime, String, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql.expression import select

import const
import wazuh.core.utils as core_utils

Base = declarative_base()

data_source_rows_list = []
defense_bypassed_rows_list = []
effective_permission_rows_list = []
impact_rows_list = []
permission_req_rows_list = []
requirement_rows_list = []
mitigate_rows_list = []
use_rows_list = []
alias_rows_list = []
contributor_rows_list = []
platform_rows_list = []
external_reference_rows_list = []


class Metadata(Base):
    """
    This table stores the metadata of the JSON file.
    The information stored:
        key: key (PK)
        value: value
    """
    __tablename__ = "metadata"

    key = Column(const.KEY_t, String, primary_key=True)
    value = Column(const.VALUE_t, String, nullable=False)


class Technique(Base):
    """
    This table stores the techniques of the JSON file.
    The information stored:
        id: Used to identify the technique (PK)
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
    __tablename__ = "technique"

    id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)
    mitre_version = Column(const.MITRE_VERSION_t, String, default=None)
    mitre_detection = Column(const.MITRE_DETECTION_t, String, default=None)
    network_requirements = Column(const.NETWORK_REQ_t, Boolean, default=False)
    remote_support = Column(const.REMOTE_SUPPORT_t, Boolean, default=False)
    revoked_by = Column(const.REVOKED_BY_t, String, default=None)
    deprecated = Column(const.DEPRECATED_t, Boolean, default=False)
    subtechnique_of = Column(const.SUBTECHNIQUE_OF_t, String, default=None)

    data_sources = relationship(const.DATASOURCE_r, backref=const.TECHNIQUES_r)
    defenses_bypassed = relationship(const.DEFENSEBYPASSES_r, backref=const.TECHNIQUES_r)
    effective_permissions = relationship(const.EFFECTIVEPERMISSON_r, backref=const.TECHNIQUES_r)
    impacts = relationship(const.IMPACT_r, backref=const.TECHNIQUES_r)
    permissions = relationship(const.PERMISSION_r, backref=const.TECHNIQUES_r)
    requirements = relationship(const.SYSTEMREQ_r, backref=const.TECHNIQUES_r)

    mitigate = relationship(const.MITIGATE_r)
    phase = relationship(const.PHASE_r)


class DataSource(Base):
    """
    This table stores the sources for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        source: Data source for this technique
    """
    __tablename__ = "data_source"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    source = Column(const.SOURCE_t, String, primary_key=True)


class DefenseByPasses(Base):
    """
    This table stores the defenses for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        defense: Defense bypassed for this technique
    """
    __tablename__ = "defense_bypassed"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    defense = Column(const.DEFENSE_t, String, primary_key=True)


class EffectivePermission(Base):
    """
    This table stores the effective permissions for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        permission: Effective permission for this technique
    """
    __tablename__ = "effective_permission"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    permission = Column(const.PERMISSION_t, String, primary_key=True)


class Impact(Base):
    """
    This table stores the impacts for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        impact: Impact of this technique
    """
    __tablename__ = "impact"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    impact = Column(const.IMPACT_t, String, primary_key=True)


class Permission(Base):
    """
    This table stores the permissions for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        permission: Permission for this technique
    """
    __tablename__ = "permission"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    permission = Column(const.PERMISSION_t, String, primary_key=True)


class SystemRequirement(Base):
    """
    This table stores the requirements for each technique.
    The information stored:
        id: Used to identify the technique (FK)
        requirements: System requirement for this technique
    """
    __tablename__ = "system_requirement"

    id = Column(const.ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)
    requirement = Column(const.REQUIREMENT_t, String, primary_key=True)


class Group(Base):
    """
    This table stores the groups of the JSON file.
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
    __tablename__ = "group"

    id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)
    mitre_version = Column(const.MITRE_VERSION_t, String, default=None)
    revoked_by = Column(const.REVOKED_BY_t, String, default=None)
    deprecated = Column(const.DEPRECATED_t, Boolean, default=False)


class Software(Base):
    """
    This table stores the software of the JSON file.
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

    id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)
    mitre_version = Column(const.MITRE_VERSION_t, String, default=None)
    revoked_by = Column(const.REVOKED_BY_t, String, default=None)
    deprecated = Column(const.DEPRECATED_t, Boolean, default=False)


class Mitigation(Base):
    """
    This table stores the mitigations of the JSON file.
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
    __tablename__ = "mitigation"

    id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)
    mitre_version = Column(const.MITRE_VERSION_t, String, default=None)
    revoked_by = Column(const.REVOKED_BY_t, String, default=None)
    deprecated = Column(const.DEPRECATED_t, Boolean, default=False)

    mitigate = relationship(const.MITIGATE_r)


class Aliases(Base):
    """
    This table stores the aliases of the JSON file.
    The information stored:
        id: Used to identify the group or software (PK).
        alias: Alias related to this item (PK).
    """
    __tablename__ = "alias"

    id = Column(const.ID_t, String, primary_key=True)
    alias = Column(const.ALIAS_t, String, primary_key=True)
    type = Column(const.TYPE_t, String, nullable=False)


class Contributors(Base):
    """
    This table stores the contributors of the JSON file.
    The information stored:
        id: Used to identify the technique, group or software (PK).
        contributor: Contributor related to this item (PK).
    """
    __tablename__ = "contributor"

    id = Column(const.ID_t, String, primary_key=True)
    contributor = Column(const.CONTRIBUTOR_t, String, primary_key=True)
    type = Column(const.TYPE_t, String, nullable=False)


class Platforms(Base):
    """
    This table stores the platforms of the JSON file.
    The information stored:
        id: Used to identify the technique or software (PK).
        platform: OS related to this item (PK).
    """
    __tablename__ = "platform"

    id = Column(const.ID_t, String, primary_key=True)
    platform = Column(const.PLATFORM_t, String, primary_key=True)
    type = Column(const.TYPE_t, String, nullable=False)


class References(Base):
    """
    This table stores the references of the JSON file.
    The information stored:
        id: Used to identify the tactic, technique, mitigation, group or software (PK).
        source: Source of this reference (PK).
        external_id: ID associated with this item (only in case of source mitre-attack).
        url: URL of the reference.
        description: Description of the reference.
    """
    __tablename__ = "reference"

    id = Column(const.ID_t, String, primary_key=True)
    source = Column(const.SOURCE_t, String, primary_key=True)
    external_id = Column(const.EXTERNAL_ID_t, String, default=None, nullable=True)
    url = Column(const.URL_t, String, primary_key=True)
    description = Column(const.DESCRIPTION_t, String, default=None, nullable=True)
    type = Column(const.TYPE_t, String, nullable=False)


class Mitigate(Base):
    """
    This table stores the relationship between mitigation and technique table.
    In this table are stored the mitigate information
    The information stored:
        id: Used to identify the mitigate
        source_id: Used to identify the mitigation (FK)
        target_id: Used to identify the technique (FK)
        description: Detailed description of the mitigate
        created_time: Publish date
        modified_time: Last modification date
    """
    __tablename__ = "mitigate"

    id = Column(const.ID_t, String, primary_key=True)
    source_id = Column(const.SOURCE_ID_t, String, ForeignKey(const.MITIGATION_ID_fk), nullable=False)
    target_id = Column(const.TARGET_ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk), nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)


class Use(Base):
    """
    This table stores the relationship of use.
    The information stored:
        id: Used to identify the use
        source_id: Used to identify the group or software
        target_id: Used to identify the technique or software
        description: Detailed description of the relationship
        created_time: Publish date
        modified_time: Last modification date
    """
    __tablename__ = "use"

    id = Column(const.ID_t, String, primary_key=True)
    source_id = Column(const.SOURCE_ID_t, String, default=None, nullable=False)
    source_type = Column(const.SOURCE_TYPE_t, String, nullable=False)
    target_id = Column(const.TARGET_ID_t, String, default=None, nullable=False)
    target_type = Column(const.TARGET_TYPE_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)


class Tactic(Base):
    """
    This table stores the tactics of the JSON file.
    The information stored:
        id: Used to identify the tactic (PK)
        name: Name of the tactic
        description: Detailed description of the tactic
        created_time: Publish date
        modified_time: Last modification date
        short_name: Short name of the tactic
    """
    __tablename__ = "tactic"

    id = Column(const.ID_t, String, primary_key=True)
    name = Column(const.NAME_t, String, nullable=False)
    description = Column(const.DESCRIPTION_t, String, default=None)
    created_time = Column(const.CREATED_t, DateTime, default=None)
    modified_time = Column(const.MODIFIED_t, DateTime, default=None)
    short_name = Column(const.SHORT_NAME_t, String, default=None)

    phase = relationship(const.PHASE_r)


class Phase(Base):
    """
    This table stores the relationship between tactic and technique table.
    The information stored:
        tactic_id: Used to identify the tactic (FK) (PK)
        tech_id: Used to identify the technique (FK) (PK)
    """
    __tablename__ = "phase"

    tactic_id = Column(const.TACTIC_ID_t, String, ForeignKey(const.TACTIC_ID_fk, ondelete='CASCADE'), primary_key=True)
    tech_id = Column(const.TECH_ID_t, String, ForeignKey(const.TECHNIQUE_ID_fk, ondelete='CASCADE'), primary_key=True)


def parse_table(function, data_object):
    row = {}
    row[const.ID_t] = data_object[const.ID_t]
    row[const.NAME_t] = data_object[const.NAME_t]

    if const.DESCRIPTION_j in data_object:
        row[const.DESCRIPTION_t] = data_object[const.DESCRIPTION_t]

    if const.CREATED_j in data_object:
        row[const.CREATED_t] = core_utils.get_utc_strptime(data_object[const.CREATED_j], const.TIME_FORMAT)
    if const.MODIFIED_j in data_object:
        row[const.MODIFIED_t] = core_utils.get_utc_strptime(data_object[const.MODIFIED_j], const.TIME_FORMAT)
    if function.__name__ == 'Tactic':
        if const.SHORT_NAME_j in data_object:
            row[const.SHORT_NAME_t] = data_object[const.SHORT_NAME_j]
    elif function.__name__ == 'Group' or \
            function.__name__ == 'Software' or \
            function.__name__ == 'Mitigation':
        if const.MITRE_VERSION_j in data_object:
            row[const.MITRE_VERSION_t] = data_object[const.MITRE_VERSION_j]
        if const.DEPRECATED_j in data_object:
            row[const.DEPRECATED_t] = data_object[const.DEPRECATED_j]

    parse_common_tables(row[const.ID_t], data_object)

    return row


def parse_json_techniques(technique_json, phases_table):
    row = {}
    row[const.ID_t] = technique_json[const.ID_t]
    row[const.NAME_t] = technique_json[const.NAME_t]

    if technique_json.get(const.DESCRIPTION_t):
        row[const.DESCRIPTION_t] = technique_json[const.DESCRIPTION_t]
    if technique_json.get(const.CREATED_j):
        row[const.CREATED_t] = core_utils.get_utc_strptime(technique_json[const.CREATED_j], const.TIME_FORMAT)
    if technique_json.get(const.MODIFIED_j):
        row[const.MODIFIED_t] = core_utils.get_utc_strptime(technique_json[const.MODIFIED_j], const.TIME_FORMAT)
    if technique_json.get(const.MITRE_VERSION_j):
        row[const.MITRE_VERSION_t] = technique_json[const.MITRE_VERSION_j]
    if technique_json.get(const.MITRE_DETECTION_j):
        row[const.MITRE_DETECTION_t] = technique_json[const.MITRE_DETECTION_j]
    if technique_json.get(const.MITRE_NETWOR_REQ_j):
        row[const.NETWORK_REQ_t] = technique_json[const.MITRE_NETWOR_REQ_j]
    if technique_json.get(const.MITRE_REMOTE_SUPP_j):
        row[const.REMOTE_SUPPORT_t] = technique_json[const.MITRE_REMOTE_SUPP_j]
    if technique_json.get(const.DEPRECATED_j):
        row[const.DEPRECATED_t] = technique_json[const.DEPRECATED_j]
    if technique_json.get(const.DATASOURCE_j):
        for data_source in list(set(technique_json[const.DATASOURCE_j])):
            row_data_source = {}
            row_data_source[const.ID_t] = row[const.ID_t]
            row_data_source[const.SOURCE_t] = data_source
            data_source_rows_list.append(row_data_source)
    if technique_json.get(const.DEFENSE_BYPASSED_j):
        for defense in list(set(technique_json[const.DEFENSE_BYPASSED_j])):
            row_defense_bypassed = {}
            row_defense_bypassed[const.ID_t] = row[const.ID_t]
            row_defense_bypassed[const.DEFENSE_t] = defense
            defense_bypassed_rows_list.append(row_defense_bypassed)
    if technique_json.get(const.EFFECTIVE_PERMISSION_j):
        for permission in list(set(technique_json[const.EFFECTIVE_PERMISSION_j])):
            row_permission = {}
            row_permission[const.ID_t] = row[const.ID_t]
            row_permission[const.PERMISSION_t] = permission
            effective_permission_rows_list.append(row_permission)
    if technique_json.get(const.IMPACT_TYPE_j):
        for impact in list(set(technique_json[const.IMPACT_TYPE_j])):
            row_impact = {}
            row_impact[const.ID_t] = row[const.ID_t]
            row_impact[const.IMPACT_t] = impact
            impact_rows_list.append(row_impact)
    if technique_json.get(const.PERMISSIONS_REQ_j):
        for permission_req in list(set(technique_json[const.PERMISSIONS_REQ_j])):
            row_permission_req = {}
            row_permission_req[const.ID_t] = row[const.ID_t]
            row_permission_req[const.PERMISSION_t] = permission_req
            permission_req_rows_list.append(row_permission_req)
    if technique_json.get(const.SYSTEM_REQ_j):
        for requirement in list(set(technique_json[const.SYSTEM_REQ_j])):
            row_requirement = {}
            row_requirement[const.ID_t] = row[const.ID_t]
            row_requirement[const.REQUIREMENT_t] = requirement
            requirement_rows_list.append(row_requirement)
    if technique_json.get(const.PHASES_j):
        for phase in technique_json[const.PHASES_j]:
            phases_table.append([row[const.ID_t], phase[const.PHASE_NAME_j]])

    parse_common_tables(row[const.ID_t], technique_json)

    return row


def parse_json_mitigate_use(data_object):
    row = {}
    row[const.ID_t] = data_object[const.ID_t]
    row[const.SOURCE_ID_t] = data_object[const.SOURCE_REF_j]
    row[const.TARGET_ID_t] = data_object[const.TARGET_REF_j]
    row[const.SOURCE_TYPE_t] = get_type(row[const.SOURCE_ID_t])
    row[const.TARGET_TYPE_t] = get_type(row[const.TARGET_ID_t])

    if data_object.get(const.DESCRIPTION_t):
        row[const.DESCRIPTION_t] = data_object[const.DESCRIPTION_t]
    if data_object.get(const.CREATED_j):
        row[const.CREATED_t] = core_utils.get_utc_strptime(data_object[const.CREATED_j], const.TIME_FORMAT)
    if data_object.get(const.MODIFIED_j):
        row[const.MODIFIED_t] = core_utils.get_utc_strptime(data_object[const.MODIFIED_j], const.TIME_FORMAT)

    return row


def get_type(object_id):
    type = ""
    if object_id.startswith(const.MALWARE_j) or object_id.startswith(const.TOOL_j):
        type = "software"
    elif object_id.startswith(const.INTRUSION_SET_j):
        type = "group"
    elif object_id.startswith(const.TACTIC_j):
        type = "tactic"
    elif object_id.startswith(const.COURSE_OF_ACTION_j):
        type = "mitigation"
    elif object_id.startswith(const.ATTACK_PATTERN_j):
        type = "technique"
    return type


def parse_common_tables(parent_id, data_object):
    # Alias
    if data_object.get(const.ALIASES_j):
        for alias in data_object[const.ALIASES_j]:
            row_alias = {}
            row_alias[const.ID_t] = parent_id
            row_alias[const.ALIAS_t] = alias
            row_alias[const.TYPE_t] = get_type(row_alias[const.ID_t])
            alias_rows_list.append(row_alias)

    if data_object.get(const.ALIAS_j):
        for alias in data_object[const.ALIAS_j]:
            row_alias = {}
            row_alias[const.ID_t] = parent_id
            row_alias[const.ALIAS_t] = alias
            row_alias[const.TYPE_t] = get_type(row_alias[const.ID_t])
            alias_rows_list.append(row_alias)

    # Contributor
    if data_object.get(const.CONTRIBUTOR_j):
        for contributor in data_object[const.CONTRIBUTOR_j]:
            row_contributor = {}
            row_contributor[const.ID_t] = parent_id
            row_contributor[const.CONTRIBUTOR_t] = contributor
            row_contributor[const.TYPE_t] = get_type(row_contributor[const.ID_t])
            contributor_rows_list.append(row_contributor)

    # Platform
    if data_object.get(const.PLATFORM_j):
        for platform in data_object[const.PLATFORM_j]:
            row_platform = {}
            row_platform[const.ID_t] = parent_id
            row_platform[const.PLATFORM_t] = platform
            row_platform[const.TYPE_t] = get_type(row_platform[const.ID_t])
            platform_rows_list.append(row_platform)

    # External References
    if data_object.get(const.EXTERNAL_REFERENCES_j):
        for reference in data_object[const.EXTERNAL_REFERENCES_j]:
            if reference.get(const.URL_j):
                row_external_ref = parse_json_ext_references(reference)
                row_external_ref[const.ID_t] = parent_id
                row_external_ref[const.TYPE_t] = get_type(row_external_ref[const.ID_t])
                external_reference_rows_list.append(row_external_ref)


def parse_json_ext_references(data_object):
    row_external_ref = {}

    if data_object.get(const.SOURCE_NAME_j):
        row_external_ref[const.SOURCE_t] = data_object[const.SOURCE_NAME_j]
    if data_object.get(const.EXTERNAL_ID_j):
        row_external_ref[const.EXTERNAL_ID_t] = data_object[const.EXTERNAL_ID_j]
    if data_object.get(const.URL_j):
        row_external_ref[const.URL_t] = data_object[const.URL_j]
    if data_object.get(const.DESCRIPTION_t):
        row_external_ref[const.DESCRIPTION_t] = data_object[const.DESCRIPTION_j]

    return row_external_ref


def parse_json_relationships(relationships_json, relationship_table_revoked_by, relationship_table_subtechique_of):
    if relationships_json.get(const.RELATIONSHIP_TYPE_j) == const.REVOKED_BY_j:
        relationship_table_revoked_by.append(
            [relationships_json[const.SOURCE_REF_j], relationships_json[const.TARGET_REF_j]])

    elif relationships_json.get(const.RELATIONSHIP_TYPE_j) == const.SUBTECHNIQUE_OF_j:
        relationship_table_subtechique_of.append(
            [relationships_json[const.SOURCE_REF_j], relationships_json[const.TARGET_REF_j]])

    elif relationships_json.get(const.RELATIONSHIP_TYPE_j) == const.MITIGATES_j:
        mitigate = parse_json_mitigate_use(relationships_json)
        mitigate_rows_list.append(mitigate)

    elif relationships_json.get(const.RELATIONSHIP_TYPE_j) == const.USES_j:
        use = parse_json_mitigate_use(relationships_json)
        use_rows_list.append(use)


def parse_list_phases(session, phase_list):
    row = {}

    row[const.TECH_ID_t] = phase_list[0]
    tactic = session.scalars(select(Tactic).filter_by(short_name=phase_list[1]).limit(1)).first()
    row[const.TACTIC_ID_t] = tactic.id

    return row


def parse_json(pathfile, session, database):
    """
    Parse enterprise-attack.json and fill mitre.db's tables.

    :param pathfile: Path directory where enterprise-attack.json file is
    :param session: SQLAlchemy session
    :param database: path to mitre.db
    :return:
    """
    try:
        # Lists
        phases_table = []
        techniques = []
        groups = []
        mitigations = []
        softwares = []
        tactics = []
        relationship_table_revoked_by = []
        relationship_table_subtechique_of = []

        metadata = Metadata()
        metadata.key = const.DB_VERSION_t
        metadata.value = const.DB_VERSION_N_t
        session.add(metadata)

        with open(pathfile) as json_file:
            datajson = json.load(json_file)
            metadata = Metadata()
            metadata.key = const.MITRE_VERSION_t
            metadata.value = datajson[const.VERSION_j]
            session.add(metadata)
            for data_object in datajson[const.OBJECT_j]:
                if data_object[const.TYPE_j] == const.INTRUSION_SET_j:
                    group = parse_table(Group, data_object)
                    groups.append(group)
                elif data_object[const.TYPE_j] == const.COURSE_OF_ACTION_j:
                    mitigation = parse_table(Mitigation, data_object)
                    mitigations.append(mitigation)
                elif data_object[const.TYPE_j] == const.MALWARE_j or \
                        data_object[const.TYPE_j] == const.TOOL_j:
                    software = parse_table(Software, data_object)
                    softwares.append(software)
                elif data_object[const.TYPE_j] == const.TACTIC_j:
                    tactic = parse_table(Tactic, data_object)
                    tactics.append(tactic)
                elif data_object[const.TYPE_j] == const.ATTACK_PATTERN_j:
                    technique = parse_json_techniques(data_object, phases_table)
                    techniques.append(technique)
                elif data_object[const.TYPE_j] == const.RELATIONSHIP_j:
                    parse_json_relationships(data_object, relationship_table_revoked_by,
                                             relationship_table_subtechique_of)
                else:
                    continue

        session.bulk_insert_mappings(Technique, techniques)
        session.bulk_insert_mappings(DataSource, data_source_rows_list)
        session.bulk_insert_mappings(DefenseByPasses, defense_bypassed_rows_list)
        session.bulk_insert_mappings(EffectivePermission, effective_permission_rows_list)
        session.bulk_insert_mappings(Impact, impact_rows_list)
        session.bulk_insert_mappings(Permission, permission_req_rows_list)
        session.bulk_insert_mappings(SystemRequirement, requirement_rows_list)
        session.bulk_insert_mappings(Group, groups)
        session.bulk_insert_mappings(Mitigation, mitigations)
        session.bulk_insert_mappings(Software, softwares)
        session.bulk_insert_mappings(Tactic, tactics)
        session.commit()

        phase_rows_list = []
        for table in phases_table:
            phase = parse_list_phases(session, table)
            phase_rows_list.append(phase)
        session.bulk_insert_mappings(Phase, phase_rows_list)
        session.commit()

        for table in relationship_table_revoked_by:
            if table[0].startswith(const.INTRUSION_SET_j):
                groups = session.get(Group, table[0])
                groups.revoked_by = table[1]

            elif table[0].startswith(const.COURSE_OF_ACTION_j):
                mitigations = session.get(Mitigation, table[0])
                mitigations.revoked_by = table[1]

            elif table[0].startswith(const.MALWARE_j) or table[0].startswith(const.TOOL_j):
                software = session.get(Software, table[0])
                software.revoked_by = table[1]

            elif table[0].startswith(const.ATTACK_PATTERN_j):
                technique = session.get(Technique, table[0])
                technique.revoked_by = table[1]

        for table in relationship_table_subtechique_of:
            technique = session.get(Technique, table[0])
            technique.subtechnique_of = table[1]

        session.bulk_insert_mappings(Mitigate, mitigate_rows_list)
        session.bulk_insert_mappings(Use, use_rows_list)

        session.bulk_insert_mappings(Aliases, alias_rows_list)
        session.bulk_insert_mappings(Contributors, contributor_rows_list)
        session.bulk_insert_mappings(Platforms, platform_rows_list)
        session.bulk_insert_mappings(References, external_reference_rows_list)

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
    gid = grp.getgrnam("wazuh").gr_gid
    os.chown(database, uid, gid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script installs mitre.db in a directory.')
    parser.add_argument('--database', '-d', help='-d /your/directory/mitre.db (default: /var/ossec/var/db/mitre.db')
    args = parser.parse_args()
    main(args.database)
