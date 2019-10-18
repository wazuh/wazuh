# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from datetime import datetime
from enum import Enum
from shutil import chown

from api.constants import SECURITY_PATH
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, UniqueConstraint
from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Create a application and configure it to be able to migrate
app = Flask(__name__)
_rbac_db_file = os.path.join(SECURITY_PATH, 'rbac.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + _rbac_db_file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
Migrate(app, db)

# Start a session and set the administrator ids and policies
_engine = create_engine(f'sqlite:///' + os.path.join(SECURITY_PATH, 'rbac.db'), echo=False)
_Base = declarative_base()
_Session = sessionmaker(bind=_engine)

# IDs reserved for administrator roles and policies, these can not be modified or deleted
admins_id = [1, 2]
admin_policy = [1]


# Error codes for Roles and Policies managers
class SecurityError(Enum):
    # The element already exist in the database
    ALREADY_EXIST = False
    # The element is invalid, missing format or property
    INVALID = -1
    # The role does not exist in the database
    ROLE_NOT_EXIST = -2
    # The policy does not exist in the database
    POLICY_NOT_EXIST = -3
    # Admin resources of the system
    ADMIN_RESOURCES = -4


class RolesPolicies(_Base):
    """
    Relational table between Roles and Policies, in this table are stored the relationship between the both entities
    The information stored from Roles and Policies are:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        created_at: Date of the relationship creation
    """
    __tablename__ = "roles_policies"

    # Schema, Many-To-Many relationship
    id = db.Column('id', db.Integer, primary_key=True)
    role_id = db.Column('role_id', db.Integer, db.ForeignKey("roles.id", ondelete='CASCADE'))
    policy_id = db.Column('policy_id', db.Integer, db.ForeignKey("policies.id", ondelete='CASCADE'))
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('role_id', 'policy_id', name='role_policy'),
                      )


def json_validator(data):
    """Function that returns True if the provided data is a valid dict, otherwise it will return False

    :param data: Data that we want to check
    :return: True -> Valid dict | False -> Not a dict or invalid dict
    """
    if isinstance(data, dict):
        return True

    return False


class Policies(_Base):
    """
    Policies table, in this table we are going to save all the information about the policies. The data that we will
    store is:
        id: ID of the policy, this is self assigned
        name: The name of the policy
        policy: The capabilities of the policy
        created_at: Date of the policy creation
    """
    __tablename__ = "policies"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    policy = db.Column('policy', TEXT)
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_policy'),
                      UniqueConstraint('policy', name='policy_definition'))

    # Relations
    roles = db.relationship("Roles", secondary='roles_policies',
                            backref=db.backref("roless", cascade="all,delete", order_by=id), lazy='dynamic')

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy
        self.created_at = datetime.utcnow()

    def get_policy(self):
        """Policy's getter

        :return: Dict with the information of the policy
        """
        return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy)}

    def to_dict(self):
        """Return the information of one policy and the roles that have assigned

        :return: Dict with the information
        """
        roles = list()
        for role in self.roles:
            roles.append(role.get_role())

        return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy), 'roles': roles}


class Roles(_Base):
    """
    Roles table, in this table we are going to save all the information about the policies. The data that we will
    store is:
        id: ID of the policy, this is self assigned
        name: The name of the policy
        policy: The capabilities of the policy
        created_at: Date of the policy creation
    """
    __tablename__ = "roles"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    rule = db.Column('rule', TEXT)
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_role'),
                      UniqueConstraint('rule', name='role_definition'))

    # Relations
    policies = db.relationship("Policies", secondary='roles_policies',
                               backref=db.backref("policiess", cascade="all,delete", order_by=id), lazy='dynamic')

    def __init__(self, name, rule):
        self.name = name
        self.rule = rule
        self.created_at = datetime.utcnow()

    def get_role(self):
        """Role's getter

        :return: Dict with the information of the role
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule)}

    def to_dict(self):
        """Return the information of one role and the policies that have assigned

        :return: Dict with the information
        """
        policies = list()
        for policy in self.policies:
            policies.append(policy.get_policy())

        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule), 'policies': policies}


class RolesManager:
    """
    This class is the manager of the Roles, this class provided
    all the methods needed for the roles administration.
    """
    def get_role(self, name: str):
        """Get the information about one role specified by name

        :param name: Name of the rol that want to get its information
        :return: Role object with all of its information
        """
        try:
            role = self.session.query(Roles).filter_by(name=name).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_role_id(self, role_id: int):
        """Get the information about one role specified by id

        :param role_id: ID of the rol that want to get its information
        :return: Role object with all of its information
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_roles(self):
        """Get the information about all roles in the system

        :return: List of Roles objects with all of its information | False -> No roles in the system
        """
        try:
            roles = self.session.query(Roles).all()
            return roles
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def add_role(self, name: str, rule: dict):
        """Add a new role

        :param name: Name of the new role
        :param rule: Rule of the new role
        :return: True -> Success | Role already exist | Invalid rule
        """
        try:
            if rule is not None and not json_validator(rule):
                return SecurityError.INVALID
            self.session.add(Roles(name=name, rule=json.dumps(rule)))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_role(self, role_id: int):
        """Delete an existent role in the system

        :param role_id: ID of the role to be deleted
        :return: True -> Success | False -> Failure
        """
        try:
            if int(role_id) not in admins_id:
                relations = self.session.query(RolesPolicies).filter_by(role_id=role_id).all()
                # If the role has one or more policies associated with it, the associations will be eliminated.
                # If the role does not exist continue
                for role_policy in relations:
                    self.session.delete(role_policy)
                # If the role does not exist we rollback the changes
                if self.session.query(Roles).filter_by(id=role_id).first() is None:
                    self.session.rollback()
                    return False
                # Finally we delete the role
                self.session.query(Roles).filter_by(id=role_id).delete()
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role_by_name(self, role_name: str):
        """Delete an existent role in the system

        :param role_name: Name of the role to be deleted
        :return: True -> Success | False -> Failure
        """
        try:
            if self.get_role(role_name) is not None and self.get_role(role_name).id not in admins_id:
                relations = self.session.query(RolesPolicies).filter_by(role_id=self.get_role(role_name).id).all()
                for role_policy in relations:
                    self.session.delete(role_policy)
                if self.session.query(Roles).filter_by(name=role_name).first() is None:
                    self.session.rollback()
                    return False
                self.session.query(Roles).filter_by(name=role_name).delete()
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_roles(self):
        """Delete all existent roles in the system

        :return: List of ids of deleted roles -> Success | False -> Failure
        """
        try:
            list_roles = list()
            roles = self.session.query(Roles).all()
            for role in roles:
                if int(role.id) not in admins_id:
                    relations = self.session.query(RolesPolicies).filter_by(role_id=role.id).all()
                    for role_policy in relations:
                        self.session.delete(role_policy)
                    list_roles.append(int(role.id))
                    self.session.query(Roles).filter_by(id=role.id).delete()
                    self.session.commit()
            return list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def update_role(self, role_id: int, name: str, rule: dict):
        """Update an existent role in the system

        :param role_id: ID of the role to be updated
        :param name: New name for the role
        :param rule: New rule for the role
        :return: True -> Success | Invalid rule | Name already in use | Role not exist
        """
        try:
            role_to_update = self.session.query(Roles).filter_by(id=role_id).first()
            if role_to_update and role_to_update is not None:
                if role_to_update.id not in admins_id:
                    # Rule is not a valid json
                    if rule is not None and not json_validator(rule):
                        return SecurityError.INVALID
                    # Change the name of the role
                    if name is not None:
                        if self.session.query(Roles).filter_by(name=name).first() is not None:
                            return SecurityError.ALREADY_EXIST
                        role_to_update.name = name
                    # Change the rule of the role
                    if rule is not None:
                        role_to_update.rule = json.dumps(rule)
                    self.session.commit()
                    return True
                return SecurityError.ADMIN_RESOURCES
            return SecurityError.ROLE_NOT_EXIST
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ROLE_NOT_EXIST

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class PoliciesManager:
    """
    This class is the manager of the Policies, this class provided
    all the methods needed for the policies administration.
    """
    def get_policy(self, name: str):
        """Get the information about one policy specified by name

        :param name: Name of the policy that want to get its information
        :return: Policy object with all of its information
        """
        try:
            policy = self.session.query(Policies).filter_by(name=name).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policy_id(self, policy_id: int):
        """Get the information about one policy specified by id

        :param policy_id: ID of the policy that want to get its information
        :return: Policy object with all of its information
        """
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policies(self):
        """Get the information about all policies in the system

        :return: List of policies objects with all of its information | False -> No policies in the system
        """
        try:
            policies = self.session.query(Policies).all()
            return policies
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def add_policy(self, name: str, policy: dict):
        """Add a new role

        :param name: Name of the new policy
        :param policy: Policy of the new policy
        :return: True -> Success | Invalid policy | Missing key (actions, resources, effect) or invalid policy (regex)
        """
        try:
            if policy is not None and not json_validator(policy):
                return SecurityError.ALREADY_EXIST
            if len(policy.keys()) != 3:
                return SecurityError.INVALID
            # To add a policy it must have the keys actions, resources, effect
            if 'actions' in policy.keys() and 'resources' in policy.keys():
                if 'effect' in policy.keys():
                    # The keys actions and resources must be lists and the key effect must be str
                    if isinstance(policy['actions'], list) and isinstance(policy['resources'], list) \
                            and isinstance(policy['effect'], str):
                        # Regular expression that prevents the creation of invalid policies
                        regex = r'^[a-z*]+:[a-z0-9*]+(:[a-z0-9*]+)*$'
                        for action in policy['actions']:
                            if not re.match(regex, action):
                                return SecurityError.INVALID
                        for resource in policy['resources']:
                            if not re.match(regex, resource):
                                return SecurityError.INVALID
                        self.session.add(Policies(name=name, policy=json.dumps(policy)))
                        self.session.commit()
                    else:
                        return SecurityError.INVALID
                else:
                    return SecurityError.INVALID
            else:
                return SecurityError.INVALID
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_policy(self, policy_id: int):
        """Delete an existent policy in the system

        :param policy_id: ID of the policy to be deleted
        :return: True -> Success | False -> Failure
        """
        try:
            if int(policy_id) not in admin_policy:
                relations = self.session.query(RolesPolicies).filter_by(policy_id=policy_id).all()
                # If the policy has relationships with roles, it first eliminates those relationships.
                # If there is no policy continues
                for role_policy in relations:
                    self.session.delete(role_policy)
                if self.session.query(Policies).filter_by(id=policy_id).first() is None:
                    self.session.rollback()
                    return False
                self.session.query(Policies).filter_by(id=policy_id).delete()
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy_by_name(self, policy_name: str):
        """Delete an existent role in the system

        :param policy_name: Name of the policy to be deleted
        :return: True -> Success | False -> Failure
        """
        try:
            if self.get_policy(policy_name) is not None:
                if self.get_policy(name=policy_name).id not in admin_policy:
                    relations = self.session.query(RolesPolicies).filter_by(
                        policy_id=self.get_policy(name=policy_name).id).all()
                    for role_policy in relations:
                        self.session.delete(role_policy)
                    if self.session.query(Policies).filter_by(name=policy_name).delete() is None:
                        self.session.rollback()
                        return False
                    self.session.query(Policies).filter_by(name=policy_name).delete()
                    self.session.commit()
                    return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_policies(self):
        """Delete all existent policies in the system

        :return: List of ids of deleted policies -> Success | False -> Failure
        """
        try:
            list_policies = list()
            policies = self.session.query(Policies).all()
            for policy in policies:
                if int(policy.id) not in admin_policy:
                    relations = self.session.query(RolesPolicies).filter_by(policy_id=policy.id).all()
                    for role_policy in relations:
                        self.session.delete(role_policy)
                    list_policies.append(int(policy.id))
                    self.session.query(Policies).filter_by(id=policy.id).delete()
                    self.session.commit()
            return list_policies
        except IntegrityError:
            self.session.rollback()
            return False

    def update_policy(self, policy_id: int, name: str, policy: dict):
        """Update an existent policy in the system

        :param policy_id: ID of the Policy to be updated
        :param name: New name for the Policy
        :param policy: New policy for the Policy
        :return: True -> Success | False -> Failure | Invalid policy | Name already in use
        """
        try:
            policy_to_update = self.session.query(Policies).filter_by(id=policy_id).first()
            if policy_to_update and policy_to_update is not None:
                if policy_to_update.id not in admin_policy:
                    # Policy is not a valid json
                    if policy is not None and not json_validator(policy):
                        return SecurityError.INVALID
                    if name is not None:
                        if self.session.query(Policies).filter_by(name=name).first() is not None:
                            return SecurityError.ALREADY_EXIST
                        policy_to_update.name = name
                    if policy is not None:
                        if 'actions' in policy.keys() and 'resources' in policy.keys() and 'effect' in policy.keys():
                            policy_to_update.policy = json.dumps(policy)
                    self.session.commit()
                    return True
                return SecurityError.ADMIN_RESOURCES
            return SecurityError.POLICY_NOT_EXIST
        except IntegrityError:
            self.session.rollback()
            return SecurityError.POLICY_NOT_EXIST

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class RolesPoliciesManager:
    """
    This class is the manager of the relationship between the roles and the policies, this class provided
    all the methods needed for the roles-policies administration.
    """
    def add_policy_to_role_admin(self, role_id: int, policy_id: int):
        # This function is reserved for internal use, allows to modify the role administrator
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if self.session.query(Policies).filter_by(id=policy_id).first():
                role.policies.append(self.session.query(Policies).filter_by(id=policy_id).first())
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def add_policy_to_role(self, role_id: int, policy_id: int):
        """Add a relation between one specified policy and one specified role

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """
        try:
            # Create a role-policy relationship if both exist
            if int(role_id) not in admins_id:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST
                if self.session.query(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is None:
                    role.policies.append(self.session.query(Policies).filter_by(id=policy_id).first())
                    self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def add_role_to_policy(self, policy_id: int, role_id: int):
        """Clone of the previous function

        :param policy_id: ID of the policy
        :param role_id: ID of the role
        :return: True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """
        return self.add_policy_to_role(role_id=role_id, policy_id=policy_id)

    def get_all_policies_from_role(self, role_id):
        """Get all the policies related with the specified role

        :param role_id: ID of the role
        :return: List of policies related with the role -> Success | False -> Failure
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            policies = role.policies
            return policies
        except IntegrityError:
            self.session.rollback()
            return False

    def get_all_roles_from_policy(self, policy_id: int):
        """Get all the roles related with the specified policy

        :param policy_id: ID of the policy
        :return: List of roles related with the policy -> Success | False -> Failure
        """
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            roles = policy.roles
            return roles
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_role_policy(self, role_id: int, policy_id: int):
        """Check if the relationship role-policy exist

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Existent relationship | False -> Failure | Role not exist
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            if policy is None:
                return SecurityError.POLICY_NOT_EXIST
            policy = role.policies.filter_by(id=policy_id).first()
            if policy is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_policy_role(self, policy_id: int, role_id: int):
        """Check if the relationship role-policy exist

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Existent relationship | False -> Failure | Policy not exist
        """
        return self.exist_role_policy(role_id, policy_id)

    def remove_policy_in_role(self, role_id: int, policy_id: int):
        """Create a role-policy relationship if both exist. Does not eliminate role and policy

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Success | False -> Failure | Role not exist | Policy not exist | Non-existent relationship
        """
        try:
            if int(role_id) not in admins_id:  # Administrator
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST
                if self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                               policy_id=policy_id).first() is not None:
                    role = self.session.query(Roles).get(role_id)
                    policy = self.session.query(Policies).get(policy_id)
                    role.policies.remove(policy)
                    self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_all_policies_in_role(self, role_id: int):
        """Removes all relations with policies. Does not eliminate roles and policies

        :param role_id: ID of the role
        :return: True -> Success | False -> Failure
        """
        try:
            if int(role_id) not in admins_id:
                policies = self.session.query(Roles).filter_by(id=role_id).first().policies
                for policy in policies:
                    if policy.id not in admin_policy:
                        self.remove_policy_in_role(role_id=role_id, policy_id=policy.id)
                return True
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_all_roles_in_policy(self, policy_id: int):
        """Removes all relations with roles. Does not eliminate roles and policies

        :param policy_id: ID of the role
        :return: True -> Success | False -> Failure
        """
        try:
            if int(policy_id) not in admin_policy:
                roles = self.session.query(Policies).filter_by(id=policy_id).first().roles
                for rol in roles:
                    if rol.id not in admins_id:
                        self.remove_policy_in_role(role_id=rol.id, policy_id=policy_id)
                return True
        except IntegrityError:
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id: int, actual_policy_id: int, new_policy_id: int):
        """Replace one existing relationship with another one

        :param role_id: Role to be modified
        :param actual_policy_id: Actual policy ID
        :param new_policy_id: New policy ID
        :return: True -> Success | False -> Failure
        """
        if int(role_id) not in admins_id:
            if self.exist_role_policy(role_id=role_id, policy_id=actual_policy_id) and \
                    self.session.query(Policies).filter_by(id=new_policy_id).first() is not None:
                self.remove_policy_in_role(role_id=role_id, policy_id=actual_policy_id)
                self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id)
                return True

        return False

    def replace_policy_role(self, policy_id: int, actual_role_id: int, new_role_id: int):
        """Replace one existing relationship with another one

        :param policy_id: Policy to be modified
        :param actual_role_id: Actual role ID
        :param new_role_id: New role ID
        :return: True -> Success | False -> Failure
        """
        if int(actual_role_id) not in admins_id:
            if self.exist_role_policy(role_id=actual_role_id, policy_id=policy_id) and \
                    self.session.query(Roles).filter_by(id=new_role_id).first() is not None:
                self.remove_policy_in_role(role_id=actual_role_id, policy_id=policy_id)
                self.add_policy_to_role(role_id=new_role_id, policy_id=policy_id)
                return True

        return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


# This is the actual sqlite database creation
_Base.metadata.create_all(_engine)

# Only if executing as root
try:
    chown(_rbac_db_file, 'ossec', 'ossec')
except PermissionError:
    pass
os.chmod(_rbac_db_file, 0o640)
_Session = sessionmaker(bind=_engine)

# These examples are for RBAC development
with PoliciesManager() as pm:
    pm.add_policy(name='wazuhPolicy', policy={
        'actions': ['*:*'],
        'resources': ['*:*'],
        'effect': 'allow'
    })

with RolesManager() as rm:
    rm.add_role('wazuh', {
        "FIND": {
            "r'^auth[a-zA-Z]+$'": ["administrator"]
        }
    })
    rm.add_role('wazuh-app', {
        "FIND": {
            "r'^auth[a-zA-Z]+$'": ["administrator-app"]
        }
    })

with RolesPoliciesManager() as rpm:
    rpm.add_policy_to_role_admin(role_id=rm.get_role(name='wazuh').id, policy_id=pm.get_policy(name='wazuhPolicy').id)