# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from datetime import datetime
from enum import IntEnum
from shutil import chown
from time import time

import yaml
from sqlalchemy import create_engine, UniqueConstraint, Column, DateTime, String, Integer, ForeignKey, Boolean
from sqlalchemy import desc
from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy.orm.exc import UnmappedInstanceError
from werkzeug.security import check_password_hash, generate_password_hash

from api.configuration import security_conf
from api.constants import SECURITY_PATH

# Max reserved ID value
max_id_reserved = 99

# Start a session and set the default security elements
_auth_db_file = os.path.join(SECURITY_PATH, 'rbac.db')
_engine = create_engine('sqlite:///' + _auth_db_file, echo=False)
_Base = declarative_base()
_Session = sessionmaker(bind=_engine)

# User IDs reserved for administrator users, these can not be modified or deleted
admin_user_ids = [1, 2]

# IDs reserved for administrator roles and policies, these can not be modified or deleted
admin_role_ids = [1, 2, 3, 4, 5, 6, 7]
admin_policy_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]

# Required rules for role
# Key: Role - Value: Rules
required_rules_for_role = {1: [1, 2]}
required_rules = {required_rule for r in required_rules_for_role.values() for required_rule in r}


def json_validator(data):
    """Function that returns True if the provided data is a valid dict, otherwise it will return False

    :param data: Data that we want to check
    :return: True -> Valid dict | False -> Not a dict or invalid dict
    """
    if isinstance(data, dict):
        return True

    return False


# Error codes for Roles and Policies managers
class SecurityError(IntEnum):
    # The element already exist in the database
    ALREADY_EXIST = 0
    # The element is invalid, missing format or property
    INVALID = -1
    # The role does not exist in the database
    ROLE_NOT_EXIST = -2
    # The policy does not exist in the database
    POLICY_NOT_EXIST = -3
    # Admin resources of the system
    ADMIN_RESOURCES = -4
    # The role does not exist in the database
    USER_NOT_EXIST = -5
    # The token-rule does not exist in the database
    TOKEN_RULE_NOT_EXIST = -6
    # The rule does not exist in the database
    RULE_NOT_EXIST = -7


class RolesRules(_Base):
    """
    Relational table between Roles and Policies, in this table are stored the relationship between the both entities
    The information stored from Roles and Policies are:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        level: Priority in case of multiples policies, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "roles_rules"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    rule_id = Column('rule_id', Integer, ForeignKey("rules.id", ondelete='CASCADE'))
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('role_id', 'rule_id', name='role_rule'),
                      )


# Declare relational tables
class RolesPolicies(_Base):
    """
    Relational table between Roles and Policies, in this table are stored the relationship between the both entities
    The information stored from Roles and Policies are:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        level: Priority in case of multiples policies, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "roles_policies"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    policy_id = Column('policy_id', Integer, ForeignKey("policies.id", ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('role_id', 'policy_id', name='role_policy'),
                      )


class UserRoles(_Base):
    """
    Relational table between User and Roles, in this table are stored the relationship between the both entities
    The information stored from User and Roles are:
        id: ID of the relationship
        user_id: ID of the user
        role_id: ID of the role
        level: Priority in case of multiples roles, higher = more priority
        created_at: Date of the relationship creation
    """
    __tablename__ = "user_roles"

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    user_id = Column('user_id', String(32), ForeignKey("users.id", ondelete='CASCADE'))
    role_id = Column('role_id', Integer, ForeignKey("roles.id", ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('user_id', 'role_id', name='user_role'),
                      )


# Declare basic tables
class UsersTokenBlacklist(_Base):
    """
    This table contains the users with an invalid token and for how long
    The information stored is:
        user_id: Affected user id
        nbf_invalid_until: The tokens that has an nbf prior to this timestamp will be invalidated
        is_valid_until: Deadline for the rule's validity. To ensure that we can delete this rule,
        the deadline will be the time of token creation plus the time of token validity.
        This way, when we delete this rule, we ensure the invalid tokens have already expired.
    """
    __tablename__ = "users_token_blacklist"

    user_id = Column('user_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer)
    is_valid_until = Column('is_valid_until', Integer)
    __table_args__ = (UniqueConstraint('user_id', name='user_invalidation_rule'),)

    def __init__(self, user_id):
        self.user_id = user_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = self.nbf_invalid_until + security_conf['auth_token_exp_timeout']

    def to_dict(self):
        """Return the information of the token rule.

        :return: Dict with the information
        """
        return {'user_id': self.user_id, 'nbf_invalid_until': self.nbf_invalid_until,
                'is_valid_until': self.is_valid_until}


class RolesTokenBlacklist(_Base):
    """
    This table contains the roles with an invalid token and for how long
    The information stored is:
        role_id: Affected role id
        nbf_invalid_until: The tokens that have an nbf prior to this timestamp will be invalidated
        is_valid_until: Deadline for the rule's validity. To ensure that we can delete this rule,
        the deadline will be the time of token creation plus the time of token validity.
        This way, when we delete this rule, we ensure the invalid tokens have already expired.
    """
    __tablename__ = "roles_token_blacklist"

    role_id = Column('role_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer)
    is_valid_until = Column('is_valid_until', Integer)
    __table_args__ = (UniqueConstraint('role_id', name='role_invalidation_rule'),)

    def __init__(self, role_id):
        self.role_id = role_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = self.nbf_invalid_until + security_conf['auth_token_exp_timeout']

    def to_dict(self):
        """Return the information of the token rule.

        :return: Dict with the information
        """
        return {'role_id': self.role_id, 'nbf_invalid_until': self.nbf_invalid_until,
                'is_valid_until': self.is_valid_until}


class User(_Base):
    __tablename__ = 'users'

    id = Column('id', Integer, primary_key=True)
    username = Column(String(32))
    password = Column(String(256))
    allow_run_as = Column(Boolean, default=False, nullable=False)
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('username', name='username_restriction'),)

    # Relations
    roles = relationship("Roles", secondary='user_roles',
                         backref=backref("rolesu", cascade="all, delete", order_by=UserRoles.role_id), lazy='dynamic')

    def __init__(self, username, password, allow_run_as=False, user_id=None):
        self.id = user_id
        self.username = username
        self.password = password
        self.allow_run_as = allow_run_as
        self.created_at = datetime.utcnow()

    def __repr__(self):
        return f"<User(user={self.username})"

    def _get_roles_id(self):
        roles = list()
        for role in self.roles:
            roles.append(role.get_role()['id'])

        return roles

    def get_roles(self):
        return list(self.roles)

    def get_user(self):
        """User's getter

        :return: Dict with the information of the user
        """
        return {'id': self.id, 'username': self.username,
                'roles': self._get_roles_id(), 'allow_run_as': self.allow_run_as}

    def to_dict(self):
        """Return the information of one policy and the roles that have assigned

        :return: Dict with the information
        """
        with UserRolesManager() as urm:
            return {'id': self.id, 'username': self.username,
                    'allow_run_as': self.allow_run_as,
                    'roles': [role.id for role in urm.get_all_roles_from_user(user_id=str(self.id))]}


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
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20))
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_role'),)

    # Relations
    policies = relationship("Policies", secondary='roles_policies',
                            backref=backref("policiess", cascade="all, delete", order_by=id), lazy='dynamic')
    users = relationship("User", secondary='user_roles',
                         backref=backref("userss", cascade="all, delete", order_by=UserRoles.user_id), lazy='dynamic')
    rules = relationship("Rules", secondary='roles_rules',
                         backref=backref("ruless", cascade="all, delete", order_by=RolesRules.id), lazy='dynamic')

    def __init__(self, name, role_id=None):
        self.id = role_id
        self.name = name
        self.created_at = datetime.utcnow()

    def get_role(self):
        """Role's getter

        :return: Dict with the information of the role
        """
        return {'id': self.id, 'name': self.name}

    def get_policies(self):
        return list(self.policies)

    def to_dict(self):
        """Return the information of one role and the users, policies and rules assigned to it.

        :return: Dict with the information
        """
        with RolesPoliciesManager() as rpm:
            return {'id': self.id, 'name': self.name,
                    'policies': [policy.id for policy in rpm.get_all_policies_from_role(role_id=self.id)],
                    'users': [user.id for user in self.users],
                    'rules': [rule.id for rule in self.rules]}


class Rules(_Base):
    """
    Rules table. In this table we are going to save all the information about the rules. The data that we will
    store is:
        id: ID of the rule, this is self assigned
        name: Name of the rule
        rule: Rule body
        created_at: Date of the rule creation
    """
    __tablename__ = "rules"

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20))
    rule = Column('rule', TEXT)
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='rule_name'),)

    # Relations
    roles = relationship("Roles", secondary='roles_rules',
                         backref=backref("ruless", cascade="all, delete", order_by=id), lazy='dynamic')

    def __init__(self, name, rule, rule_id=None):
        self.id = rule_id
        self.name = name
        self.rule = rule
        self.created_at = datetime.utcnow()

    def get_rule(self):
        """Rule getter.

        :return: Dict with the information of the rule
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule)}

    def to_dict(self):
        """Return the information of one rule and its roles

        :return: Dict with the information
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule),
                'roles': [role.id for role in self.roles]}


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
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20))
    policy = Column('policy', TEXT)
    created_at = Column('created_at', DateTime, default=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_policy'),
                      UniqueConstraint('policy', name='policy_definition'))

    # Relations
    roles = relationship("Roles", secondary='roles_policies',
                         backref=backref("roless", cascade="all, delete", order_by=id), lazy='dynamic')

    def __init__(self, name, policy, policy_id=None):
        self.id = policy_id
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
        with RolesPoliciesManager() as rpm:
            return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy),
                    'roles': [role.id for role in rpm.get_all_roles_from_policy(policy_id=self.id)]}


class TokenManager:
    """
    This class is the manager of Token blacklist, this class provides
    all the methods needed for the token blacklist administration.
    """

    def is_token_valid(self, token_nbf_time: int, user_id: int = None, role_id: int = None):
        """Check if specified token is valid

        Parameters
        ----------
        user_id : int
            Current token's user id
        role_id : int
            Current token's role id
        token_nbf_time : int
            Token's issue timestamp

        Returns
        -------
        True if is valid, False if not
        """
        try:
            user_rule = self.session.query(UsersTokenBlacklist).filter_by(user_id=user_id).first()
            role_rule = self.session.query(RolesTokenBlacklist).filter_by(role_id=role_id).first()
            return (not user_rule or (token_nbf_time > user_rule.nbf_invalid_until)) and \
                   (not role_rule or (token_nbf_time > role_rule.nbf_invalid_until))
        except IntegrityError:
            return True

    def get_all_rules(self):
        """Return two dictionaries where keys are role_ids and user_ids and the value of each them is nbf_invalid_until

        Returns
        -------
        dict
        """
        try:
            users_rules = map(UsersTokenBlacklist.to_dict, self.session.query(UsersTokenBlacklist).all())
            roles_rules = map(RolesTokenBlacklist.to_dict, self.session.query(RolesTokenBlacklist).all())
            users_format_rules, roles_format_rules = dict(), dict()
            for rule in list(users_rules):
                users_format_rules[rule['user_id']] = rule['nbf_invalid_until']
            for rule in list(roles_rules):
                roles_format_rules[rule['role_id']] = rule['nbf_invalid_until']
            return users_format_rules, roles_format_rules
        except IntegrityError:
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def add_user_roles_rules(self, users: set = None, roles: set = None):
        """Add new rules for users-token or roles-token.
        Both, nbf_invalid_until and is_valid_until are generated automatically

        Parameters
        ----------
        users : set
            Set with the affected users
        roles : set
            Set with the affected roles

        Returns
        -------
        True if the success, SecurityError.ALREADY_EXIST if failed
        """
        if users is None:
            users = set()
        if roles is None:
            roles = set()

        try:
            self.delete_all_expired_rules()
            for user_id in users:
                self.delete_rule(user_id=user_id)
                self.session.add(UsersTokenBlacklist(user_id=user_id))
                self.session.commit()
            for role_id in roles:
                self.delete_rule(role_id=role_id)
                self.session.add(RolesTokenBlacklist(role_id=role_id))
                self.session.commit()

            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, user_id: int = None, role_id: int = None):
        """Remove the rule for the specified role

        Parameters
        ----------
        user_id : int
            Desired user_id
        role_id : int
            Desired role_id

        Returns
        -------
        True if success, SecurityError.TOKEN_RULE_NOT_EXIST if failed
        """
        try:
            self.session.query(UsersTokenBlacklist).filter_by(user_id=user_id).delete()
            self.session.query(RolesTokenBlacklist).filter_by(role_id=role_id).delete()
            self.session.commit()

            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def delete_all_expired_rules(self):
        """Delete all expired rules in the system

        Returns
        -------
        List of removed user and role rules
        """
        try:
            list_users, list_roles = list(), list()
            current_time = int(time())
            users_tokens_in_blacklist = self.session.query(UsersTokenBlacklist).all()
            for user_token in users_tokens_in_blacklist:
                token_rule = self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_users.append(user_token.user_id)
            roles_tokens_in_blacklist = self.session.query(RolesTokenBlacklist).all()
            for role_token in roles_tokens_in_blacklist:
                token_rule = self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_roles.append(role_token.role_id)

            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_rules(self):
        """Delete all existent rules in the system

        Returns
        -------
        List of removed user and role rules
        """
        try:
            list_users, list_roles = list(), list()
            users_tokens_in_blacklist = self.session.query(UsersTokenBlacklist).all()
            roles_tokens_in_blacklist = self.session.query(RolesTokenBlacklist).all()
            clean = False
            for user_token in users_tokens_in_blacklist:
                list_roles.append(user_token.user_id)
                self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id).delete()
                clean = True
            for role_token in roles_tokens_in_blacklist:
                list_roles.append(role_token.role_id)
                self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id).delete()
                clean = True

            clean and self.session.commit()
            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class AuthenticationManager:
    """Class for dealing with authentication stuff without worrying about database.
    It manages users and token generation.
    """

    def add_user(self, username: str, password: str, allow_run_as: bool = False, check_default: bool = True):
        """Creates a new user if it does not exist.

        Parameters
        ----------
        username : str
            Unique user name
        password : str
            Password provided by user. It will be stored hashed
        allow_run_as : bool
            Flag that indicates if the user can log into the API throw an authorization context
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True if the user has been created successfully. False otherwise (i.e. already exists)
        """
        try:
            user_id = None
            try:
                if check_default and self.session.query(User).order_by(desc(User.id)
                                                                       ).limit(1).scalar().id < max_id_reserved:
                    user_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(User(username=username, password=generate_password_hash(password),
                                  allow_run_as=allow_run_as, user_id=user_id))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def update_user(self, user_id: str, password: str, allow_run_as: bool):
        """Update the password an existent user

        Parameters
        ----------
        user_id : str
            Unique user id
        password : str
            Password provided by user. It will be stored hashed
        allow_run_as : bool
            Enable authorization context login method for the new user

        Returns
        -------
        True if the user has been modify successfully. False otherwise
        """
        try:
            user = self.session.query(User).filter_by(id=user_id).first()
            if user is not None:
                if password:
                    user.password = generate_password_hash(password)
                if allow_run_as is not None:
                    user.allow_run_as = allow_run_as
                if password or allow_run_as is not None:
                    self.session.commit()
                    return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_user(self, user_id: str):
        """Remove the specified user

        Parameters
        ----------
        user_id : str
            Unique user id

        Returns
        -------
        True if the user has been delete successfully. False otherwise
        """
        if int(user_id) in admin_user_ids:
            return SecurityError.ADMIN_RESOURCES

        try:
            if self.session.query(User).filter_by(id=user_id).first():
                # If the user has one or more roles associated with it, the associations will be eliminated.
                with UserRolesManager() as urm:
                    urm.remove_all_roles_in_user(user_id=user_id)
                self.session.delete(self.session.query(User).filter_by(id=user_id).first())
                self.session.commit()
                return True
            else:
                return False
        except UnmappedInstanceError:
            # User already deleted
            return False

    def check_user(self, username, password):
        """Validates a username-password pair.

        :param username: string Unique user name
        :param password: string Password to be checked against the one saved in the database
        :return: True if username and password matches. False otherwise.
        """
        user = self.session.query(User).filter_by(username=username).first()
        return check_password_hash(user.password, password) if user else False

    def get_user(self, username: str = None):
        """Get an specified user in the system
        :param username: string Unique user name
        :return: An specified user
        """
        try:
            if username is not None:
                return self.session.query(User).filter_by(username=username).first().to_dict()
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_user_id(self, user_id: str = None):
        """Get an specified user in the system.

        Parameters
        ----------
        user_id : str
            Unique user id

        Returns
        -------
        Information about the specified user
        """
        try:
            if user_id is not None:
                return self.session.query(User).filter_by(id=user_id).first().to_dict()
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def user_allow_run_as(self, username: str = None):
        """Get the allow_run_as's flag of specified user in the system

        :param username: string Unique user name
        :return: An specified user
        """
        try:
            if username is not None:
                return self.session.query(User).filter_by(username=username).first().get_user()['allow_run_as']
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_users(self):
        """Get all users in the system

        :return: All users
        """
        try:
            users = self.session.query(User).all()
        except IntegrityError:
            self.session.rollback()
            return False

        user_ids = list()
        for user in users:
            if user is not None:
                user_dict = {
                    'user_id': str(user.id),
                    'username': user.username
                }
                user_ids.append(user_dict)
        return user_ids

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


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
            return role.to_dict()
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
            return role.to_dict()
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

    def add_role(self, name: str, check_default: bool = True):
        """Add a new role.

        Parameters
        ----------
        name : str
            Name of the new role
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Role already exist
        """
        try:
            role_id = None
            try:
                if check_default and self.session.query(Roles).order_by(desc(Roles.id)
                                                                        ).limit(1).scalar().id < max_id_reserved:
                    role_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Roles(name=name, role_id=role_id))
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
            if int(role_id) not in admin_role_ids:
                # If the role does not exist we rollback the changes
                if self.session.query(Roles).filter_by(id=role_id).first() is None:
                    return False
                # If the role has one or more policies associated with it, the associations will be eliminated.
                with UserRolesManager() as urm:
                    urm.remove_all_users_in_role(role_id=role_id)
                with RolesPoliciesManager() as rpm:
                    rpm.remove_all_policies_in_role(role_id=role_id)
                # Remove all associated rules
                with RolesRulesManager() as rrum:
                    rrum.remove_all_rules_in_role(role_id=role_id)
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
            if self.get_role(role_name) is not None and self.get_role(role_name)['id'] not in admin_role_ids:
                role_id = self.session.query(Roles).filter_by(name=role_name).first().id
                if role_id:
                    self.delete_role(role_id=role_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
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
                if int(role.id) not in admin_role_ids:
                    with RolesPoliciesManager() as rpm:
                        rpm.remove_all_policies_in_role(role_id=role.id)
                    list_roles.append(int(role.id))
                    self.session.query(Roles).filter_by(id=role.id).delete()
                    self.session.commit()
            return list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def update_role(self, role_id: int, name: str):
        """Update an existent role in the system

        :param role_id: ID of the role to be updated
        :param name: New name for the role
        :return: True -> Success | Invalid rule | Name already in use | Role not exist
        """
        try:
            role_to_update = self.session.query(Roles).filter_by(id=role_id).first()
            if role_to_update and role_to_update is not None:
                if role_to_update.id not in admin_role_ids:
                    # Change the name of the role
                    if name is not None:
                        role_to_update.name = name
                    self.session.commit()
                    return True
                return SecurityError.ADMIN_RESOURCES
            return SecurityError.ROLE_NOT_EXIST
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class RulesManager:
    """
        This class is Rules manager. This class provides all the methods needed for the rules administration.
        """

    def get_rule(self, rule_id: int):
        """Get the information about one rule specified by id.

        Parameters
        ----------
        rule_id : int
            ID of the rule.

        Returns
        -------
        Rule object with all its information.
        """
        try:
            rule = self.session.query(Rules).filter_by(id=rule_id).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rule_by_name(self, rule_name: str):
        """Get the information about one rule specified by name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.

        Returns
        -------
        Rule object with all its information.
        """
        try:
            rule = self.session.query(Rules).filter_by(name=rule_name).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rules(self):
        """Get the information about all rules in the system.

        Returns
        -------
        List of Rule objects with all of its information | False -> No rules in the system
        """
        try:
            rules = self.session.query(Rules).all()
            return rules
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def add_rule(self, name: str, rule: dict, check_default: bool = True):
        """Add a new rule.

        Parameters
        ----------
        name : str
            Name of the new rule.
        rule : dict
            Rule dictionary.
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Rule already exists | Invalid rule
        """
        try:
            if rule is not None and not json_validator(rule):
                return SecurityError.INVALID
            rule_id = None
            try:
                if check_default and \
                        self.session.query(Policies).order_by(desc(Policies.id)
                                                              ).limit(1).scalar().id < max_id_reserved:
                    rule_id = max_id_reserved + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Rules(name=name, rule=json.dumps(rule), rule_id=rule_id))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, rule_id: int):
        """Delete an existent rule from the system specified by its ID.

        Parameters
        ----------
        rule_id : int
            Id of the rule.
        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if rule_id not in required_rules:
                # If the role does not exist we rollback the changes
                if self.session.query(Rules).filter_by(id=rule_id).first() is None:
                    return False
                # If the role has one or more rules associated with it, the associations will be eliminated.
                with RolesRulesManager() as rrum:
                    rrum.remove_all_roles_in_rule(rule_id=rule_id)
                # Finally we delete the role
                self.session.query(Rules).filter_by(id=rule_id).delete()
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_rule_by_name(self, rule_name: str):
        """Delete an existent rule from the system specified by its name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.
        Returns
        -------
        True -> Success | False -> Failure | ADMIN_RESOURCES -> Admin rules cannot be deleted
        """
        try:
            if self.get_rule_by_name(rule_name) is not None and \
                    self.get_rule_by_name(rule_name)['id'] not in required_rules:
                rule_id = self.session.query(Rules).filter_by(name=rule_name).first().id
                if rule_id:
                    self.delete_rule(rule_id=rule_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_rules(self):
        """Delete all existent rules from the system.

        Returns
        -------
        List of deleted rules -> Success | False -> Failure
        """
        try:
            list_rules = list()
            rules = self.session.query(Rules).all()
            for rule in rules:
                if int(rule.id) not in required_rules:
                    with RolesRulesManager() as rrum:
                        rrum.remove_all_roles_in_rule(rule_id=rule.id)
                    list_rules.append(int(rule.id))
                    self.session.query(Rules).filter_by(id=rule.id).delete()
                    self.session.commit()
            return list_rules
        except IntegrityError:
            self.session.rollback()
            return False

    def update_rule(self, rule_id: int, name: str, rule: dict):
        """Update an existent rule in the system.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        name : name
            Name of the rule.
        rule : dict
            Dictionary with the rule itself.

        Returns
        -------
        True -> Success | Invalid rule | Name already in use | Rule already in use | Rule not exists
        """
        try:
            rule_to_update = self.session.query(Rules).filter_by(id=rule_id).first()
            if rule_to_update and rule_to_update is not None:
                if rule_to_update.id not in required_rules:
                    # Rule is not a valid json
                    if rule is not None and not json_validator(rule):
                        return SecurityError.INVALID
                    # Change the rule
                    if name is not None:
                        rule_to_update.name = name
                    if rule is not None:
                        rule_to_update.rule = json.dumps(rule)
                    self.session.commit()
                    return True
                return SecurityError.ADMIN_RESOURCES
            return SecurityError.RULE_NOT_EXIST
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

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
            return policy.to_dict()
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
            return policy.to_dict()
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

    def add_policy(self, name: str, policy: dict, check_default: bool = True):
        """Add a new policy.

        Parameters
        ----------
        name : str
            Name of the new policy
        policy : dict
            Policy of the new policy
        check_default : bool
            Flag that indicates if the user ID can be less than max_id_reserved

        Returns
        -------
        True -> Success | Invalid policy | Missing key (actions, resources, effect) or invalid policy (regex)
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
                        regex = r'^[a-z_\-*]+:[a-z0-9_\-*]+([:|&]{0,1}[a-z0-9_\-*]+)*$'
                        for action in policy['actions']:
                            if not re.match(regex, action):
                                return SecurityError.INVALID
                        for resource in policy['resources']:
                            if not re.match(regex, resource):
                                return SecurityError.INVALID
                        policy_id = None
                        try:
                            if check_default and \
                                    self.session.query(Policies).order_by(desc(Policies.id)
                                                                          ).limit(1).scalar().id < max_id_reserved:
                                policy_id = max_id_reserved + 1
                        except (TypeError, AttributeError):
                            pass
                        self.session.add(Policies(name=name, policy=json.dumps(policy), policy_id=policy_id))
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
            if int(policy_id) not in admin_policy_ids:
                # If there is no policy continues
                if self.session.query(Policies).filter_by(id=policy_id).first() is None:
                    return False
                # If the policy has relationships with roles, it first eliminates those relationships.
                with RolesPoliciesManager() as rpm:
                    rpm.remove_all_roles_in_policy(policy_id=policy_id)
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
            if self.get_policy(policy_name) is not None and \
                    self.get_policy(name=policy_name)['id'] not in admin_policy_ids:
                policy_id = self.session.query(Policies).filter_by(name=policy_name).first().id
                if policy_id:
                    self.delete_policy(policy_id=policy_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
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
                if int(policy.id) not in admin_policy_ids:
                    with RolesPoliciesManager() as rpm:
                        rpm.remove_all_roles_in_policy(policy_id=policy.id)
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
                if policy_to_update.id not in admin_policy_ids:
                    # Policy is not a valid json
                    if policy is not None and not json_validator(policy):
                        return SecurityError.INVALID
                    if name is not None:
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
            return SecurityError.ALREADY_EXIST

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class UserRolesManager:
    """
    This class is the manager of the relationship between the user and the roles, this class provided
    all the methods needed for the user-roles administration.
    """

    def add_role_to_user(self, user_id: str, role_id: int, position: int = None, force_admin: bool = False):
        """Add a relation between one specified user and one specified role.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of the role
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator user is not allowed. If True, it will be applied to admin users too

        Returns
        -------
        True -> Success | False -> Failure | User not found | Role not found | Existing relationship | Invalid level
        """
        try:
            # Create a role-policy relationship if both exist
            if user_id not in admin_user_ids or force_admin:
                user = self.session.query(User).filter_by(id=user_id).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if position is not None or \
                        self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is None:
                    if position is not None and \
                            self.session.query(UserRoles).filter_by(user_id=user_id, level=position).first() and \
                            self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is None:
                        user_roles = [row for row in self.session.query(
                            UserRoles).filter(UserRoles.user_id == user_id, UserRoles.level >= position
                                              ).order_by(UserRoles.level).all()]
                        new_level = position
                        for relation in user_roles:
                            relation.level = new_level + 1
                            new_level += 1

                    user.roles.append(role)
                    user_role = self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first()
                    if position is None:
                        roles = user.get_roles()
                        position = len(roles) - 1
                    else:
                        max_position = max([row.level for row in self.session.query(UserRoles).filter_by(
                            user_id=user_id).all()])
                        if max_position == 0 and len(list(user.roles)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    user_role.level = position

                    self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def add_user_to_role(self, user_id: str, role_id: int, position: int = -1):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of the role
        position : int
            Order to be applied in case of multiples roles in the same user

        Returns
        -------
        True -> Success | False -> Failure | User not found | Role not found | Existing relationship | Invalid level
        """
        return self.add_role_to_user(user_id=user_id, role_id=role_id, position=position)

    def get_all_roles_from_user(self, user_id: str):
        """Get all the roles related with the specified user.

        Parameters
        ----------
        user_id : str
            ID of the user

        Returns
        -------
        List of roles related with the user -> Success | False -> Failure
        """
        try:
            user_roles = self.session.query(UserRoles).filter_by(user_id=user_id).order_by(UserRoles.level).all()
            roles = list()
            for relation in user_roles:
                roles.append(self.session.query(Roles).filter_by(id=relation.role_id).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_users_from_role(self, role_id: int):
        """Get all the users related with the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        List of users related with the role -> Success | False -> Failure
        """
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            return map(User.to_dict, role.users)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_user_role(self, user_id: str, role_id: int):
        """Check if the relationship user-role exist.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of th role

        Returns
        -------
        True -> Existent relationship | False -> Failure | User not exist
        """
        try:
            user = self.session.query(User).filter_by(id=user_id).first()
            if user is None:
                return SecurityError.USER_NOT_EXIST
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            role = user.roles.filter_by(id=role_id).first()
            if role is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_role_user(self, user_id: str, role_id: int):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of th role

        Returns
        -------
        True -> Existent relationship | False -> Failure | User not exist
        """
        return self.exist_user_role(user_id=user_id, role_id=role_id)

    def remove_role_in_user(self, user_id: str, role_id: int):
        """Remove a role-policy relationship if both exist. Does not eliminate role and policy.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure | User not exist | Role not exist | Non-existent relationship
        """
        try:
            if user_id not in admin_user_ids:  # Administrator
                user = self.session.query(User).filter_by(id=user_id).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if self.session.query(UserRoles).filter_by(user_id=user_id, role_id=role_id).first() is not None:
                    user = self.session.query(User).get(user_id)
                    role = self.session.query(Roles).get(role_id)
                    user.roles.remove(role)
                    self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_user_in_role(self, user_id: str, role_id: int):
        """Clone of the previous function.

        Parameters
        ----------
        user_id : str
            ID of the user
        role_id : int
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure | User not exist | Role not exist | Non-existent relationship
        """
        return self.remove_role_in_user(user_id=user_id, role_id=role_id)

    def remove_all_roles_in_user(self, user_id: str):
        """Removes all relations with roles. Does not eliminate users and roles.

        Parameters
        ----------
        user_id : str
            ID of the user

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if user_id not in admin_user_ids:
                roles = self.session.query(User).filter_by(id=user_id).first().roles
                for role in roles:
                    self.remove_role_in_user(user_id=user_id, role_id=role.id)
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_users_in_role(self, role_id: int):
        """Clone of the previous function.

        Parameters
        ----------
        role_id : str
            ID of the role

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            if int(role_id) not in admin_role_ids:
                users = self.session.query(Roles).filter_by(id=role_id).first().users
                for user in users:
                    if user.id not in admin_user_ids:
                        self.remove_user_in_role(user_id=user.id, role_id=role_id)
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_user_role(self, user_id: str, actual_role_id: int, new_role_id: int, position: int = -1):
        """Replace one existing relationship with another one.

        Parameters
        ----------
        user_id : str
            ID of the user
        actual_role_id : int
            ID of the role
        new_role_id : int
            ID of the new role
        position : int
            Order to be applied in case of multiples roles in the same user

        Returns
        -------
        True -> Success | False -> Failure
        """
        if user_id not in admin_user_ids and self.exist_user_role(user_id=user_id, role_id=actual_role_id) and \
                self.session.query(Roles).filter_by(id=new_role_id).first() is not None:
            self.remove_role_in_user(user_id=user_id, role_id=actual_role_id)
            self.add_user_to_role(user_id=user_id, role_id=new_role_id, position=position)
            return True

        return False

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

    def add_policy_to_role(self, role_id: int, policy_id: int, position: int = None, force_admin: bool = False):
        """Add a relation between one specified policy and one specified role

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator roles is not allowed. If True, it will be applied to admin roles too

        Returns
        -------
        bool
            True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """

        def check_max_level(role_id_level):
            return max([r.level for r in self.session.query(RolesPolicies).filter_by(role_id=role_id_level).all()])

        try:
            # Create a role-policy relationship if both exist
            if int(role_id) not in admin_role_ids or force_admin:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST
                if position is not None or self.session.query(
                        RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is None:
                    if position is not None and \
                            self.session.query(RolesPolicies).filter_by(role_id=role_id, level=position).first() and \
                            self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                                        policy_id=policy_id).first() is None:
                        role_policies = [row for row in self.session.query(
                            RolesPolicies).filter(RolesPolicies.role_id == role_id, RolesPolicies.level >= position
                                                  ).order_by(RolesPolicies.level).all()]
                        new_level = position
                        for relation in role_policies:
                            relation.level = new_level + 1
                            new_level += 1

                    role.policies.append(policy)
                    role_policy = self.session.query(RolesPolicies).filter_by(role_id=role_id,
                                                                              policy_id=policy_id).first()
                    if position is None or position > check_max_level(role_id) + 1:
                        position = len(role.get_policies()) - 1
                    else:
                        max_position = max([row.level for row in self.session.query(RolesPolicies).filter_by(
                            role_id=role_id).all()])
                        if max_position == 0 and len(list(role.policies)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    role_policy.level = position

                    self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def add_role_to_policy(self, policy_id: int, role_id: int, position: int = None):
        """Clone of the previous function

        Parameters
        ----------
        role_id : int
            ID of the role
        policy_id : int
            ID of the policy
        position : int
            Order to be applied in case of multiples roles in the same user
        force_admin : bool
            By default, changing an administrator roles is not allowed. If True, it will be applied to admin roles too

        Returns
        -------
        bool
            True -> Success | False -> Failure | Role not found | Policy not found | Existing relationship
        """
        return self.add_policy_to_role(role_id=role_id, policy_id=policy_id, position=position)

    def get_all_policies_from_role(self, role_id):
        """Get all the policies related with the specified role

        :param role_id: ID of the role
        :return: List of policies related with the role -> Success | False -> Failure
        """
        try:
            role_policies = self.session.query(RolesPolicies).filter_by(role_id=role_id).order_by(
                RolesPolicies.level).all()
            policies = list()
            for relation in role_policies:
                policy = self.session.query(Policies).filter_by(id=relation.policy_id).first()
                if policy:
                    policies.append(policy)
            return policies
        except (IntegrityError, AttributeError):
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
        except (IntegrityError, AttributeError):
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
        """Remove a role-policy relationship if both exist. Does not eliminate role and policy

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Success | False -> Failure | Role not exist | Policy not exist | Non-existent relationship
        """
        try:
            if int(role_id) not in admin_role_ids:  # Administrator
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

    def remove_role_in_policy(self, role_id: int, policy_id: int):
        """Clone of the previous function

        :param role_id: ID of the role
        :param policy_id: ID of the policy
        :return: True -> Success | False -> Failure | Role not exist | Policy not exist | Non-existent relationship
        """
        return self.remove_policy_in_role(role_id=role_id, policy_id=policy_id)

    def remove_all_policies_in_role(self, role_id: int):
        """Removes all relations with policies. Does not eliminate roles and policies

        :param role_id: ID of the role
        :return: True -> Success | False -> Failure
        """
        try:
            if int(role_id) not in admin_role_ids:
                policies = self.session.query(Roles).filter_by(id=role_id).first().policies
                for policy in policies:
                    if policy.id not in admin_policy_ids:
                        self.remove_policy_in_role(role_id=role_id, policy_id=policy.id)
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_roles_in_policy(self, policy_id: int):
        """Removes all relations with roles. Does not eliminate roles and policies

        :param policy_id: ID of the policy
        :return: True -> Success | False -> Failure
        """
        try:
            if int(policy_id) not in admin_policy_ids:
                roles = self.session.query(Policies).filter_by(id=policy_id).first().roles
                for rol in roles:
                    if rol.id not in admin_role_ids:
                        self.remove_policy_in_role(role_id=rol.id, policy_id=policy_id)
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id: int, actual_policy_id: int, new_policy_id: int):
        """Replace one existing relationship with another one

        :param role_id: Role to be modified
        :param actual_policy_id: Actual policy ID
        :param new_policy_id: New policy ID
        :return: True -> Success | False -> Failure
        """
        if int(role_id) not in admin_role_ids and \
                self.exist_role_policy(role_id=role_id, policy_id=actual_policy_id) and \
                self.session.query(Policies).filter_by(id=new_policy_id).first() is not None:
            self.remove_policy_in_role(role_id=role_id, policy_id=actual_policy_id)
            self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id)
            return True

        return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class RolesRulesManager:
    """
    This class is the manager of the relationships between the roles and the rules. This class provides
    all the methods needed for the roles-rules administration.
    """

    def add_rule_to_role(self, rule_id: int, role_id: int):
        """Add a relation between one specified role and one specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        role_id : int
            ID of the role.

        Returns
        -------
        True -> Success | False -> Failure | Role not found | Rule not found | Existing relationship
        """
        try:
            # Create a rule-role relationship if both exist
            rule = self.session.query(Rules).filter_by(id=rule_id).first()
            if rule is None:
                return SecurityError.RULE_NOT_EXIST
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            if self.session.query(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).first() is None:
                role.rules.append(rule)
                self.session.commit()
                return True
            else:
                return SecurityError.ALREADY_EXIST
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def get_all_rules_from_role(self, role_id: int):
        """Get all the rules related to the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
            List of rules related with the role -> Success | False -> Failure
        """
        try:
            rule_roles = self.session.query(RolesRules).filter_by(role_id=role_id).order_by(RolesRules.id).all()
            rules = list()
            for relation in rule_roles:
                rules.append(self.session.query(Rules).filter_by(id=relation.rule_id).first())
            return rules
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_roles_from_rule(self, rule_id: int):
        """Get all the roles related to the specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the rule.

        Returns
        -------
            List of roles related with the rule -> Success | False -> Failure
        """
        try:
            role_rules = self.session.query(RolesRules).filter_by(rule_id=rule_id).order_by(RolesRules.id).all()
            roles = list()
            for relation in role_rules:
                roles.append(self.session.query(Roles).filter_by(id=relation.role_id).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_role_rule(self, role_id: int, rule_id: int):
        """Check if the role-rule relationship exists.

        Parameters
        ----------
        role_id : int
            ID of the role.
        rule_id : int
            ID of the rule.

        Returns
        -------
        True -> Existent relationship | False -> Failure | Rule not exists | Role not exists
        """
        try:
            rule = self.session.query(Rules).filter_by(id=rule_id).first()
            if rule is None:
                return SecurityError.RULE_NOT_EXIST
            role = self.session.query(Roles).filter_by(id=role_id).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            match = role.rules.filter_by(id=rule_id).first()
            if match is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_rule_in_role(self, rule_id: int, role_id: int):
        """Remove a role-rule relationship if both exists. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        role_id : int
            ID of the role.

        Returns
        -------
        True -> Success | False -> Failure | Role not exists | Rule not exist s| Non-existent relationship
        """
        try:
            if rule_id not in required_rules_for_role.get(role_id, []):  # Required rule
                rule = self.session.query(Rules).filter_by(id=rule_id).first()
                if rule is None:
                    return SecurityError.RULE_NOT_EXIST
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if self.session.query(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).first() is not None:
                    rule = self.session.query(Rules).get(rule_id)
                    role = self.session.query(Roles).get(role_id)
                    rule.roles.remove(role)
                    self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_role_in_rule(self, rule_id: int, role_id: int):
        """Remove a role-rule relationship if both exists. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        role_id : int
            ID of the role.

        Returns
        -------
        True -> Success | False -> Failure | Role not exists | Rule not exist s| Non-existent relationship
        """
        return self.remove_rule_in_role(rule_id=rule_id, role_id=role_id)

    def remove_all_roles_in_rule(self, rule_id: int):
        """Remove all relations between a rule and its roles. This does not delete the objects.

        Parameters
        ----------
        rule_id : int
            ID of the rule.

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            roles = self.session.query(Rules).filter_by(id=rule_id).first().roles
            for role in roles:
                self.remove_role_in_rule(rule_id=rule_id, role_id=role.id)
            return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_rules_in_role(self, role_id: int):
        """Remove all relations between a role and its rules. This does not delete the objects.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        True -> Success | False -> Failure
        """
        try:
            rules = self.session.query(Roles).filter_by(id=role_id).first().rules
            for rule in rules:
                self.remove_rule_in_role(rule_id=rule.id, role_id=role_id)
            return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_rule_role(self, rule_id: int, current_role_id: int, new_role_id: int):
        """Replace one existing role_rule relationship with another one.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        current_role_id : int
            Current ID of the role.
        new_role_id : int
            New role ID.

        Returns
        -------
        True -> Success | False -> Failure
        """
        if rule_id not in required_rules_for_role.get(int(current_role_id), []) and self.exist_role_rule(
                rule_id=rule_id,
                role_id=current_role_id) \
                and self.session.query(Roles).filter_by(id=new_role_id).first() is not None:
            self.remove_role_in_rule(rule_id=rule_id, role_id=current_role_id)
            self.add_rule_to_role(rule_id=rule_id, role_id=new_role_id)
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
chown(_auth_db_file, 'ossec', 'ossec')
os.chmod(_auth_db_file, 0o640)

default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'default')

# Create default users if they don't exist yet
with open(os.path.join(default_path, "users.yaml"), 'r') as stream:
    default_users = yaml.safe_load(stream)

    with AuthenticationManager() as auth:
        for d_username, payload in default_users[next(iter(default_users))].items():
            auth.add_user(username=d_username, password=payload['password'],
                          allow_run_as=payload['allow_run_as'], check_default=False)

# Create default roles if they don't exist yet
with open(os.path.join(default_path, "roles.yaml"), 'r') as stream:
    default_roles = yaml.safe_load(stream)

    with RolesManager() as rm:
        for d_role_name, payload in default_roles[next(iter(default_roles))].items():
            rm.add_role(name=d_role_name, check_default=False)

with open(os.path.join(default_path, 'rules.yaml'), 'r') as stream:
    default_rules = yaml.safe_load(stream)

    with RulesManager() as rum:
        for d_rule_name, payload in default_rules[next(iter(default_rules))].items():
            rum.add_rule(name=d_rule_name, rule=payload['rule'], check_default=False)

# Create default policies if they don't exist yet
with open(os.path.join(default_path, "policies.yaml"), 'r') as stream:
    default_policies = yaml.safe_load(stream)

    with PoliciesManager() as pm:
        for d_policy_name, payload in default_policies[next(iter(default_policies))].items():
            for name, policy in payload['policies'].items():
                pm.add_policy(name=f'{d_policy_name}_{name}', policy=policy, check_default=False)

# Create the relationships
with open(os.path.join(default_path, "relationships.yaml"), 'r') as stream:
    default_relationships = yaml.safe_load(stream)

    # User-Roles relationships
    with UserRolesManager() as urm:
        for d_username, payload in default_relationships[next(iter(default_relationships))]['users'].items():
            with AuthenticationManager() as am:
                d_user_id = am.get_user(username=d_username)['id']
            for d_role_name in payload['role_ids']:
                urm.add_role_to_user(user_id=d_user_id, role_id=rm.get_role(name=d_role_name)['id'], force_admin=True)

    # Role-Policies relationships
    with RolesPoliciesManager() as rpm:
        for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
            for d_policy_name in payload['policy_ids']:
                for sub_name in default_policies[next(iter(default_policies))][d_policy_name]['policies'].keys():
                    rpm.add_policy_to_role(role_id=rm.get_role(name=d_role_name)['id'],
                                           policy_id=pm.get_policy(name=f'{d_policy_name}_{sub_name}')['id'],
                                           force_admin=True)

    # Role-Rules relationships
    with RolesRulesManager() as rrum:
        for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
            for d_rule_name in payload['rule_ids']:
                rrum.add_rule_to_role(role_id=rm.get_role(name=d_role_name)['id'],
                                      rule_id=rum.get_rule_by_name(d_rule_name)['id'])
