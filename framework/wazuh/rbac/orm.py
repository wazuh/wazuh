# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import os
import re
from datetime import datetime
from enum import IntEnum
from functools import partial
from shutil import chown
from time import time
from typing import Optional, Union

import yaml
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    desc,
    or_,
)
from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from sqlalchemy.orm.exc import UnmappedInstanceError
from sqlalchemy.sql import text
from sqlalchemy.sql.expression import delete, select
from wazuh.core.common import DEFAULT_RBAC_RESOURCES, WAZUH_LIB, wazuh_gid, wazuh_uid
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.utils import get_utc_now, safe_move
from wazuh.rbac.utils import clear_cache
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger('wazuh-api')

# Max reserved ID value
WAZUH_USER_ID = 1
WAZUH_WUI_USER_ID = 2
MAX_ID_RESERVED = 99
CLOUD_RESERVED_RANGE = 89

# Start a session and set the default security elements
DB_FILE = WAZUH_LIB / 'rbac.db'
DB_FILE_TMP = f'{DB_FILE}.tmp'
CURRENT_ORM_VERSION = 1
_new_columns = {}
_engine = create_engine(f'sqlite:///{DB_FILE}', echo=False)
_Base = declarative_base()

# Required rules for role
# Key: Role - Value: Rules
REQUIRED_RULE_FOR_ROLE = {1: [1, 2]}
required_rules = {required_rule for r in REQUIRED_RULE_FOR_ROLE.values() for required_rule in r}


# Security error codes for each RBAC resource's manager
class SecurityError(IntEnum):
    """Security errors enumeration."""

    # The element already exists in the database
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
    # The relationships can not be removed
    RELATIONSHIP_ERROR = -8


# Declare relational tables


class RolesRules(_Base):
    """Class that represents the relational table storing the relationships between Roles and Rules.
    The information stored from each relationship is:
        id: ID of the relationship
        role_id: ID of the role
        rule_id: ID of the rule
        created_at: Date of the relationship creation.
    """

    __tablename__ = 'roles_rules'

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'))
    rule_id = Column('rule_id', Integer, ForeignKey('rules.id', ondelete='CASCADE'))
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('role_id', 'rule_id', name='role_rule'),)

    roles = relationship('Roles', back_populates='rules_associations')
    rules = relationship('Rules', back_populates='roles_associations')


class RolesPolicies(_Base):
    """Class that represents the relational table storing the relationships between Roles and Policies.
    The information stored from each relationship is:
        id: ID of the relationship
        role_id: ID of the role
        policy_id: ID of the policy
        level: Priority in case of multiple policies (a lower level means more priority)
        created_at: Date of the relationship creation.
    """

    __tablename__ = 'roles_policies'

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    role_id = Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'))
    policy_id = Column('policy_id', Integer, ForeignKey('policies.id', ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('role_id', 'policy_id', name='role_policy'),)

    roles = relationship('Roles', back_populates='policies_associations')
    policies = relationship('Policies', back_populates='roles_associations')


class UserRoles(_Base):
    """Class that represents the relational table storing the relationships between Users and Roles.
    The information stored from each relationship is:
        id: ID of the relationship
        user_id: ID of the user
        role_id: ID of the role
        level: Priority in case of multiple roles (a lower level means more priority)
        created_at: Date of the relationship creation.
    """

    __tablename__ = 'user_roles'

    # Schema, Many-To-Many relationship
    id = Column('id', Integer, primary_key=True)
    user_id = Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'))
    role_id = Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'))
    level = Column('level', Integer, default=0)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('user_id', 'role_id', name='user_role'),)

    users = relationship('User', back_populates='roles_associations')
    roles = relationship('Roles', back_populates='users_associations')


# Blacklists


class RunAsTokenBlacklist(_Base):
    """Class that represents the table containing the tokens given through the run_as login endpoint that are considered
    invalid. An invalid token is an expired or revoked token.
    The information stored is:
        nbf_invalid_until: Time of the issue that caused the tokens to be invalidated
        is_valid_until: Token's expiration date.
    """

    __tablename__ = 'runas_token_blacklist'

    nbf_invalid_until = Column('nbf_invalid_until', Integer, primary_key=True)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('nbf_invalid_until', name='nbf_invalid_until_invalidation_rule'),)

    def __init__(self):
        self.nbf_invalid_until = int(time())
        self.is_valid_until = (
            self.nbf_invalid_until + CentralizedConfig.get_management_api_config().jwt_expiration_timeout
        )

    def to_dict(self) -> dict:
        """Return the information of the RunAsTokenBlacklist object.

        Returns
        -------
        dict
            Dictionary with the object information.
        """
        return {'nbf_invalid_until': self.nbf_invalid_until, 'is_valid_until': self.is_valid_until}


class UsersTokenBlacklist(_Base):
    """Class that represents the table containing the tokens given through the login endpoint that are considered
    invalid. An invalid token is an expired or revoked token.
    The information stored is:
        user_id: ID of the user affected by the token
        nbf_invalid_until: Time of the issue that caused the tokens to be invalidated
        is_valid_until: Token's expiration date.
    """

    __tablename__ = 'users_token_blacklist'

    user_id = Column('user_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer, nullable=False)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', name='user_invalidation_rule'),)

    def __init__(self, user_id):
        self.user_id = user_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = (
            self.nbf_invalid_until + CentralizedConfig.get_management_api_config().jwt_expiration_timeout
        )

    def to_dict(self):
        """Return the information of the token rule.

        Returns
        -------
        Dict with the information
        """
        return {
            'user_id': self.user_id,
            'nbf_invalid_until': self.nbf_invalid_until,
            'is_valid_until': self.is_valid_until,
        }


class RolesTokenBlacklist(_Base):
    """Class that represents the table containing the roles with an invalid token.
    An invalid token is an expired or revoked token.
    The information stored is:
        role_id: ID of the role affected by the token
        nbf_invalid_until: Time of the issue that caused the tokens to be invalidated
        is_valid_until: Token's expiration date.
    """

    __tablename__ = 'roles_token_blacklist'

    role_id = Column('role_id', Integer, primary_key=True)
    nbf_invalid_until = Column('nbf_invalid_until', Integer, nullable=False)
    is_valid_until = Column('is_valid_until', Integer, nullable=False)
    __table_args__ = (UniqueConstraint('role_id', name='role_invalidation_rule'),)

    def __init__(self, role_id):
        self.role_id = role_id
        self.nbf_invalid_until = int(time())
        self.is_valid_until = (
            self.nbf_invalid_until + CentralizedConfig.get_management_api_config().jwt_expiration_timeout
        )

    def to_dict(self):
        """Return the information of the token rule.

        Returns
        -------
        Dict with the information
        """
        return {
            'role_id': self.role_id,
            'nbf_invalid_until': self.nbf_invalid_until,
            'is_valid_until': self.is_valid_until,
        }


# Declare basic tables


class User(_Base):
    """This table stores all the information related to Users.
    The information stored for each object is:
        id: ID of the user
        username: The name of the user
        password: The password of the user
        allow_run_as: Whether the user is able to log in with an authorization context or not
        created_at: Date of the user creation.
    """

    __tablename__ = 'users'

    id = Column('id', Integer, primary_key=True)
    username = Column(String(32), nullable=False)
    password = Column(String(256), nullable=False)
    allow_run_as = Column(Boolean, default=False, nullable=False)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('username', name='username_restriction'),)

    # Relations
    roles = relationship(
        'Roles',
        secondary='user_roles',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='roles_associations,users,roles',
    )
    roles_associations = relationship('UserRoles', back_populates='users', cascade='all,delete', overlaps='users')

    def __init__(
        self, username: str, password: str, allow_run_as: bool = False, created_at: datetime = None, user_id: int = None
    ):
        """Class constructor.

        Parameters
        ----------
        username : str
            The name of the user.
        password : str
            The password of the user.
        allow_run_as : bool
            Whether the user is able to log in with an authorization context or not.
        created_at : datetime
            Date of the user creation.
        user_id : int
            ID of the user.
        """
        self.id = user_id
        self.username = username
        self.password = password
        self.allow_run_as = allow_run_as
        self.created_at = created_at or get_utc_now()

    def __repr__(self):
        return f'<User(user={self.username})'

    def _get_roles_id(self) -> list:
        """Get IDs of the user roles.

        Returns
        -------
        list
            List of user roles IDs.
        """
        roles = list()
        for role in self.roles:
            roles.append(role.get_role()['id'])

        return roles

    def get_roles(self) -> list:
        """Get user roles.

        Returns
        -------
        list
            List of user roles.
        """
        return list(self.roles)

    def get_user(self) -> dict:
        """User's getter method.

        Returns
        -------
        dict
            Dictionary with the information of the user.
        """
        return {
            'id': self.id,
            'username': self.username,
            'roles': self._get_roles_id(),
            'allow_run_as': self.allow_run_as,
        }

    def to_dict(self, session: Session = None) -> dict:
        """Return the information of the user and its roles.

        Parameters
        ----------
        session : Session
            SQL Alchemy ORM session.

        Returns
        -------
        dict
            Dictionary with the information of the user and its roles.
        """
        with UserRolesManager(session=session) as urm:
            return {
                'id': self.id,
                'username': self.username,
                'allow_run_as': self.allow_run_as,
                'roles': [role.id for role in urm.get_all_roles_from_user(user_id=self.id)],
            }


class Roles(_Base):
    """This table stores all the information related to Roles.
    The information stored for each object is:
        id: ID of the role
        name: The name of the role
        created_at: Date of the role creation.
    """

    __tablename__ = 'roles'

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('name', name='name_role'), CheckConstraint('length(name) <= 64'))

    # Relations
    policies = relationship(
        'Policies',
        secondary='roles_policies',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='policies_associations,roles,policies',
    )
    users = relationship(
        'User',
        secondary='user_roles',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='users_associations,roles,users',
    )
    rules = relationship(
        'Rules',
        secondary='roles_rules',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='roles_associations,roles,rules',
    )

    policies_associations = relationship(
        'RolesPolicies', back_populates='roles', cascade='all,delete', overlaps='roles,policies'
    )
    users_associations = relationship('UserRoles', back_populates='roles', cascade='all,delete', overlaps='users,roles')
    rules_associations = relationship(
        'RolesRules', back_populates='roles', cascade='all,delete', overlaps='roles,rules'
    )

    def __init__(self, name: str, role_id: int = None, created_at: datetime = None):
        """Class constructor.

        Parameters
        ----------
        name : str
            Name of the role.
        role_id : int
            ID of the role.
        created_at : datetime
            Date of the role creation.
        """
        self.id = role_id
        self.name = name
        self.created_at = created_at or get_utc_now()

    def get_role(self) -> dict:
        """Role's getter method.

        Returns
        -------
        dict
            Dictionary with the information of the role.
        """
        return {'id': self.id, 'name': self.name}

    def get_policies(self) -> list:
        """Get role policies.

        Returns
        -------
        list
            List of the role policies.
        """
        return list(self.policies)

    def to_dict(self, session: Session = None) -> dict:
        """Return the information of the role and its users, policies and rules.

        Parameters
        ----------
        session : Session
            SQL Alchemy ORM session.

        Returns
        -------
        dict
            Dictionary with the information of the role and its users, policies and rules.
        """
        with RolesPoliciesManager(session=session) as rpm:
            return {
                'id': self.id,
                'name': self.name,
                'policies': [policy.id for policy in rpm.get_all_policies_from_role(role_id=self.id)],
                'users': [user.id for user in self.users],
                'rules': [rule.id for rule in self.rules],
            }


class Rules(_Base):
    """This table stores all the information related to Rules.
    The information stored for each object is:
        id: ID of the rule
        name: The name of the rule
        rule: The body of the rule
        created_at: Date of the rule creation.
    """

    __tablename__ = 'rules'

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    rule = Column('rule', TEXT, nullable=False)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (UniqueConstraint('name', name='rule_name'), UniqueConstraint('rule', name='rule_definition'))

    # Relations
    roles = relationship(
        'Roles',
        secondary='roles_rules',
        back_populates='rules',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='roles_associations,rules,roles',
    )
    roles_associations = relationship('RolesRules', back_populates='rules', cascade='all,delete', overlaps='roles')

    def __init__(self, name: str, rule: str, rule_id: int = None, created_at: datetime = None):
        """Class constructor.

        Parameters
        ----------
        name : str
            Name of the rule.
        rule : str
            String representation of the rule body.
        created_at : datetime
            Date if the rule creation
        """
        self.id = rule_id
        self.name = name
        self.rule = rule
        self.created_at = created_at or get_utc_now()

    def get_rule(self) -> dict:
        """Rule getter method.

        Returns
        -------
        dict
            Dictionary with the information of the rule.
        """
        return {'id': self.id, 'name': self.name, 'rule': json.loads(self.rule)}

    def to_dict(self) -> dict:
        """Return the information of the rule and its roles.

        Returns
        -------
        dict
            Dictionary with the information of the rule and its roles.
        """
        return {
            'id': self.id,
            'name': self.name,
            'rule': json.loads(self.rule),
            'roles': [role.id for role in self.roles],
        }


class Policies(_Base):
    """This table stores all the information related to Policies.
    The information stored for each object is:
        id: ID of the policy
        name: The name of the policy
        policy: The body of the policy
        created_at: Date of the policy creation.
    """

    __tablename__ = 'policies'

    # Schema
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(20), nullable=False)
    policy = Column('policy', TEXT, nullable=False)
    created_at = Column('created_at', DateTime, default=get_utc_now())
    __table_args__ = (
        UniqueConstraint('name', name='name_policy'),
        UniqueConstraint('policy', name='policy_definition'),
    )

    # Relations
    roles = relationship(
        'Roles',
        secondary='roles_policies',
        passive_deletes=True,
        cascade='all,delete',
        lazy='dynamic',
        overlaps='roles_associations,policies,roles',
    )
    roles_associations = relationship(
        'RolesPolicies', back_populates='policies', cascade='all,delete', overlaps='policies'
    )

    def __init__(self, name: str, policy: str, policy_id: int = None, created_at: datetime = None):
        """Class constructor.

        Parameters
        ----------
        name : str
            Name of the policy.
        policy : str
            Body of the policy.
        policy_id : int
            ID of the policy.
        created_at : datetime
            Date of the policy creation.
        """
        self.id = policy_id
        self.name = name
        self.policy = policy
        self.created_at = created_at or get_utc_now()

    def get_policy(self) -> dict:
        """Policy's getter method.

        Returns
        -------
        dict
            Dictionary with the information of the policy.
        """
        return {'id': self.id, 'name': self.name, 'policy': json.loads(self.policy)}

    def to_dict(self, session: Session = None) -> dict:
        """Return the information of the policy and the roles containing it.

        Parameters
        ----------
        session : Session
            SQL Alchemy ORM session.

        Returns
        -------
        dict
            Dictionary with the policy information and the roles containing it.
        """
        with RolesPoliciesManager(session=session) as rpm:
            return {
                'id': self.id,
                'name': self.name,
                'policy': json.loads(self.policy),
                'roles': [role.id for role in rpm.get_all_roles_from_policy(policy_id=self.id)],
            }


# Table Managers


class RBACManager:
    """Generic class used to manage the information from each table."""

    def __init__(self, session: Session = None):
        """Class constructor.

        Parameters
        ----------
        session : Session
            SQL Alchemy ORM session.
        """
        self.session = session or sessionmaker(bind=create_engine(f'sqlite:///{DB_FILE}', echo=False))()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class TokenManager(RBACManager):
    """Manager of the TokenBlacklist class.
    This class provides all the methods needed for the administration of the TokenBlacklist objects.
    """

    def is_token_valid(
        self, token_nbf_time: int, user_id: int = None, role_id: int = None, run_as: bool = False
    ) -> bool:
        """Check if the specified token is valid.

        Parameters
        ----------
        user_id : int
            Current token's user id.
        role_id : int
            Current token's role id.
        token_nbf_time : int
            Token's issue timestamp.
        run_as : bool
            Indicate if the token has been granted through run_as endpoint.

        Returns
        -------
        bool
            True if the token is valid, False otherwise.
        """
        try:
            user_rule = self.session.scalars(select(UsersTokenBlacklist).filter_by(user_id=user_id).limit(1)).first()
            role_rule = self.session.scalars(select(RolesTokenBlacklist).filter_by(role_id=role_id).limit(1)).first()
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            return (
                (not user_rule or (token_nbf_time > user_rule.nbf_invalid_until))
                and (not role_rule or (token_nbf_time > role_rule.nbf_invalid_until))
                and (not run_as or (not runas_rule or (token_nbf_time > runas_rule.nbf_invalid_until)))
            )
        except IntegrityError:
            return True

    def get_all_rules(self) -> Union[tuple, int]:
        """Return two dictionaries where the keys are the role IDs and user IDs of each rule and the values are the
        rule nbf_invalid_until value.
        It also returns a dictionary with the nbf_invalid_until value of run_as.

        Returns
        -------
        Union[tuple, int]
            Dictionaries representing the nbf_invalid_until of each rule and the roles and users affected
            or a SecurityError code.
        """
        try:
            users_format_rules, roles_format_rules, runas_format_rule = dict(), dict(), dict()
            users_rules = map(UsersTokenBlacklist.to_dict, self.session.scalars(select(UsersTokenBlacklist)).all())
            roles_rules = map(RolesTokenBlacklist.to_dict, self.session.scalars(select(RolesTokenBlacklist)).all())
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            if runas_rule:
                runas_rule = runas_rule.to_dict()
                runas_format_rule['run_as'] = runas_rule['nbf_invalid_until']
            for rule in list(users_rules):
                users_format_rules[rule['user_id']] = rule['nbf_invalid_until']
            for rule in list(roles_rules):
                roles_format_rules[rule['role_id']] = rule['nbf_invalid_until']

            return users_format_rules, roles_format_rules, runas_format_rule
        except IntegrityError:
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def add_user_roles_rules(self, users: set = None, roles: set = None, run_as: bool = False) -> Union[bool, int]:
        """Add new rules for users-token or roles-token.
        The values nbf_invalid_until and is_valid_until are generated automatically.

        Parameters
        ----------
        users : set
            Set with the affected users.
        roles : set
            Set with the affected roles.
        run_as : bool
            Indicate if the token has been granted through the run_as login endpoint.

        Returns
        -------
        Union[bool, int]
            True if the operation was done successfully or a SecurityError code if it failed.
        """
        if users is None:
            users = set()
        if roles is None:
            roles = set()

        try:
            self.delete_all_expired_rules()
            for user_id in users:
                self.delete_rule(user_id=int(user_id))
                self.session.add(UsersTokenBlacklist(user_id=int(user_id)))
                self.session.commit()
            for role_id in roles:
                self.delete_rule(role_id=int(role_id))
                self.session.add(RolesTokenBlacklist(role_id=int(role_id)))
                self.session.commit()
            if run_as:
                self.delete_rule(run_as=run_as)
                self.session.add(RunAsTokenBlacklist())
                self.session.commit()

            clear_cache()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, user_id: int = None, role_id: int = None, run_as: bool = False) -> Union[bool, int]:
        """Remove the rule for the specified role and user.

        Parameters
        ----------
        user_id : int
            ID of the user for which the rule is going to be deleted.
        role_id : int
            ID of the role for which the rule is going to be deleted.
        run_as : bool
            Indicate if the token has been granted through the run_as login endpoint.

        Returns
        -------
        Union[bool, int]
            True if the operation was done successfully or a SecurityError code if it failed.
        """
        try:
            self.session.execute(delete(UsersTokenBlacklist).filter_by(user_id=user_id))
            self.session.execute(delete(RolesTokenBlacklist).filter_by(role_id=role_id))
            if run_as:
                run_as_rule = self.session.query(RunAsTokenBlacklist).first()
                run_as_rule and self.session.delete(run_as_rule)
            self.session.commit()

            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.TOKEN_RULE_NOT_EXIST

    def delete_all_expired_rules(self) -> Union[tuple[list, list], bool]:
        """Delete all expired rules in the system.

        Returns
        -------
        Union[list, bool]
            List of removed user and role rules or False if the operation failed.
        """
        try:
            list_users, list_roles = list(), list()
            current_time = int(time())
            users_tokens_in_blacklist = self.session.scalars(select(UsersTokenBlacklist)).all()
            for user_token in users_tokens_in_blacklist:
                token_rule = self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_users.append(user_token.user_id)
            roles_tokens_in_blacklist = self.session.scalars(select(RolesTokenBlacklist)).all()
            for role_token in roles_tokens_in_blacklist:
                token_rule = self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id)
                if token_rule.first() and current_time > token_rule.first().is_valid_until:
                    token_rule.delete()
                    self.session.commit()
                    list_roles.append(role_token.role_id)
            runas_token_in_blacklist = self.session.query(RunAsTokenBlacklist).first()
            if runas_token_in_blacklist and runas_token_in_blacklist.to_dict()['is_valid_until'] < current_time:
                self.session.delete(runas_token_in_blacklist)
                self.session.commit()

            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_rules(self) -> Union[tuple[list, list], bool]:
        """Delete all existent rules in the system.

        Returns
        -------
        Union[list, bool]
            List of removed user and role rules or False if the operation failed.
        """
        try:
            list_users, list_roles = list(), list()
            users_tokens_in_blacklist = self.session.scalars(select(UsersTokenBlacklist)).all()
            roles_tokens_in_blacklist = self.session.scalars(select(RolesTokenBlacklist)).all()

            clean = False
            for user_token in users_tokens_in_blacklist:
                list_roles.append(user_token.user_id)
                self.session.query(UsersTokenBlacklist).filter_by(user_id=user_token.user_id).delete()
                clean = True
            for role_token in roles_tokens_in_blacklist:
                list_roles.append(role_token.role_id)
                self.session.query(RolesTokenBlacklist).filter_by(role_id=role_token.role_id).delete()
                clean = True
            runas_rule = self.session.query(RunAsTokenBlacklist).first()
            if runas_rule:
                self.session.delete(runas_rule)
                clean = True

            clean and self.session.commit()
            return list_users, list_roles
        except IntegrityError:
            self.session.rollback()
            return False


class AuthenticationManager(RBACManager):
    """Manager of the User class.
    This class provides all the methods needed for the administration of the User objects.
    """

    def edit_run_as(self, user_id: int, allow_run_as: bool) -> Union[bool, int]:
        """Change the specified user's allow_run_as flag.

        Parameters
        ----------
        user_id : int
            Unique user id.
        allow_run_as : bool
            Flag that indicates if the user can log into the API through an authorization context.

        Returns
        -------
        Union[bool, int]
            True if the user's flag has been modified successfully, False if the modification failed, or a SecurityError
            code if the specified value is not correct.
        """
        try:
            user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
            if user is not None:
                if isinstance(allow_run_as, bool):
                    user.allow_run_as = allow_run_as
                    self.session.commit()
                    return True
                return SecurityError.INVALID
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def add_user(
        self,
        username: str,
        password: str,
        user_id: int = None,
        hashed_password: bool = False,
        created_at: datetime = None,
        check_default: bool = True,
    ) -> bool:
        """Create a new user if it does not exist.

        Parameters
        ----------
        username : str
            Unique username.
        password : str
            Password provided by user. It will be stored hashed.
        user_id : int
            User ID.
        hashed_password : bool
            Whether the password is already hashed or not.
        created_at : datetime
            Date when the resource was created.
        check_default : bool
            Flag that indicates if the user ID can be less than MAX_ID_RESERVED.

        Returns
        -------
        bool
            True if the user has been created successfully. False otherwise (i.e. already exists).
        """
        try:
            try:
                if (
                    check_default
                    and self.session.query(User).order_by(desc(User.id)).limit(1).scalar().id < MAX_ID_RESERVED
                ):
                    user_id = MAX_ID_RESERVED + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(
                User(
                    username=username,
                    password=password if hashed_password else generate_password_hash(password),
                    created_at=created_at,
                    user_id=user_id,
                )
            )
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def update_user(self, user_id: int, password: str = None, name: str = None, hashed_password: bool = False) -> bool:
        """Update an existent user's name or password.

        Parameters
        ----------
        user_id : int
            Unique user ID.
        password : str
            Password provided by user. It will be stored hashed.
        name : str
            New username.
        hashed_password : bool
            Whether the password is already hashed or not.

        Returns
        -------
        bool
            True if the user has been modified successfully. False otherwise.
        """
        try:
            user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
            if user is not None:
                if name is not None:
                    user.username = name
                if password is not None:
                    user.password = password if hashed_password else generate_password_hash(password)
                if name is not None or password is not None:
                    self.session.commit()
                    return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_user(self, user_id: int) -> Union[bool, int]:
        """Remove the specified user.

        Parameters
        ----------
        user_id : int
            ID of the user to be deleted.

        Returns
        -------
        Union[bool, int]
            True if the user has been deleted successfully. False or a SecurityError code otherwise.
        """
        try:
            if user_id > MAX_ID_RESERVED:
                user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
                if user is None:
                    return False
                self.session.delete(user)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except UnmappedInstanceError:
            # User already deleted
            return False

    def check_user(self, username: str, password: str) -> bool:
        """Validate a username-password pair.

        Parameters
        ----------
        username : str
            Name of the user to be validated.
        password : str
            Password to be checked against the one saved in the database.

        Returns
        -------
        bool
            True if username and password matches. False otherwise.
        """
        user = self.session.scalars(select(User).filter_by(username=username).limit(1)).first()
        return check_password_hash(user.password, password) if user else False

    def get_user(self, username: str = None) -> Union[dict, bool]:
        """Get a specified user in the system given its name.

        Parameters
        ----------
        username : str
            Name of the user to be obtained.

        Returns
        -------
        Union[dict, bool]
            Dictionary representing the user or False if the user was not found.
        """
        try:
            if username is not None:
                return (
                    self.session.scalars(select(User).filter_by(username=username).limit(1))
                    .first()
                    .to_dict(self.session)
                )
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_user_id(self, user_id: int) -> Union[dict, bool]:
        """Get a specified user in the system given its ID.

        Parameters
        ----------
        user_id : int
            ID of the user to be obtained.

        Returns
        -------
        Union[dict, bool]
            Dictionary representing the user or False if the user was not found.
        """
        try:
            if user_id is not None:
                return self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first().to_dict(self.session)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def user_allow_run_as(self, username: str = None) -> Union[str, bool]:
        """Get the allow_run_as flag of a specified user in the system given its name.

        Parameters
        ----------
        username : str
            Name of the user for which we want to get the allow_run_as flag.

        Returns
        -------
        Union[str, bool]
            String representing the value of allow_run_as or False if the user was not found.
        """
        try:
            if username is not None:
                return (
                    self.session.scalars(select(User).filter_by(username=username).limit(1))
                    .first()
                    .get_user()['allow_run_as']
                )

        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_users(self) -> Union[list[dict], bool]:
        """Get all users in the system.

        Returns
        -------
        list
            List of dictionaries representing the system users or False in case of integrity errors.
        """
        try:
            users = self.session.scalars(select(User)).all()
        except IntegrityError:
            self.session.rollback()
            return False

        user_ids = list()
        for user in users:
            if user is not None:
                user_dict = {'user_id': user.id, 'username': user.username}
                user_ids.append(user_dict)
        return user_ids

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the users from the `source` database filtering by IDs and insert them into the `target` database.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        old_users = manager.get_data(source, User, User.id, from_id=from_id, to_id=to_id)

        for user in old_users:
            if user.id in (WAZUH_USER_ID, WAZUH_WUI_USER_ID):
                self.update_user(user.id, user.password, hashed_password=True)
                continue

            status = self.add_user(
                username=user.username,
                password=user.password,
                created_at=user.created_at,
                user_id=user.id,
                hashed_password=True,
                check_default=False,
            )

            if status is False:
                logger.warning(
                    f'User {user.id} ({user.username}) is part of the new default users. '
                    f"Renaming it to '{user.username}_user'"
                )

                self.add_user(
                    username=f'{user.username}_user',
                    password=user.password,
                    created_at=user.created_at,
                    user_id=user.id,
                    hashed_password=True,
                    check_default=False,
                )


class RolesManager(RBACManager):
    """Manager of the Roles class.
    This class provides all the methods needed for the administration of the Roles objects.
    """

    def get_role(self, name: str) -> Union[dict, int]:
        """Get the information about a role given its name.

        Parameters
        ----------
        name : str
            Name of the role that we want to get its information from.

        Returns
        -------
        Union[dict, int]
            Dictionary with the information of the role or a SecurityError code.
        """
        try:
            role = self.session.scalars(select(Roles).filter_by(name=name).limit(1)).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role.to_dict(self.session)
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_role_id(self, role_id: int) -> Union[dict, int]:
        """Get the information about a role given its ID.

        Parameters
        ----------
        role_id : int
            ID of the role that we want to get its information from.

        Returns
        -------
        Union[dict, int]
            Dictionary with the information of the role or a SecurityError code.
        """
        try:
            role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            if not role:
                return SecurityError.ROLE_NOT_EXIST
            return role.to_dict(self.session)
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def get_roles(self) -> Union[list, int]:
        """Get all roles in the system.

        Returns
        -------
        Union[list, int]
            List of Roles objects or a SecurityError code.
        """
        try:
            roles = self.session.scalars(select(Roles)).all()
            return roles
        except IntegrityError:
            return SecurityError.ROLE_NOT_EXIST

    def add_role(
        self, name: str, role_id: int = None, created_at: datetime = None, check_default: bool = True
    ) -> Union[bool, int]:
        """Add a new role.

        Parameters
        ----------
        name : str
            Name of the new role.
        role_id : int
            Role ID.
        created_at : datetime
            Date when the resource was created.
        check_default : bool
            Flag that indicates if the role ID can be less than MAX_ID_RESERVED.

        Returns
        -------
        Union[bool, int]
            List of Roles objects or a SecurityError code.
        """
        try:
            try:
                if (
                    check_default
                    and self.session.query(Roles).order_by(desc(Roles.id)).limit(1).scalar().id < MAX_ID_RESERVED
                ):
                    role_id = MAX_ID_RESERVED + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Roles(name=name, role_id=role_id, created_at=created_at))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_role(self, role_id: int) -> Union[bool, int]:
        """Delete an existent role in the system.

        Parameters
        ----------
        role_id : int
            ID of the role to be deleted.

        Returns
        -------
        Union[bool, int]
            True if the role was deleted successfully, False if the operation failed, or a SecurityError code.
        """
        try:
            if role_id > MAX_ID_RESERVED:
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return False
                self.session.delete(role)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role_by_name(self, role_name: str) -> bool:
        """Delete an existent role in the system given its name.

        Parameters
        ----------
        role_name : str
            Name of the role to be deleted.

        Returns
        -------
        bool
            True is the role was deleted successfully, False otherwise.
        """
        try:
            if self.get_role(role_name) is not None and self.get_role(role_name)['id'] > MAX_ID_RESERVED:
                role_id = self.session.scalars(select(Roles).filter_by(name=role_name).limit(1)).first().id
                if role_id:
                    self.delete_role(role_id=role_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_roles(self) -> Union[list, bool]:
        """Delete all existent roles in the system.

        Returns
        -------
        Union[list, bool]
            List of deleted roles or Failed if the operatio failed.
        """
        try:
            list_roles = list()
            roles = self.session.scalars(select(Roles)).all()
            for role in roles:
                if int(role.id) > MAX_ID_RESERVED:
                    self.session.delete(self.session.scalars(select(Roles).filter_by(id=role.id).limit(1)).first())
                    self.session.commit()
                    list_roles.append(int(role.id))
            return list_roles
        except IntegrityError:
            self.session.rollback()
            return False

    def update_role(self, role_id: int, name: str) -> Union[bool, int]:
        """Update an existent role in the system.

        Parameters
        ----------
        role_id : int
            ID of the role to be updated.
        name : str
            New name for the role.

        Returns
        -------
        Union[bool, int]
            Return True if the role was updated successfully or a SecurityError code.
        """
        try:
            role_to_update = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            if role_to_update and role_to_update is not None:
                if role_to_update.id > MAX_ID_RESERVED:
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

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the roles from the `source` database filtering by IDs and insert them into the `target` database.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_roles = manager.get_data(source, Roles, Roles.id, from_id=from_id, to_id=to_id)
        for role in old_roles:
            status = self.add_role(name=role.name, created_at=role.created_at, role_id=role.id, check_default=False)

            if status == SecurityError.ALREADY_EXIST:
                logger.warning(
                    f'Role {role.id} ({role.name}) is part of the new default roles. '
                    f"Renaming it to '{role.name}_user'"
                )

                self.add_role(
                    name=f'{role.name}_user', created_at=role.created_at, role_id=role.id, check_default=False
                )


class RulesManager(RBACManager):
    """Manager of the Rules class.
    This class provides all the methods needed for the administration of the Rules objects.
    """

    def get_rule(self, rule_id: int) -> Union[dict, int]:
        """Get the information about a rule given its ID.

        Parameters
        ----------
        rule_id : int
            ID of the rule.

        Returns
        -------
        Union[dict, int]
            Dictionary with the information of the rule or a SecurityError code.
        """
        try:
            rule = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rule_by_name(self, rule_name: str) -> Union[dict, int]:
        """Get the information about a rule given its name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.

        Returns
        -------
        Union[dict, int]
            Dictionary with the information of the rule or a SecurityError code.
        """
        try:
            rule = self.session.scalars(select(Rules).filter_by(name=rule_name).limit(1)).first()
            if not rule:
                return SecurityError.RULE_NOT_EXIST
            return rule.to_dict()
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def get_rules(self) -> Union[list, int]:
        """Get all the rules in the system.

        Returns
        -------
        Union[list, int]
            List of all the Rules objects or a SecurityError code.
        """
        try:
            rules = self.session.scalars(select(Rules)).all()
            return rules
        except IntegrityError:
            return SecurityError.RULE_NOT_EXIST

    def add_rule(
        self, name: str, rule: dict, rule_id: int = None, created_at: datetime = None, check_default: bool = True
    ) -> Union[bool, int]:
        """Add a new rule.

        Parameters
        ----------
        name : str
            Name of the new rule.
        rule : dict
            Body of the rule.
        rule_id : int
            Rule ID.
        created_at : datetime
            Date when the resource was created.
        check_default : bool
            Flag that indicates if the rule ID can be less than MAX_ID_RESERVED

        Returns
        -------
        Union[bool, int]
            True if the rule was added successfully or a SecurityError code.
        """
        try:
            if rule is not None and not isinstance(rule, dict):
                return SecurityError.INVALID
            try:
                if (
                    check_default
                    and self.session.query(Rules).order_by(desc(Rules.id)).limit(1).scalar().id < MAX_ID_RESERVED
                ):
                    rule_id = MAX_ID_RESERVED + 1
            except (TypeError, AttributeError):
                pass
            self.session.add(Rules(name=name, rule=json.dumps(rule), rule_id=rule_id, created_at=created_at))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_rule(self, rule_id: int) -> Union[bool, int]:
        """Delete an existent rule from the system given its ID.

        Parameters
        ----------
        rule_id : int
            Id of the rule.

        Returns
        -------
        Union[bool, int]
            True if the rule was deleted, False if the operation failed, or a SecurityError code.
        """
        try:
            if rule_id > MAX_ID_RESERVED:
                rule = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
                if rule is None:
                    return False
                self.session.delete(rule)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_rule_by_name(self, rule_name: str) -> bool:
        """Delete an existent rule from the system given its name.

        Parameters
        ----------
        rule_name : str
            Name of the rule.

        Returns
        -------
        bool
            True if the rule was deleted or False if the operation failed.
        """
        try:
            if (
                self.get_rule_by_name(rule_name) is not None
                and self.get_rule_by_name(rule_name)['id'] > MAX_ID_RESERVED
            ):
                rule_id = self.session.scalars(select(Rules).filter_by(name=rule_name).limit(1)).first().id
                if rule_id:
                    self.delete_rule(rule_id=rule_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_rules(self) -> Union[list, bool]:
        """Delete all existent rules from the system.

        Returns
        -------
        Union[list, bool]
            List with the rules deleted or False if the operation failed.
        """
        try:
            list_rules = list()
            rules = self.session.scalars(select(Rules)).all()
            for rule in rules:
                if int(rule.id) > MAX_ID_RESERVED:
                    self.session.delete(self.session.scalars(select(Rules).filter_by(id=rule.id).limit(1)).first())
                    self.session.commit()
                    list_rules.append(int(rule.id))
            return list_rules
        except IntegrityError:
            self.session.rollback()
            return False

    def update_rule(self, rule_id: int, name: str, rule: dict) -> Union[bool, int]:
        """Update an existent rule in the system.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        name : name
            Name of the rule.
        rule : dict
            Dictionary representing the rule body.

        Returns
        -------
        Union[bool, int]
            True if the rule was updated successfully or a SecurityError code otherwise.
        """
        try:
            rule_to_update = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
            if rule_to_update and rule_to_update is not None:
                if rule_to_update.id > MAX_ID_RESERVED:
                    # Rule is not a valid json
                    if rule is not None and not isinstance(rule, dict):
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

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the rules from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_rules = manager.get_data(source, Rules, Rules.id, from_id=from_id, to_id=to_id)

        for rule in old_rules:
            status = self.add_rule(
                name=rule.name,
                rule=json.loads(rule.rule),
                created_at=rule.created_at,
                rule_id=rule.id,
                check_default=False,
            )
            # If the user's rule has the same body as an existing default rule, it won't be inserted and its
            # role-rule relationships will be linked to that default rule instead of replacing it.
            if status == SecurityError.ALREADY_EXIST:
                logger.warning(
                    f'Rule {rule.id} ({rule.name}) is part of the new default rules. '
                    'Attempting to migrate relationships'
                )
                roles_rules = (
                    manager.get_table(manager.sessions[source], RolesRules)
                    .filter(RolesRules.rule_id == rule.id)
                    .order_by(RolesRules.id.asc())
                    .all()
                )
                new_rule_id = manager.sessions[target].query(Rules).filter_by(rule=str(rule.rule)).first().id

                with RolesRulesManager(manager.sessions[target]) as role_rules_manager:
                    for role_rule in roles_rules:
                        role_rules_manager.add_rule_to_role(
                            role_id=role_rule.role_id,
                            rule_id=new_rule_id,
                            created_at=role_rule.created_at,
                            force_admin=True,
                        )
                    logger.info(f'All relationships were migrated to the new rule {new_rule_id}')


class PoliciesManager(RBACManager):
    """Manager of the Policies class.
    This class provides all the methods needed for the administration of the Policies objects.
    """

    ACTION_REGEX = r'^[a-zA-Z_\-]+:[a-zA-Z_\-]+$'
    RESOURCE_REGEX = r'^[a-zA-Z_\-*]+:[\w_\-*]+:[\w_\-\/.*]+$'
    POLICY_ATTRIBUTES = {'actions': list, 'resources': list, 'effect': str}

    def get_policy(self, name: str) -> Union[dict, int]:
        """Get the information about a policy given its name.

        Parameters
        ----------
        name : str
            Name of the policy that we want to get its information from.

        Returns
        -------
        Union[dict, int]
            Dictionary with the policy information or a SecurityError code.
        """
        try:
            policy = self.session.scalars(select(Policies).filter_by(name=name).limit(1)).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy.to_dict(self.session)
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policy_id(self, policy_id: int) -> Union[dict, int]:
        """Get the information about a policy given its ID.

        Parameters
        ----------
        policy_id : int
            ID of the policy that we want to get its information from.

        Returns
        -------
        Union[dict, int]
            Dictionary with the policy information or a SecurityError code.
        """
        try:
            policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
            if not policy:
                return SecurityError.POLICY_NOT_EXIST
            return policy.to_dict(self.session)
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def get_policies(self) -> Union[list, int]:
        """Get the information about all policies in the system.

        Returns
        -------
        Union[list, int]
            List with all the Policies objects or a SecurityError code.
        """
        try:
            policies = self.session.scalars(select(Policies)).all()
            return policies
        except IntegrityError:
            return SecurityError.POLICY_NOT_EXIST

    def add_policy(
        self, name: str, policy: dict, policy_id: int = None, created_at: datetime = None, check_default: bool = True
    ) -> Union[bool, int]:
        """Add a new policy.

        Parameters
        ----------
        name : str
            Name of the new policy.
        policy : dict
            Body of the new policy
        policy_id : int
            Policy ID.
        created_at : datetime
            Date when the resource was created.
        check_default : bool
            Flag that indicates if the policy ID can be less than MAX_ID_RESERVED.

        Returns
        -------
        Union[bool, int]
            True if the policy was added successfully or a SecurityError code if the operation failed.
        """
        try:
            if policy is not None and not isinstance(policy, dict):
                return SecurityError.ALREADY_EXIST
            if policy is None or len(policy) != 3:
                return SecurityError.INVALID
            # To add a policy, its body must have the `actions`, `resources`, and `effect` keys;
            # and the values must be instances of `list`, `list` and `str`
            if all(
                [
                    isinstance(policy.get(attribute), attr_type)
                    for attribute, attr_type in self.POLICY_ATTRIBUTES.items()
                ]
            ):
                for action in policy['actions']:
                    if not re.match(self.ACTION_REGEX, action):
                        return SecurityError.INVALID
                for resource in policy['resources']:
                    if not all(re.match(self.RESOURCE_REGEX, res) for res in resource.split('&')):
                        return SecurityError.INVALID

                try:
                    if not check_default:
                        policies = sorted([p.id for p in self.get_policies()]) or [0]
                        policy_id = policy_id or max(filter(lambda x: not (x > CLOUD_RESERVED_RANGE), policies)) + 1

                    elif (
                        check_default
                        and self.session.query(Policies).order_by(desc(Policies.id)).limit(1).scalar().id
                        < MAX_ID_RESERVED
                    ):
                        policy_id = MAX_ID_RESERVED + 1

                except (TypeError, AttributeError):
                    pass
                self.session.add(
                    Policies(name=name, policy=json.dumps(policy), policy_id=policy_id, created_at=created_at)
                )
                self.session.commit()
                return True
            else:
                return SecurityError.INVALID
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def delete_policy(self, policy_id: int) -> Union[bool, int]:
        """Delete an existent policy in the system.

        Parameters
        ----------
        policy_id : int
            ID of the policy to be deleted.

        Returns
        -------
        Union[bool, int]
            True if the policy was deleted successfully, False if the operation failed, or a SecurityError code.
        """
        try:
            if int(policy_id) > MAX_ID_RESERVED:
                policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
                if policy is None:
                    return False
                self.session.delete(policy)
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy_by_name(self, policy_name: str) -> bool:
        """Delete an existent role in the system given its name.

        Parameters
        ----------
        policy_name : str
            Name of the policy to be deleted.

        Returns
        -------
        bool
            True if the policy was deleted successfully, False otherwise.
        """
        try:
            if self.get_policy(policy_name) is not None and self.get_policy(name=policy_name)['id'] > MAX_ID_RESERVED:
                policy_id = self.session.scalars(select(Policies).filter_by(name=policy_name).limit(1)).first().id
                if policy_id:
                    self.delete_policy(policy_id=policy_id)
                    return True
            return False
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def delete_all_policies(self) -> Union[list, bool]:
        """Delete all existent policies in the system.

        Returns
        -------
        Union[list, bool]
            List with the Policies objects deleted or False if the operation failed.
        """
        try:
            list_policies = list()
            policies = self.session.scalars(select(Policies)).all()
            for policy in policies:
                if int(policy.id) > MAX_ID_RESERVED:
                    self.session.delete(self.session.scalars(select(Policies).filter_by(id=policy.id).limit(1)).first())
                    self.session.commit()
                    list_policies.append(int(policy.id))
            return list_policies
        except IntegrityError:
            self.session.rollback()
            return False

    def update_policy(self, policy_id: int, name: str, policy: dict, check_default: bool = True) -> Union[bool, int]:
        """Update an existent policy in the system.

        Parameters
        ----------
        policy_id : int
            ID of the Policy to be updated.
        name : str
            New name for the Policy.
        policy : dict
            New body for the Policy.
        check_default : bool, optional
            Flag that indicates if the policy ID can be less than MAX_ID_RESERVED.

        Returns
        -------
        Union[bool, int]
            True if the policy was updated successfully, False if the operation failed, or a SecurityError code.
        """
        try:
            policy_to_update = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
            if policy_to_update and policy_to_update is not None:
                if policy_to_update.id > MAX_ID_RESERVED or not check_default:
                    # Policy is not a valid json
                    if policy is not None and not isinstance(policy, dict):
                        return SecurityError.INVALID
                    if name is not None:
                        policy_to_update.name = name
                    if (
                        policy is not None
                        and 'actions' in policy.keys()
                        and 'resources' in policy
                        and 'effect' in policy
                    ):
                        for action in policy['actions']:
                            if not re.match(self.ACTION_REGEX, action):
                                return SecurityError.INVALID
                        for resource in policy['resources']:
                            if not all(re.match(self.RESOURCE_REGEX, res) for res in resource.split('&')):
                                return SecurityError.INVALID
                        policy_to_update.policy = json.dumps(policy)
                    self.session.commit()
                    return True
                return SecurityError.ADMIN_RESOURCES
            return SecurityError.POLICY_NOT_EXIST
        except IntegrityError:
            self.session.rollback()
            return SecurityError.ALREADY_EXIST

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the policies from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_policies = manager.get_data(source, Policies, Policies.id, from_id=from_id, to_id=to_id)

        for policy in old_policies:
            status = self.add_policy(
                name=policy.name,
                policy=json.loads(policy.policy),
                created_at=policy.created_at,
                policy_id=policy.id,
                check_default=False,
            )
            # If the user's policy has the same body as an existing default policy, it won't be inserted and its
            # role-policy relationships will be linked to that default policy instead of replacing it.
            if status == SecurityError.ALREADY_EXIST:
                logger.warning(
                    f'Policy {policy.id} ({policy.name}) is part of the new default policies. '
                    'Attempting to migrate relationships'
                )
                roles_policies = (
                    manager.get_table(manager.sessions[source], RolesPolicies)
                    .filter(RolesPolicies.policy_id == policy.id)
                    .order_by(RolesPolicies.id.asc())
                    .all()
                )
                new_policy_id = manager.sessions[target].query(Policies).filter_by(policy=str(policy.policy)).first().id

                with RolesPoliciesManager(manager.sessions[target]) as role_policy_manager:
                    for role_policy in roles_policies:
                        role_policy_manager.add_policy_to_role(
                            role_id=role_policy.role_id,
                            policy_id=new_policy_id,
                            position=role_policy.level,
                            created_at=role_policy.created_at,
                            force_admin=True,
                        )
                    logger.info(f'All relationships were migrated to the new policy {new_policy_id}')


class UserRolesManager(RBACManager):
    """Manager of the UserRoles class.
    This class provides all the methods needed for the administration of the UserRoles objects.
    """

    def add_role_to_user(
        self,
        user_id: int,
        role_id: int,
        position: int = None,
        created_at: datetime = None,
        force_admin: bool = False,
        atomic: bool = True,
    ) -> Union[bool, int]:
        """Add a relation between a specified user and a specified role.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of the role.
        position : int
            Order to be applied in case of multiple roles assigned to the same user.
        created_at : datetime
            Date when the resource was created.
        force_admin : bool
            Flag used to update administrator users, which cannot be updated by default.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the role was added to the user successfully or a SecurityError code if the operation failed.
        """
        try:
            # Create a role-policy relationship if both exist
            if user_id > MAX_ID_RESERVED or force_admin:
                user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if (
                    position is not None
                    or self.session.scalars(
                        select(UserRoles).filter_by(user_id=user_id, role_id=role_id).limit(1)
                    ).first()
                    is None
                ):
                    if (
                        position is not None
                        and self.session.scalars(
                            select(UserRoles).filter_by(user_id=user_id, level=position).limit(1)
                        ).first()
                        and self.session.scalars(
                            select(UserRoles).filter_by(user_id=user_id, role_id=role_id).limit(1)
                        ).first()
                        is None
                    ):
                        user_roles = [
                            row
                            for row in self.session.query(UserRoles)
                            .filter(UserRoles.user_id == user_id, UserRoles.level >= position)
                            .order_by(UserRoles.level)
                            .all()
                        ]
                        new_level = position
                        for relation in user_roles:
                            relation.level = new_level + 1
                            new_level += 1

                    user.roles.append(role)
                    user_role = self.session.scalars(
                        select(UserRoles).filter_by(user_id=user_id, role_id=role_id).limit(1)
                    ).first()
                    if position is None:
                        roles = user.get_roles()
                        position = len(roles) - 1
                    else:
                        max_position = max(
                            [row.level for row in self.session.query(UserRoles).filter_by(user_id=user_id).all()]
                        )
                        if max_position == 0 and len(list(user.roles)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    user_role.level = position
                    user_role.created_at = created_at or get_utc_now()

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def add_user_to_role(self, user_id: int, role_id: int, position: int = -1, atomic: bool = True) -> Union[bool, int]:
        """Add a relation between a specified user and a specified role.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of the role.
        position : int
            Order to be applied in case of multiple roles assigned to the same user.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the role was added to the user successfully or a SecurityError code if the operation failed.
        """
        return self.add_role_to_user(user_id=user_id, role_id=role_id, position=position, atomic=atomic)

    def get_all_roles_from_user(self, user_id: int) -> Union[bool, list]:
        """Get all the roles related to the specified user.

        Parameters
        ----------
        user_id : int
            ID of the user to get the roles from.

        Returns
        -------
        Union[bool, list]
            List of the roles related to the specified user or False if the operation failed.
        """
        try:
            user_roles = self.session.scalars(
                select(UserRoles).filter_by(user_id=user_id).order_by(UserRoles.level)
            ).all()
            roles = list()
            for relation in user_roles:
                roles.append(self.session.scalars(select(Roles).filter_by(id=relation.role_id).limit(1)).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_users_from_role(self, role_id: int) -> Union[bool, map]:
        """Get all the users related to the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        Union[bool, map]
            List of the users related to the specified user or False if the operation failed.
        """
        try:
            role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            return map(partial(User.to_dict, session=self.session), role.users)
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_user_role(self, user_id: int, role_id: int) -> Union[bool, int]:
        """Check if the relationship between a specified user and a specified role exists.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of th role.

        Returns
        -------
        Union[bool, int]
            True if the relationship exists, False if the relationship does not exist, or a SecurityError code.
        """
        try:
            user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
            if user is None:
                return SecurityError.USER_NOT_EXIST
            role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            role = user.roles.filter_by(id=role_id).first()
            if role is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_role_user(self, user_id: int, role_id: int) -> Union[bool, int]:
        """Check if the relationship between a specified user and a specified role exists.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of th role.

        Returns
        -------
        Union[bool, int]
            True if the relationship exists, False if the relationship does not exist, or a SecurityError code.
        """
        return self.exist_user_role(user_id=user_id, role_id=role_id)

    def remove_role_in_user(self, user_id: int, role_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specified user and a specified role.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of the role.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code if the operation failed.
        """
        try:
            if user_id > MAX_ID_RESERVED:  # Administrator
                user = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first()
                if user is None:
                    return SecurityError.USER_NOT_EXIST
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if (
                    self.session.scalars(select(UserRoles).filter_by(user_id=user_id, role_id=role_id).limit(1)).first()
                    is not None
                ):
                    user = self.session.get(User, user_id)
                    role = self.session.get(Roles, role_id)
                    user.roles.remove(role)
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_user_in_role(self, user_id: int, role_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specified user and a specified role.

        Parameters
        ----------
        user_id : int
            ID of the user.
        role_id : int
            ID of the role.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code if the operation failed.
        """
        return self.remove_role_in_user(user_id=user_id, role_id=role_id, atomic=atomic)

    def remove_all_roles_in_user(self, user_id: int) -> bool:
        """Remove the relationships between a specified user and all its roles.

        Parameters
        ----------
        user_id : int
            ID of the user.

        Returns
        -------
        bool
            True if the relationships were deleted successfully, False otherwise.
        """
        try:
            if user_id > MAX_ID_RESERVED:
                roles = self.session.scalars(select(User).filter_by(id=user_id).limit(1)).first().roles
                for role in roles:
                    self.remove_role_in_user(user_id=user_id, role_id=role.id, atomic=False)
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_users_in_role(self, role_id: int) -> Union[bool, int]:
        """Remove the relationships between a specified role and the users related to it.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        bool
            True if the relationships were deleted successfully, False otherwise.
        """
        try:
            if int(role_id) > MAX_ID_RESERVED:
                users = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first().users
                for user in users:
                    if self.remove_user_in_role(user_id=user.id, role_id=role_id, atomic=False) is not True:
                        return SecurityError.RELATIONSHIP_ERROR
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_user_role(
        self, user_id: int, actual_role_id: int, new_role_id: int, position: int = -1
    ) -> Union[bool, int]:
        """Replace an existing relationship with another one.

        Parameters
        ----------
        user_id : int
            ID of the user.
        actual_role_id : int
            ID of the role.
        new_role_id : int
            ID of the new role.
        position : int
            Order to be applied in case of multiple roles assigned to the same user.

        Returns
        -------
        Union[bool, int]
            True if the relationship was replaced successfully, False if the operation failed, or a SecurityError code.
        """
        if (
            user_id > MAX_ID_RESERVED
            and self.exist_user_role(user_id=user_id, role_id=actual_role_id)
            and self.session.scalars(select(Roles).filter_by(id=new_role_id).limit(1)).first() is not None
        ):
            if (
                self.remove_role_in_user(user_id=user_id, role_id=actual_role_id, atomic=False) is not True
                or self.add_user_to_role(user_id=user_id, role_id=new_role_id, position=position, atomic=False)
                is not True
            ):
                return SecurityError.RELATIONSHIP_ERROR
            self.session.commit()
            return True

        return False

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the user roles from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_user_roles = manager.get_data(
            source, UserRoles, UserRoles.user_id, UserRoles.role_id, from_id=from_id, to_id=to_id
        )
        old_user_roles = sorted(old_user_roles, key=lambda item: item.level)

        for user_role in old_user_roles:
            user_id = user_role.user_id
            role_id = user_role.role_id
            # Look for the ID of a default resource from the old database in the new database using its name
            # This allows us to keep the relationship if the related default resource now has a different id
            if int(user_id) <= MAX_ID_RESERVED:
                try:
                    user_name = (
                        manager.get_table(manager.sessions[source], User).filter(User.id == user_id).first().username
                    )
                    user_id = AuthenticationManager(manager.sessions[target]).get_user(username=user_name)['id']
                except TypeError:
                    logger.warning(
                        f'User {user_id} ({user_name}) no longer exists. Removing affected ' 'user-role relationships'
                    )
                    continue

            if int(role_id) <= MAX_ID_RESERVED:
                try:
                    role_name = (
                        manager.get_table(manager.sessions[source], Roles).filter(Roles.id == role_id).first().name
                    )
                    role_id = RolesManager(manager.sessions[target]).get_role(name=role_name)['id']
                except TypeError:
                    logger.warning(
                        f'Role {role_id} ({role_name}) no longer exists. Removing affected ' 'user-role relationships'
                    )
                    continue

            self.add_role_to_user(user_id=user_id, role_id=role_id, created_at=user_role.created_at, force_admin=True)


class RolesPoliciesManager(RBACManager):
    """Manager of the RolesPolicies class.
    This class provides all the methods needed for the administration of the RolesPolicies objects.
    """

    def add_policy_to_role(
        self,
        role_id: int,
        policy_id: int,
        position: int = None,
        created_at: datetime = None,
        force_admin: bool = False,
        atomic: bool = True,
    ) -> Union[bool, int]:
        """Add a relationship between a specified policy and a specified role.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.
        position : int
            Order to be applied in case of multiple policies in the same role.
        created_at : datetime
            Date when the resource was created.
        force_admin : bool
            Flag used to update administrator roles, which cannot be updated by default.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the policy was added successfully or a SecurityError code if the operation failed.
        """

        def check_max_level(role_id_filter: int) -> int:
            """Get the highest level from the relationships between a specified role and all its policies.

            Parameters
            ----------
            role_id_filter : int
                ID of the role to filter by.

            Returns
            -------
            int
                Highest level of the role relationships with its policies.
            """
            return max(
                [r.level for r in self.session.scalars(select(RolesPolicies).filter_by(role_id=role_id_filter)).all()]
            )

        try:
            # Create a role-policy relationship if both exist
            if int(role_id) > MAX_ID_RESERVED or force_admin:
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST
                if (
                    position is not None
                    or self.session.scalars(
                        select(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).limit(1)
                    ).first()
                    is None
                ):
                    if (
                        position is not None
                        and self.session.scalars(
                            select(RolesPolicies).filter_by(role_id=role_id, level=position).limit(1)
                        ).first()
                        and self.session.scalars(
                            select(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).limit(1)
                        ).first()
                        is None
                    ):
                        role_policies = [
                            row
                            for row in self.session.query(RolesPolicies)
                            .filter(RolesPolicies.role_id == role_id, RolesPolicies.level >= position)
                            .order_by(RolesPolicies.level)
                            .all()
                        ]
                        new_level = position
                        for relation in role_policies:
                            relation.level = new_level + 1
                            new_level += 1

                    role.policies.append(policy)
                    role_policy = self.session.scalars(
                        select(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).limit(1)
                    ).first()
                    if position is None or position > check_max_level(role_id) + 1:
                        position = len(role.get_policies()) - 1
                    else:
                        max_position = max(
                            [
                                row.level
                                for row in self.session.scalars(select(RolesPolicies).filter_by(role_id=role_id)).all()
                            ]
                        )
                        if max_position == 0 and len(list(role.policies)) - 1 == 0:
                            position = 0
                        elif position > max_position + 1:
                            position = max_position + 1
                    role_policy.level = position
                    role_policy.created_at = created_at or get_utc_now()

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def add_role_to_policy(
        self, policy_id: int, role_id: int, position: int = None, force_admin: bool = False, atomic: bool = True
    ) -> Union[bool, int]:
        """Add a relationship between a specified policy and a specified role.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.
        position : int
            Order to be applied in case of multiple policies in the same role.
        created_at : datetime
            Date when the resource was created.
        force_admin : bool
            Flag used to update administrator roles, which cannot be updated by default.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the policy was added successfully or a SecurityError code if the operation failed.
        """
        return self.add_policy_to_role(
            role_id=role_id, policy_id=policy_id, position=position, force_admin=force_admin, atomic=atomic
        )

    def get_all_policies_from_role(self, role_id: int) -> Union[list, bool]:
        """Get all the policies related to the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role

        Returns
        -------
        Union[list, bool]
            List of policies related to the role or False if the operation failed.
        """
        try:
            role_policies = self.session.scalars(
                select(RolesPolicies).filter_by(role_id=role_id).order_by(RolesPolicies.level)
            ).all()
            policies = list()
            for relation in role_policies:
                policy = self.session.scalars(select(Policies).filter_by(id=relation.policy_id).limit(1)).first()
                if policy:
                    policies.append(policy)
            return policies
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_roles_from_policy(self, policy_id: int) -> Union[list, bool]:
        """Get all the roles containing a specified policy.

        Parameters
        ----------
        policy_id : int
            ID of the policy.

        Returns
        -------
        Union[list, bool]
            List of roles having the specified policy or False if the operation failed.
        """
        try:
            policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
            roles = policy.roles
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_role_policy(self, role_id: int, policy_id: int) -> Union[bool, int]:
        """Check if a relationship between a role and a policy exits.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.

        Returns
        -------
        Union[bool, int]
            True if the relationship exists, False if the relationship does not exist, or a SecurityError code.
        """
        try:
            role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
            if policy is None:
                return SecurityError.POLICY_NOT_EXIST
            policy = role.policies.filter_by(id=policy_id).first()
            if policy is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_policy_role(self, policy_id: int, role_id: int) -> Union[bool, int]:
        """Check if a relationship between a role and a policy exits.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.

        Returns
        -------
        Union[bool, int]
            True if the relationship exists, False if the relationship does not exist, or a SecurityError code.
        """
        return self.exist_role_policy(role_id, policy_id)

    def remove_policy_in_role(self, role_id: int, policy_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specific role and a specific policy if both exist.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code otherwise.
        """
        try:
            if int(role_id) > MAX_ID_RESERVED:  # Administrator
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                policy = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first()
                if policy is None:
                    return SecurityError.POLICY_NOT_EXIST

                role_policy = self.session.scalars(
                    select(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).limit(1)
                ).first()

                if role_policy is not None:
                    role = self.session.get(Roles, role_id)
                    policy = self.session.get(Policies, policy_id)
                    role.policies.remove(policy)

                    # Update position value
                    relationships_to_update = [
                        row
                        for row in self.session.query(RolesPolicies).filter(
                            RolesPolicies.role_id == role_id, RolesPolicies.level >= role_policy.level
                        )
                    ]

                    for relation in relationships_to_update:
                        relation.level -= 1

                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_role_in_policy(self, role_id: int, policy_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specific role and a specific policy if both exist.

        Parameters
        ----------
        role_id : int
            ID of the role.
        policy_id : int
            ID of the policy.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code otherwise.
        """
        return self.remove_policy_in_role(role_id=role_id, policy_id=policy_id, atomic=atomic)

    def remove_all_policies_in_role(self, role_id: int) -> Union[bool, int]:
        """Remove all relationships between a specified role and its policies.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        Union[bool, int]
            True if the relationships were removed successfully or a SecurityError code otherwise.
        """
        try:
            if int(role_id) > MAX_ID_RESERVED:
                policies = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first().policies
                for policy in policies:
                    if self.remove_policy_in_role(role_id=role_id, policy_id=policy.id, atomic=False) is not True:
                        return SecurityError.RELATIONSHIP_ERROR
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_roles_in_policy(self, policy_id: int) -> bool:
        """Remove all relationships between a specified policy and the roles it belongs to.

        Parameters
        ----------
        policy_id : int
            ID of the policy.

        Returns
        -------
        bool
            True if the relationships were removed successfully or a SecurityError code otherwise.
        """
        try:
            if int(policy_id) > MAX_ID_RESERVED:
                roles = self.session.scalars(select(Policies).filter_by(id=policy_id).limit(1)).first().roles
                for rol in roles:
                    self.remove_policy_in_role(role_id=rol.id, policy_id=policy_id, atomic=False)
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id: int, current_policy_id: int, new_policy_id: int) -> Union[int, bool]:
        """Replace an existing relationship with another one.

        Parameters
        ----------
        role_id : int
            ID of the role.
        current_policy_id : int
            ID of a policy related to the role.
        new_policy_id : int
            ID of the new policy to relate to the role.

        Returns
        -------
        Union[int, bool]
            True if the relationship was replaced successfully, False or SecurityError code otherwise.
        """
        if (
            int(role_id) > MAX_ID_RESERVED
            and self.exist_role_policy(role_id=role_id, policy_id=current_policy_id)
            and self.session.scalars(select(Policies).filter_by(id=new_policy_id).limit(1)).first() is not None
        ):
            if (
                self.remove_policy_in_role(role_id=role_id, policy_id=current_policy_id, atomic=False) is not True
                or self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id, atomic=False) is not True
            ):
                return SecurityError.RELATIONSHIP_ERROR
            self.session.commit()
            return True

        return False

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the roles policies from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_roles_policies = manager.get_data(
            source, RolesPolicies, RolesPolicies.role_id, RolesPolicies.policy_id, from_id, to_id
        )
        old_roles_policies = sorted(old_roles_policies, key=lambda item: item.level)
        for role_policy in old_roles_policies:
            role_id = role_policy.role_id
            policy_id = role_policy.policy_id

            # Look for the ID of a default resource from the old database in the new database using its name
            # This allows us to keep the relationship if the related default resource now has a different id
            if int(role_id) <= MAX_ID_RESERVED:
                try:
                    role_name = (
                        manager.get_table(manager.sessions[source], Roles).filter(Roles.id == role_id).first().name
                    )
                    role_id = RolesManager(manager.sessions[target]).get_role(name=role_name)['id']
                except TypeError:
                    logger.warning(
                        f'Role {role_id} ({role_name}) no longer exists. Removing affected ' 'role-policy relationships'
                    )
                    continue

            if int(policy_id) <= MAX_ID_RESERVED:
                try:
                    policy_name = (
                        manager.get_table(manager.sessions[source], Policies)
                        .filter(Policies.id == policy_id)
                        .first()
                        .name
                    )
                    policy_id = PoliciesManager(manager.sessions[target]).get_policy(name=policy_name)['id']
                except TypeError:
                    logger.warning(
                        f'Policy {policy_id} ({policy_name}) no longer exists. Removing affected '
                        'role-policy relationships'
                    )
                    continue

            self.add_policy_to_role(
                role_id=role_id, policy_id=policy_id, created_at=role_policy.created_at, force_admin=True
            )


class RolesRulesManager(RBACManager):
    """Manager of the RolesRules class.
    This class provides all the methods needed for the administration of the RolesRules objects.
    """

    def add_rule_to_role(
        self, rule_id: int, role_id: int, created_at: datetime = None, atomic: bool = True, force_admin: bool = False
    ) -> Union[bool, int]:
        """Add a relation between a specified role and a specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the rule
        role_id : int
            ID of the role.
        created_at : datetime
            Date when the resource was created.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.
        force_admin : bool
            Flag used to update administrator roles, which cannot be updated by default.

        Returns
        -------
        Union[bool, int]:
            True if the rule was added successfully or a SecurityError code if the operation failed.
        """
        try:
            # Create a rule-role relationship if both exist
            if int(rule_id) > MAX_ID_RESERVED or force_admin:
                rule = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
                if rule is None:
                    return SecurityError.RULE_NOT_EXIST
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST

                if (
                    self.session.scalars(
                        select(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).limit(1)
                    ).first()
                    is None
                ):
                    role.rules.append(rule)
                    role_rule = self.session.scalars(
                        select(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).limit(1)
                    ).first()
                    role_rule.created_at = created_at or get_utc_now()
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.ALREADY_EXIST
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, InvalidRequestError):
            self.session.rollback()
            return SecurityError.INVALID

    def get_all_rules_from_role(self, role_id: int) -> Union[list, bool]:
        """Get all the rules related to the specified role.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        Union[list, bool]
            List of rules related to the role or False if the operation failed.
        """
        try:
            rule_roles = self.session.scalars(
                select(RolesRules).filter_by(role_id=role_id).order_by(RolesRules.id)
            ).all()
            rules = list()
            for relation in rule_roles:
                rules.append(self.session.scalars(select(Rules).filter_by(id=relation.rule_id).limit(1)).first())
            return rules
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def get_all_roles_from_rule(self, rule_id: int) -> Union[list, bool]:
        """Get all the roles related to the specified rule.

        Parameters
        ----------
        rule_id : int
            ID of the role.

        Returns
        -------
        Union[list, bool]
            List of roles related to the rule or False if the operation failed.
        """
        try:
            role_rules = self.session.scalars(
                select(RolesRules).filter_by(rule_id=rule_id).order_by(RolesRules.id)
            ).all()
            roles = list()
            for relation in role_rules:
                roles.append(self.session.scalars(select(Roles).filter_by(id=relation.role_id).limit(1)).first())
            return roles
        except (IntegrityError, AttributeError):
            self.session.rollback()
            return False

    def exist_role_rule(self, role_id: int, rule_id: int) -> Union[bool, int]:
        """Check if the relationship between a specified role and a specified rule exists.

        Parameters
        ----------
        role_id : int
            ID of the role.
        rule_id : int
            ID of the rule.

        Returns
        -------
        Union[bool, int]
            True if the relationship exists, False or a SecurityError code otherwise.
        """
        try:
            rule = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
            if rule is None:
                return SecurityError.RULE_NOT_EXIST
            role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
            if role is None:
                return SecurityError.ROLE_NOT_EXIST
            match = role.rules.filter_by(id=rule_id).first()
            if match is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_rule_in_role(self, rule_id: int, role_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specified rule and a specified role if both exist.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        role_id : int
            ID of the role.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code if the operation failed.
        """
        try:
            if int(rule_id) > MAX_ID_RESERVED:  # Required rule
                rule = self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first()
                if rule is None:
                    return SecurityError.RULE_NOT_EXIST
                role = self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first()
                if role is None:
                    return SecurityError.ROLE_NOT_EXIST
                if (
                    self.session.scalars(
                        select(RolesRules).filter_by(rule_id=rule_id, role_id=role_id).limit(1)
                    ).first()
                    is not None
                ):
                    rule = self.session.get(Rules, rule_id)
                    role = self.session.get(Roles, role_id)
                    rule.roles.remove(role)
                    atomic and self.session.commit()
                    return True
                else:
                    return SecurityError.INVALID
            return SecurityError.ADMIN_RESOURCES
        except IntegrityError:
            self.session.rollback()
            return SecurityError.INVALID

    def remove_role_in_rule(self, rule_id: int, role_id: int, atomic: bool = True) -> Union[bool, int]:
        """Remove a relationship between a specified rule and a specified role if both exist.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        role_id : int
            ID of the role.
        atomic : bool
            Flag used to indicate the atomicity of the operation. If this function is called within a loop or a function
            composed of several operations, atomicity cannot be guaranteed unless this flag is set to True.

        Returns
        -------
        Union[bool, int]
            True if the relationship was removed successfully or a SecurityError code if the operation failed.
        """
        return self.remove_rule_in_role(rule_id=rule_id, role_id=role_id, atomic=atomic)

    def remove_all_roles_in_rule(self, rule_id: int) -> Union[bool, int]:
        """Remove all relationships between a specified rule and its roles.

        Parameters
        ----------
        rule_id : int
            ID of the rule

        Returns
        -------
        Union[bool, int]
            True if the relationships were removed successfully, False or a SecurityError code otherwise.
        """
        try:
            if int(rule_id) > MAX_ID_RESERVED:
                self.session.scalars(select(Rules).filter_by(id=rule_id).limit(1)).first().roles = list()
                self.session.commit()
                return True
            return SecurityError.ADMIN_RESOURCES
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def remove_all_rules_in_role(self, role_id: int) -> bool:
        """Remove all relationships between a specified role and its rules.

        Parameters
        ----------
        role_id : int
            ID of the role.

        Returns
        -------
        bool
            True if the relationships were removed successfully, False otherwise.
        """
        try:
            if int(role_id) > MAX_ID_RESERVED:
                self.session.scalars(select(Roles).filter_by(id=role_id).limit(1)).first().rules = list()
                self.session.commit()
                return True
        except (IntegrityError, TypeError):
            self.session.rollback()
            return False

    def replace_rule_role(self, rule_id: int, current_role_id: int, new_role_id: int) -> Union[bool, int]:
        """Replace an existing relationship between a specified rule and a specified role with another one.

        Parameters
        ----------
        rule_id : int
            ID of the rule.
        current_role_id : int
            ID of the related role to be replaced.
        new_role_id : int
            ID of the role to be replaced in the relationship.

        Returns
        -------
        Union[bool, int]
            True if the relationship was replaced successfully, False or a SecurityError code otherwise.
        """
        if (
            current_role_id > MAX_ID_RESERVED
            and self.exist_role_rule(rule_id=rule_id, role_id=current_role_id)
            and self.session.session.scalars(select(Roles).filter_by(id=new_role_id).limit(1)).first() is not None
        ):
            if (
                self.remove_role_in_rule(rule_id=rule_id, role_id=current_role_id, atomic=False) is not True
                or self.add_rule_to_role(rule_id=rule_id, role_id=new_role_id, atomic=False) is not True
            ):
                return SecurityError.RELATIONSHIP_ERROR

            return True

        return False

    def migrate_data(
        self, manager, source: str, target: str, from_id: Optional[int] = None, to_id: Optional[int] = None
    ) -> None:
        """Get the role rules from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        manager: RBACManager
            The manager in charge of the table data.
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        # This is to avoid an error when trying to update default users, roles, policies and rules
        if check_if_reserved_id(from_id, to_id):
            return

        old_roles_rules = manager.get_data(
            source, RolesRules, RolesRules.role_id, RolesRules.rule_id, from_id=from_id, to_id=to_id
        )
        for role_rule in old_roles_rules:
            role_id = role_rule.role_id
            rule_id = role_rule.rule_id

            # Look for the ID of a default resource from the old database in the new database using its name
            # This allows us to keep the relationship if the related default resource now has a different id
            if int(role_id) <= MAX_ID_RESERVED:
                try:
                    role_name = (
                        manager.get_table(manager.sessions[source], Roles).filter(Roles.id == role_id).first().name
                    )
                    role_id = RolesManager(manager.sessions[target]).get_role(name=role_name)['id']
                except TypeError:
                    logger.warning(
                        f'Role {role_id} ({role_name}) no longer exists. Removing affected ' 'role-rule relationships'
                    )
                    continue

            if int(rule_id) <= MAX_ID_RESERVED:
                try:
                    rule_name = (
                        manager.get_table(manager.sessions[source], Rules).filter(Rules.id == rule_id).first().name
                    )
                    rule_id = RulesManager(manager.sessions[target]).get_rule_by_name(rule_name=rule_name)['id']
                except TypeError:
                    logger.warning(
                        f'Rule {rule_id} ({rule_name}) no longer exists. Removing affected ' 'role-rule relationships'
                    )
                    continue

            self.add_rule_to_role(role_id=role_id, rule_id=rule_id, created_at=role_rule.created_at, force_admin=True)


class DatabaseManager:
    """Class used to manage the RBAC databases."""

    def __init__(self):
        """Class constructor."""
        self.engines = {}
        self.sessions = {}

    def close_sessions(self):
        """Close all the stored database connections."""
        for session in self.sessions:
            self.sessions[session].close()

        for engine in self.engines:
            self.engines[engine].dispose()

    def connect(self, database_path: str):
        """Create database engine and session and bind them.

        Parameters
        ----------
        database_path : str
            Path to the database to connect to.
        """
        self.engines[database_path] = create_engine(f'sqlite:///{database_path}', echo=False)
        self.sessions[database_path] = sessionmaker(bind=self.engines[database_path])()

    def create_database(self, database: str):
        """Create the given database.

        Parameters
        ----------
        database : str
            Name of the stored database.
        """
        # This is the actual sqlite database creation
        _Base.metadata.create_all(self.engines[database])

    def get_database_version(self, database: str) -> str:
        """Get the given database version.

        Parameters
        ----------
        database : str
            Name of the stored database.

        Returns
        -------
        str
            Database version.
        """
        return str(self.sessions[database].execute(text('pragma user_version')).first()[0])

    def insert_default_resources(self, database: str):
        """Insert default security resources into the given database.

        Parameters
        ----------
        database : str
            Name of the stored database.
        """
        # Create default users if they don't exist yet
        with open(os.path.join(DEFAULT_RBAC_RESOURCES, 'users.yaml'), 'r') as stream:
            default_users = yaml.safe_load(stream)

            with AuthenticationManager(self.sessions[database]) as auth:
                for d_username, payload in default_users[next(iter(default_users))].items():
                    auth.add_user(username=d_username, password=payload['password'], check_default=False)
                    auth.edit_run_as(
                        user_id=auth.get_user(username=d_username)['id'], allow_run_as=payload['allow_run_as']
                    )

        # Create default roles if they don't exist yet
        with open(os.path.join(DEFAULT_RBAC_RESOURCES, 'roles.yaml'), 'r') as stream:
            default_roles = yaml.safe_load(stream)

            with RolesManager(self.sessions[database]) as rm:
                for d_role_name, payload in default_roles[next(iter(default_roles))].items():
                    rm.add_role(name=d_role_name, check_default=False)

        with open(os.path.join(DEFAULT_RBAC_RESOURCES, 'rules.yaml'), 'r') as stream:
            default_rules = yaml.safe_load(stream)

            with RulesManager(self.sessions[database]) as rum:
                for d_rule_name, payload in default_rules[next(iter(default_rules))].items():
                    rum.add_rule(name=d_rule_name, rule=payload['rule'], check_default=False)

        # Create default policies if they don't exist yet
        with open(os.path.join(DEFAULT_RBAC_RESOURCES, 'policies.yaml'), 'r') as stream:
            default_policies = yaml.safe_load(stream)

            with PoliciesManager(self.sessions[database]) as pm:
                for d_policy_name, payload in default_policies[next(iter(default_policies))].items():
                    for name, policy in payload['policies'].items():
                        policy_name = f'{d_policy_name}_{name}'
                        pm.add_policy(name=policy_name, policy=policy, check_default=False)

        # Create the relationships
        with open(os.path.join(DEFAULT_RBAC_RESOURCES, 'relationships.yaml'), 'r') as stream:
            default_relationships = yaml.safe_load(stream)

            # User-Roles relationships
            with UserRolesManager(self.sessions[database]) as urm:
                for d_username, payload in default_relationships[next(iter(default_relationships))]['users'].items():
                    with AuthenticationManager(self.sessions[database]) as am:
                        d_user_id = am.get_user(username=d_username)['id']
                    for d_role_name in payload['role_ids']:
                        urm.add_role_to_user(
                            user_id=d_user_id, role_id=rm.get_role(name=d_role_name)['id'], force_admin=True
                        )

            # Role-Policies relationships
            with RolesPoliciesManager(self.sessions[database]) as rpm:
                for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
                    for d_policy_name in payload['policy_ids']:
                        for sub_name in default_policies[next(iter(default_policies))][d_policy_name][
                            'policies'
                        ].keys():
                            rpm.add_policy_to_role(
                                role_id=rm.get_role(name=d_role_name)['id'],
                                policy_id=pm.get_policy(name=f'{d_policy_name}_{sub_name}')['id'],
                                force_admin=True,
                            )

            # Role-Rules relationships
            with RolesRulesManager(self.sessions[database]) as rrum:
                for d_role_name, payload in default_relationships[next(iter(default_relationships))]['roles'].items():
                    for d_rule_name in payload['rule_ids']:
                        rrum.add_rule_to_role(
                            role_id=rm.get_role(name=d_role_name)['id'],
                            rule_id=rum.get_rule_by_name(d_rule_name)['id'],
                            force_admin=True,
                        )

    @staticmethod
    def get_table(session: Session, table: callable):
        """Return the proper `Table` object depending on the database version.

        Parameters
        ----------
        session : Session
            Database session from which to extract data.
        table : callable
            Database table to return.

        Returns
        -------
        SQLAlchemy table object
        """
        try:
            # Try to use the current table schema
            session.query(table).first()
            return session.query(table)
        except OperationalError:
            # Return an old schema without the new columns
            return session.query(table).with_entities(
                *[column for column in table.__table__.columns if column.key not in _new_columns]
            )

    def get_data(
        self, source: str, table: callable, col_a: Column, col_b: Column = None, from_id: int = None, to_id: int = None
    ) -> list:
        """Get the resources from the given table filtering up to 2 columns by the 'from_id' and 'to_id'
        parameters.

        Parameters
        ----------
        source : str
            Path to the database to migrate data from.
        table : callable
            Table from which the resources are gotten.
        col_a : Column
            First column to filter in.
        col_b : Column
            Second column to filter in.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.

        Returns
        -------
        list
            List of resources from the given table with ID filter.
        """
        result = []
        try:
            if from_id and to_id:
                condition = (
                    or_(col_a.between(from_id, to_id), col_b.between(from_id, to_id))
                    if col_b
                    else col_a.between(from_id, to_id)
                )
            elif from_id:
                condition = or_(col_a >= from_id, col_b >= from_id) if col_b else col_a >= from_id
            elif to_id:
                condition = or_(col_a <= from_id, col_b <= from_id) if col_b else col_a <= from_id

            result = [
                resource
                for resource in self.get_table(self.sessions[source], table).filter(condition).order_by(col_a).all()
            ]
        except OperationalError:
            pass

        return result

    def migrate_data(self, source: str, target: str, from_id: int = None, to_id: int = None) -> None:
        """Get the resources from the `source` database filtering by IDs and insert them into the `target` database.
        This function will adapt the relationship between problematic resources if needed.

        Parameters
        ----------
        source : str
            Path to the database to migrate data from.
        target : str
            Path to the database where data will be migrated to.
        from_id : id
            ID which the resources will be migrated from.
        to_id : id
            ID which the resources will be migrated to.
        """
        resources = [
            RolesManager,
            RulesManager,
            PoliciesManager,
            UserRolesManager,
            RolesPoliciesManager,
            RolesRulesManager,
        ]

        with AuthenticationManager(self.sessions[target]) as auth_manager:
            auth_manager.migrate_data(self, source, target, from_id=from_id, to_id=to_id)

        if check_if_reserved_id(from_id=from_id, to_id=to_id):
            logger.warning(f"User {from_id} and {to_id} are part of the default users and can't be updated")
            return

        for manager in resources:
            with manager(self.sessions[target]) as resource_manager:
                resource_manager.migrate_data(self, source, target, from_id=from_id, to_id=to_id)

    def rollback(self, database: str):
        """Abort any pending change for the current session.

        Parameters
        ----------
        database : str
            Path to the database to apply rollback.
        """
        self.sessions[database].rollback()

    def set_database_version(self, database: str, version: int):
        """Set the new value for the database version.

        Parameters
        ----------
        database : str
            Path to the database.
        version : int
            New database version.
        """
        self.sessions[database].execute(text(f'pragma user_version={version}'))


def check_if_reserved_id(from_id: Optional[str], to_id: Optional[str]):
    """Checks if the ids are reserved ones.

    Parameters
    ----------
    from_id : Optional[str]
        ID which the resources will be migrated from.
    to_id : Optional[str]
        ID which the resources will be migrated to.

    Returns
    -------
    bool
        Condition result
    """
    return from_id == WAZUH_USER_ID and to_id == WAZUH_WUI_USER_ID


def check_database_integrity():
    """Check RBAC database integrity.
    If the database does not exist, it must be created properly.
    If the database exists, the RBAC DB migration process is applied.

    Raises
    ------
    ValueError
        Error when trying to retrieve the current RBAC database version.
    Exception
        Generic error during the database migration process.
    """

    def _set_permissions_and_ownership(database: str):
        """Set Wazuh ownership and permissions.

        Parameters
        ----------
        database : str
            Path to the database which permissions are going to be changed.
        """
        chown(database, wazuh_uid(), wazuh_gid())
        os.chmod(database, 0o640)

    try:
        logger.info('Checking RBAC database integrity...')

        if os.path.exists(DB_FILE):
            # If db exists, fix permissions and ownership and connect to it
            logger.info(f'{DB_FILE} file was detected')
            _set_permissions_and_ownership(DB_FILE)
            db_manager.connect(DB_FILE)
            current_version = int(db_manager.get_database_version(DB_FILE))
            expected_version = CURRENT_ORM_VERSION

            # Check if an upgrade is required
            if current_version < expected_version:
                logger.info(
                    'RBAC database migration required. '
                    f'Current version is {current_version} but it should be {expected_version}. '
                    f'Upgrading RBAC database to version {expected_version}'
                )
                # Remove tmp database if present
                os.path.exists(DB_FILE_TMP) and os.remove(DB_FILE_TMP)

                # Create new tmp database and populate it with default resources
                db_manager.connect(DB_FILE_TMP)
                db_manager.create_database(DB_FILE_TMP)
                _set_permissions_and_ownership(DB_FILE_TMP)
                db_manager.insert_default_resources(DB_FILE_TMP)

                # Migrate data from old database
                db_manager.migrate_data(
                    source=DB_FILE, target=DB_FILE_TMP, from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID
                )
                db_manager.migrate_data(
                    source=DB_FILE, target=DB_FILE_TMP, from_id=CLOUD_RESERVED_RANGE, to_id=MAX_ID_RESERVED
                )
                db_manager.migrate_data(source=DB_FILE, target=DB_FILE_TMP, from_id=MAX_ID_RESERVED + 1)

                # Apply changes and replace database
                db_manager.set_database_version(DB_FILE_TMP, expected_version)
                db_manager.close_sessions()
                safe_move(DB_FILE_TMP, DB_FILE, ownership=(wazuh_uid(), wazuh_gid()), permissions=0o640)
                logger.info(f'{DB_FILE} database upgraded successfully')

        # If the database does not exist, it means this is a fresh installation and must be created properly
        else:
            logger.info('RBAC database not found. Initializing')
            db_manager.connect(DB_FILE)
            db_manager.create_database(DB_FILE)
            _set_permissions_and_ownership(DB_FILE)
            db_manager.insert_default_resources(DB_FILE)
            db_manager.set_database_version(DB_FILE, CURRENT_ORM_VERSION)
            db_manager.close_sessions()
            logger.info(f'{DB_FILE} database created successfully')
    except ValueError as e:
        logger.error('Error retrieving the current Wazuh RBAC database version. Aborting database integrity check')
        db_manager.close_sessions()
        raise e
    except Exception as e:
        logger.error('Error during the database migration. Restoring the previous database file')
        logger.error(f'Error details: {str(e)}')
        db_manager.close_sessions()
        raise e
    else:
        logger.info('RBAC database integrity check finished successfully')
    finally:
        # Remove tmp database if present
        os.path.exists(DB_FILE_TMP) and os.remove(DB_FILE_TMP)


db_manager = DatabaseManager()
