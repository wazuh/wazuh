#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


#####################################################################################
#                                                                                   #
#   Usage:                                                                          #
#       When we modify the structure of our database we will have to use the        #
#                                                                                   #
#                               flask db migrate                                    #
#                                                                                   #
#       command in order to migrate the changes.                                    #
#       Once we have the migrated changes we will have generated a version file     #
#       inside the versions folder, to apply the changes we must do a               #
#                                                                                   #
#                               flask db upgrade                                    #
#                                                                                   #
#       We also have the option to do a downgrade to remove the last commit         #
#       that has the database                                                       #
#                                                                                   #
#####################################################################################

import os
import json
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.sqlite import TEXT
from api.constants import SECURITY_PATH
from sqlalchemy.ext.declarative import declarative_base
from shutil import chown
from datetime import datetime


app = Flask(__name__)
_rbac_db_file = os.path.join(SECURITY_PATH, 'RBAC.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + _rbac_db_file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
Migrate(app, db)

_engine = create_engine(f'sqlite:///' + os.path.join(SECURITY_PATH, 'RBAC.db'), echo=False)
_Base = declarative_base()
_Session = sessionmaker(bind=_engine)
admins_id = [1]
admin_policy = [1]


class RolesPolicies(_Base):
    """"""
    __tablename__ = "roles_policies"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    role_id = db.Column('role_id', db.Integer, db.ForeignKey("roles.id", ondelete='CASCADE'))
    policy_id = db.Column('policy_id', db.Integer, db.ForeignKey("policies.id", ondelete='CASCADE'))
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow(), onpudate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('role_id', 'policy_id', name='role_policy'),
                      )


def json_validator(data):
    if isinstance(data, dict):
        return True

    return False


class Policies(_Base):
    """"""
    __tablename__ = "policies"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    policy = db.Column('policy', TEXT)
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow(), onpudate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_policy'),
                      UniqueConstraint('policy', name='policy_definition'))

    # Relations
    roles = db.relationship("Roles", secondary='roles_policies',
                            backref=db.backref("roless", cascade="all,delete", order_by=id), lazy='dynamic')

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def get_policy(self):
        return {'id': self.id, 'name': self.name, 'policy': self.policy}

    def to_dict(self):
        roles = list()
        for role in self.roles:
            roles.append(role.get_policy())

        return {'id': self.id, 'name': self.name, 'policy': self.policy, 'roles': roles}


class Roles(_Base):
    """"""
    __tablename__ = "roles"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    rule = db.Column('rule', TEXT)
    created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow())
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow(), onpudate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('name', name='name_role'),
                      UniqueConstraint('rule', name='role_definition'))

    # Relations
    policies = db.relationship("Policies", secondary='roles_policies',
                               backref=db.backref("policiess", cascade="all,delete", order_by=id), lazy='dynamic')

    def __init__(self, name, rule):
        self.name = name
        self.rule = rule
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def get_policy(self):
        return {'id': self.id, 'name': self.name, 'rule': self.rule}

    def to_dict(self):
        policies = list()
        for policy in self.policies:
            policies.append(policy.get_policy())

        return {'id': self.id, 'name': self.name, 'rule': self.rule, 'policies': policies}


class RolesManager:
    def get_role(self, name):
        try:
            role = self.session.query(Roles).filter_by(name=name).first()
            return role
        except IntegrityError:
            return False

    def get_role_id(self, id):
        try:
            role = self.session.query(Roles).filter_by(id=id).first()
            return role
        except IntegrityError:
            return False

    def get_roles(self):
        try:
            roles = self.session.query(Roles).all()
            return roles
        except IntegrityError:
            return False

    def add_role(self, name, rule):
        try:
            if (rule is None) or (rule is not None and not json_validator(rule)):
                return -1
            self.session.add(Roles(name=name, rule=json.dumps(rule)))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role(self, role_id):
        try:
            if int(role_id) not in admins_id:
                relations = self.session.query(RolesPolicies).filter_by(role_id=role_id).all()
                for role_policy in relations:
                    self.session.delete(role_policy)
                if self.session.query(Roles).filter_by(id=role_id).first() is None:
                    self.session.rollback()
                    return False
                self.session.query(Roles).filter_by(id=role_id).delete()
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role_by_name(self, role_name):
        try:
            if self.get_role(role_name).id not in admins_id:
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
        try:
            list_roles = list()
            roles = self.session.query(Roles).all()
            for role in roles:
                if role.id not in admins_id:
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

    def update_role(self, role_id, name, rule):
        try:
            role_to_update = self.session.query(Roles).filter_by(id=role_id).first()
            if role_to_update not in admins_id and role_to_update is not None:
                if rule is not None and not json_validator(rule):
                    return -1
                if name is not None:
                    role_to_update.name = name
                if rule is not None:
                    role_to_update.rule = json.dumps(rule)
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class PoliciesManager:
    def get_policy(self, name):
        try:
            policy = self.session.query(Policies).filter_by(name=name).first()
            return policy
        except IntegrityError:
            return False

    def get_policy_by_id(self, id):
        try:
            policy = self.session.query(Policies).filter_by(id=id).first()
            return policy
        except IntegrityError:
            return False

    def get_policies(self):
        try:
            policies = self.session.query(Policies).all()
            return policies
        except IntegrityError:
            return False

    def add_policy(self, name, policy):
        try:
            if (policy is None) or (policy is not None and not json_validator(policy)):
                return False
            self.session.add(Policies(name=name, policy=json.dumps(policy)))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy(self, policy_id):
        try:
            if int(policy_id) not in admin_policy:
                relations = self.session.query(RolesPolicies).filter_by(policy_id=policy_id).all()
                for role_policy in relations:
                    self.session.delete(role_policy)
                if self.session.query(Policies).filter_by(id=policy_id).first() is None:
                    self.session.rollback()
                    return False
                self.session.query(Policies).filter_by(id=policy_id).delete()
                self.session.commit()
                return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy_by_name(self, policy_name):
        try:
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
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_all_policies(self):
        try:
            list_policies = list()
            policies = self.session.query(Policies).all()
            for policy in policies:
                if policy.id not in admin_policy:
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

    def update_policy(self, policy_id, name, policy):
        try:
            policy_to_update = self.session.query(Policies).filter_by(id=policy_id).first()
            if policy_to_update not in admin_policy and policy_to_update is not None:
                if policy is not None and not json_validator(policy):
                    return -1
                if name is not None:
                    policy_to_update.name = name
                if policy is not None:
                    policy_to_update.policy = json.dumps(policy)
                self.session.commit()
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class RolesPoliciesManager:
    def add_policy_to_role_admin(self, role_id, policy_id):
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

    def add_policy_to_role(self, role_id, policy_id):
        try:
            if int(role_id) not in admins_id:
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return -1
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return -2
                if self.session.query(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is None:
                    role.policies.append(self.session.query(Policies).filter_by(id=policy_id).first())
                    self.session.commit()
                    return True
                else:
                    return -3
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def add_role_to_policy(self, policy_id, role_id):
        return self.add_policy_to_role(role_id=role_id, policy_id=policy_id)

    def get_all_policies_from_role(self, role_id):
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            policies = role.policies
            return policies
        except IntegrityError:
            self.session.rollback()
            return False

    def get_all_roles_from_policy(self, policy_id):
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            roles = policy.roles
            return roles
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_role_policy(self, role_id, policy_id):
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            policy = role.policies.filter_by(id=policy_id).first()
            if policy is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def exist_policy_role(self, policy_id, role_id):
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            role = policy.roles.filter_by(id=role_id).first()
            if role is not None:
                return True
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_policy_in_role(self, role_id, policy_id):
        try:
            if int(role_id) not in admins_id:  # Administrator
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return -1
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return -2
                if self.session.query(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is not None:
                    role = self.session.query(Roles).get(role_id)
                    policy = self.session.query(Policies).get(policy_id)
                    role.policies.remove(policy)
                    self.session.commit()
                    return True
                else:
                    return -3
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_role_in_policy(self, policy_id, role_id):
        try:
            if int(role_id) not in admins_id:  # Administrator
                role = self.session.query(Roles).filter_by(id=role_id).first()
                if role is None:
                    return -1
                policy = self.session.query(Policies).filter_by(id=policy_id).first()
                if policy is None:
                    return -2
                if self.session.query(RolesPolicies).filter_by(role_id=role_id, policy_id=policy_id).first() is not None:
                    policy = self.session.query(Policies).get(policy_id)
                    role = self.session.query(Roles).get(role_id)
                    policy.roles.remove(role)
                    self.session.commit()
                    return True
                else:
                    return -3
            return False
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_all_policies_in_role(self, role_id):
        try:
            if int(role_id) not in admins_id:
                policies = self.session.query(Roles).filter_by(id=role_id).first().policies
                for policy in policies:
                    self.remove_policy_in_role(role_id=role_id, policy_id=policy.id)
                return True
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_all_roles_in_policy(self, policy_id):
        try:
            if policy_id not in admin_policy:
                roles = self.session.query(Policies).filter_by(id=policy_id).first().roles
                for rol in roles:
                    if rol.id != 1:
                        self.remove_policy_in_role(role_id=rol.id, policy_id=policy_id)
                return True
        except IntegrityError:
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id, actual_policy_id, new_policy_id):
        if int(role_id) not in admins_id:
            if self.exist_role_policy(role_id=role_id, policy_id=actual_policy_id) and \
                    self.session.query(Policies).filter_by(id=new_policy_id).first() is not None:
                self.remove_policy_in_role(role_id=role_id, policy_id=actual_policy_id)
                self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id)
                return True

        return False

    def replace_policy_role(self, policy_id, actual_role_id, new_role_id):
        if actual_role_id not in admins_id:
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

with PoliciesManager() as pm:
    pm.add_policy('wazuhPolicy', {"administratorPolicy": "total_access"})

with RolesManager() as rm:
    rm.add_role('wazuh', {"administrator": "administrator"})

with RolesPoliciesManager() as rpm:
    rpm.add_policy_to_role_admin(role_id=rm.get_role(name='wazuh').id, policy_id=pm.get_policy(name='wazuhPolicy').id)
