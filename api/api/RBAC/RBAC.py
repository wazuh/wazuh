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
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from api.constants import SECURITY_PATH
# from sqlalchemy.ext.declarative import declarative_base
# from shutil import chown
# from datetime import datetime


app = Flask(__name__)
_rbac_db_file = os.path.join(SECURITY_PATH, 'RBAC.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + _rbac_db_file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
Migrate(app, db)

_engine = create_engine(f'sqlite:///' + os.path.join(SECURITY_PATH, 'RBAC.db'), echo=False)
# _Base = declarative_base()
_Session = sessionmaker(bind=_engine)


roles_policies_table = db.Table('roles_policies',
                                db.Column('role_id', db.ForeignKey("roles.id", ondelete='CASCADE', onupdate="CASCADE"),
                                          nullable=False),
                                db.Column('policy_id', db.ForeignKey("policies.id", ondelete='CASCADE',
                                                                     onupdate="CASCADE"),
                                          nullable=False),
                                UniqueConstraint('role_id', 'policy_id', name='role_policy_pair')
                                )


class Policies(db.Model):
    """"""
    __tablename__ = "policies"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    policy = db.Column('policy', db.String)
    # created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow, onpudate=datetime.utcnow)
    __table_args__ = (UniqueConstraint('name', 'policy', name='name_policy'),
                      )

    # Relations
    roles = db.relationship("Roles", secondary=roles_policies_table,
                            backref=db.backref("policiess", cascade="all,delete", order_by=id, uselist=False), lazy='dynamic')

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy
        # self.created_at = datetime.utcnow
        # self.updated_at = datetime.utcnow


class Roles(db.Model):
    """"""
    __tablename__ = "roles"

    # Schema
    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    role = db.Column('role', db.String)
    # created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow, onpudate=datetime.utcnow)
    __table_args__ = (UniqueConstraint('name', 'role', name='name_role'),
                      )

    # Relations
    policies = db.relationship("Policies", secondary=roles_policies_table,
                               backref=db.backref("roless", cascade="all,delete", order_by=id, uselist=False), lazy='dynamic')

    def __init__(self, name, role):
        self.name = name
        self.role = role
        # self.created_at = datetime.utcnow
        # self.updated_at = datetime.utcnow


# # This is the actual sqlite database creation
# _Base.metadata.create_all(_engine)
# # Only if executing as root
# try:
#     chown(_rbac_db_file, 'ossec', 'ossec')
# except PermissionError:
#     pass
# os.chmod(_rbac_db_file, 0o640)
# _Session = sessionmaker(bind=_engine)


class RolesManager:
    def get_role(self, name):
        try:
            role = self.session.query(Roles).filter_by(name=name).first()
            return role
        except IntegrityError:
            return False

    def get_roles(self):
        try:
            roles = self.session.query(Roles).all()
            return roles
        except IntegrityError:
            return False

    def add_role(self, name, role):
        try:
            self.session.add(Roles(name=name, role=role))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_role(self, role_id):
        try:
            self.session.query(Roles).filter_by(id=role_id).delete()
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def update_role(self, id, name=None, role=None):
        try:
            role_to_update = self.session.query(Roles).filter_by(id=id).first()
            if name is not None:
                role_to_update.name = name
            if role is not None:
                role_to_update.role = role
            self.session.commit()
            return True
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

    def get_policies(self):
        try:
            policies = self.session.query(Policies).all()
            return policies
        except IntegrityError:
            return False

    def add_policy(self, name, policy):
        try:
            self.session.add(Policies(name=name, policy=policy))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy(self, policy_id):
        try:
            self.session.query(Policies).filter_by(id=policy_id).delete()
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def delete_policy_by_name(self, policy_name):
        try:
            self.session.query(Policies).filter_by(name=policy_name).delete()
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def update_policy(self, policy_id, new_name, role_definition):
        try:
            role_to_update = self.session.query(Roles).filter_by(id=policy_id)
            role_to_update.name = new_name
            role_to_update.role = role_definition
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class RolesPoliciesManager:
    def add_policy_to_role(self, role_id, policy_id):
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            role.policies.append(self.session.query(Policies).filter_by(id=policy_id).first())
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def add_role_to_policy(self, policy_id, role_id):
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            policy.roles.append(self.session.query(Roles).filter_by(id=role_id).first())
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def get_all_policies_from_role(self, role_id):
        try:
            role = self.session.query(Roles).filter_by(id=role_id).first()
            policies = role.policies
            for policy in policies:
                print('Role id: {} Policy id: {}'.format(role.id, policy.id))
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def get_all_roles_from_policy(self, policy_id):
        try:
            policy = self.session.query(Policies).filter_by(id=policy_id).first()
            roles = policy.roles
            for role in roles:
                print('Role id: {} Policy id: {}'.format(role.id, policy.id))
            return True
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

    def remove_policy_in_role(self, role_id, policy_id):
        try:
            role = self.session.query(Roles).get(role_id)
            policy = self.session.query(Policies).get(policy_id)
            role.policies.remove(policy)
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            return False

    def remove_all_policies_in_role(self, role_id):
        try:
            policies = self.session.query(Roles).filter_by(id=role_id).first().policies
            for policy in policies:
                self.remove_policy_in_role(role_id=role_id, policy_id=policy.id)
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def replace_role_policy(self, role_id, actual_policy_id, new_policy_id):
        if self.exist_role_policy(role_id=role_id, policy_id=actual_policy_id) and \
                self.session.query(Policies).filter_by(id=new_policy_id).first() is not None:
            self.remove_policy_in_role(role_id=role_id, policy_id=actual_policy_id)
            self.add_policy_to_role(role_id=role_id, policy_id=new_policy_id)
            return True

        return False

    def replace_policy_role(self, policy_id, actual_role_id, new_role_id):
        if self.exist_role_policy(role_id=actual_role_id, policy_id=policy_id) and \
                self.session.query(Policies).filter_by(id=new_role_id).first() is not None:
            self.remove_policy_in_role(role_id=actual_role_id, policy_id=policy_id)
            self.add_policy_to_role(role_id=new_role_id, policy_id=policy_id)
            return True

        return False

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


if __name__ == '__main__':
    app.run(APP='RBAC')