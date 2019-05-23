#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from api.constants import SECURITY_PATH
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(SECURITY_PATH, 'RBAC.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
Migrate(app, db)


class Policies(db.Model):
    """"""
    __tablename__ = "policies"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    policy = db.Column('policy', db.String)
    # created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow, onpudate=datetime.utcnow)

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy
        # self.created_at = datetime.utcnow
        # self.updated_at = datetime.utcnow


class Roles(db.Model):
    """"""
    __tablename__ = "roles"

    id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column('name', db.String(20))
    role = db.Column('role', db.String)
    # created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow, onpudate=datetime.utcnow)

    def __init__(self, name, role):
        self.name = name
        self.role = role


class Roles_Policies(db.Model):
    """"""
    __tablename__ = "roles_policies"

    role_id = db.Column('role_id', db.Integer, db.ForeignKey("roles.id"), primary_key=True, nullable=False)
    policy_id = db.Column('policy_id', db.Integer, db.ForeignKey("policies.id"), primary_key=True, nullable=False)
    # created_at = db.Column('created_at', db.DateTime, default=datetime.utcnow)
    # updated_at = db.Column('updated_at', db.DateTime, default=datetime.utcnow, onpudate=datetime.utcnow)

    def __init__(self, role_id, policy_id):
        self.role_id = role_id
        self.policy_id = policy_id


if __name__ == '__main__':
    app.run(APP='RBAC')