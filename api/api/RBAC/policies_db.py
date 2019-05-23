#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from api.constants import SECURITY_PATH
import logging


logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

app = Flask('RBAC')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
_db_path = f'sqlite:///' + os.path.join(SECURITY_PATH, 'RBAC.db')
app.config['SQLALCHEMY_DATABASE_URI'] = _db_path

db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)


########################################################################
class Policies(db.Model):
    """"""
    __tablename__ = "policies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    policy = db.Column(db.String, unique=True)

    # ----------------------------------------------------------------------
    def __init__(self, name, policy):
        """"""
        self.name = name
        self.policy = policy


class Rules(db.Model):
    """"""
    __tablename__ = "rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    rule = db.Column(db.String, unique=True)

    # ----------------------------------------------------------------------
    def __init__(self, name, rule):
        """"""
        self.name = name
        self.rule = rule


if __name__ == '__main__':
    manager.run()
