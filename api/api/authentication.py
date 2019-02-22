# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
from datetime import datetime
from shutil import chown

from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from wazuh.common import ossec_path
from werkzeug.security import check_password_hash, generate_password_hash

# Set authentication database
_auth_db_file = os.path.join(ossec_path, 'api', 'users.db')
_engine = create_engine(f'sqlite://{_auth_db_file}', echo=False)
_Base = declarative_base()


# Declare tables
class _User(_Base):
    __tablename__ = 'users'

    username = Column(String(32), primary_key=True)
    password = Column(String(256))

    def __repr__(self):
       return f"<User(user={self.user})"


class _Token(_Base):
    __tablename__ = 'tokens'

    token = Column(String(512), primary_key=True)
    issued_date = Column(DateTime)
    expiry_date = Column(DateTime)


# This is the actual sqlite database creation
_Base.metadata.create_all(_engine)
chown(_auth_db_file, 'root', 'ossec')
Session = sessionmaker(bind=_engine)


class AuthenticationManager:

    def add_user(self, username, password):
        try:
            self.session.add(_User(username=username, password=generate_password_hash(password)))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def check_user(self, username, password):
        user = self.session.query(_User).filter_by(username=username).first()
        return check_password_hash(user.password, password) if user else False

    def check_token(self, token):
        db_token = self.session.query(_Token).filter_by(token=token).filter(_Token.expiry_date < datetime.now()).first()
        return db_token is not None

    def __enter__(self):
        self.session = Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


# Create default users if they don't exist yet
with AuthenticationManager() as auth:
    auth.add_user('wazuh-app', 'wazuh-app')
    auth.add_user('wazuh', 'wazuh')


def check_user(user, password, required_scopes=None):
    with AuthenticationManager() as auth:
        if auth.check_user(user, password):
            return {'sub': 'foo',
                    'active': True
                    }

    return None


def check_token(token, required_scopes=None):
    if token == 'blablablablabla':
        return {'active': True
                }
    return None
