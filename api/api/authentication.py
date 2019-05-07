# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
from secrets import token_urlsafe
from shutil import chown
from time import time

from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, String
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.exceptions import Unauthorized
from werkzeug.security import check_password_hash, generate_password_hash

from api.api_exception import APIException
from api.constants import SECURITY_PATH

# Set authentication database
_auth_db_file = os.path.join(SECURITY_PATH, 'users.db')
_engine = create_engine(f'sqlite:///{_auth_db_file}', echo=False)
_Base = declarative_base()


# Declare tables
class _User(_Base):
    __tablename__ = 'users'

    username = Column(String(32), primary_key=True)
    password = Column(String(256))

    def __repr__(self):
        return f"<User(user={self.user})"


# This is the actual sqlite database creation
_Base.metadata.create_all(_engine)
# Only if executing as root
try:
    chown(_auth_db_file, 'ossec', 'ossec')
except PermissionError:
    pass
os.chmod(_auth_db_file, 0o640)
_Session = sessionmaker(bind=_engine)


class AuthenticationManager:
    """
    Class for dealing with authentication stuff without worrying about database.
    It manages users and token generation.
    """

    def add_user(self, username, password):
        """
        Creates a new user if it does not exist.
        :param username: string Unique user name
        :param password: string Password provided by user. It will be stored hashed
        :return: True if the user has been created successfuly. False otherwise (i.e. already exists)
        """
        try:
            self.session.add(_User(username=username, password=generate_password_hash(password)))
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def check_user(self, username, password):
        """
        Validates a username-password pair.
        :param username: string Unique user name
        :param password: string Password to be checked against the one saved in the database
        :return: True if username and password matches. False otherwise.
        """
        user = self.session.query(_User).filter_by(username=username).first()
        return check_password_hash(user.password, password) if user else False

    def login_user(self, username, password):
        """
        Validates a username-password pair and generates a jwt token
        :param username: string Unique user name
        :param password: string Password to be checked against the one saved in the database
        :return: string jwt encoded token or None if user credentials are rejected
        """
        if self.check_user(username=username, password=password):
            return generate_token(username)
        return None

    def __enter__(self):
        self.session = _Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


# Create default users if they don't exist yet
with AuthenticationManager() as auth:
    auth.add_user('wazuh-app', 'wazuh-app')
    auth.add_user('wazuh', 'wazuh')


def check_user(user, password, required_scopes=None):
    """
    Convenience method to use in openapi specification
    :param user: string Unique username
    :param password: string user password
    :param required_scopes:
    :return:
    """
    with AuthenticationManager() as auth:
        if auth.check_user(user, password):
            return {'sub': 'foo',
                    'active': True
                    }

    return None


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_LIFETIME_SECONDS = 600
JWT_ALGORITHM = 'HS256'


# Generate secret file to keep safe or load existing secret
_secret_file_path = os.path.join(SECURITY_PATH, 'jwt_secret')
try:
    if not os.path.exists(_secret_file_path):
        JWT_SECRET = token_urlsafe(512)
        with open(_secret_file_path, mode='x') as secret_file:
            secret_file.write(JWT_SECRET)
        # Only if executing as root
        try:
            chown(_secret_file_path, 'root', 'ossec')
        except PermissionError:
            pass
        os.chmod(_secret_file_path, 0o640)
    else:
        with open(_secret_file_path, mode='r') as secret_file:
            JWT_SECRET = secret_file.readline()
except IOError as e:
    raise APIException(2002)


def generate_token(user_id):
    """
    Generates an encoded jwt token. This method should be called once a user is properly logged on.
    :param user_id: string Unique user name
    :return: string jwt formatted string
    """
    timestamp = int(time())
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": str(user_id),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token):
    """
    Decodes a jwt formatted token. Raise an Unauthorized exception in case validation fails.
    :param token: string jwt formatted token
    :return: dict payload ot the token
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise Unauthorized from e
