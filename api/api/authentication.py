# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash


engine = create_engine('sqlite:///:memory:', echo=False)
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    username = Column(String(32), primary_key=True)
    password = Column(String(256))

    def __repr__(self):
       return f"<User(user={self.user})"


class Token(Base):
    __tablename__ = 'tokens'

    token = Column(String(512), primary_key=True)
    issued_date = Column(DateTime)
    expiry_date = Column(DateTime)


Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


def check_user(user, password, required_scopes=None):
    if user == 'foo' and password == 'bar':
        return {'sub': 'foo',
                'active': True
                }

    return None


def check_token(token, required_scopes=None):
    if token == 'blablablablabla':
        return {'active': True
                }
    return None


class Authentication:

    def __init__(self):
        self.session = Session()

    def add_user(self, username, password):
        self.session.add(User(username=username, password=generate_password_hash(password)))

    def check_user(self, username, password):
        user = self.session.query(User).filter_by(username=username).first()
        return check_password_hash(user.password, password)

    def check_token(self, token):
        pass
