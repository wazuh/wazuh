# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401
from typing import Dict, List  # noqa: F401

from connexion import ProblemException

from api.models.base_model_ import Body, Model

KEY_LENGTH = 32


class DisconnectedTime(Model):
    def __init__(self, enabled=True, value="1h"):
        self.swagger_types = {
            'enabled': bool,
            'value': str
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'value': 'value'
        }

        self._enabled = enabled
        self._value = value

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class AgentForce(Model):
    def __init__(self, enabled=True, disconnected_time=None, after_registration_time="1h"):
        self.swagger_types = {
            'enabled': bool,
            'disconnected_time': DisconnectedTime,
            'after_registration_time': str
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'disconnected_time': 'disconnected_time',
            'after_registration_time': 'after_registration_time'
        }

        self._enabled = enabled
        self._disconnected_time = DisconnectedTime(**disconnected_time or {}).to_dict()
        self._after_registration_time = after_registration_time

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def disconnected_time(self):
        return self._disconnected_time

    @disconnected_time.setter
    def disconnected_time(self, disconnected_time):
        self._disconnected_time = disconnected_time

    @property
    def after_registration_time(self):
        return self._after_registration_time

    @after_registration_time.setter
    def after_registration_time(self, after_registration_time):
        self._after_registration_time = after_registration_time


class AgentAddedModel(Body):

    def __init__(
        self,
        id: str = None,
        name: str = None,
        key: str = None,
        groups: str = None,
        ips: str = None,
        os: str = None,
    ):
        self.swagger_types = {
            'id': str,
            'name': str,
            'key': str,
            'groups': str,
            'ips': str,
            'os': str,
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'key': 'key',
            'groups': 'groups',
            'ips': 'ips',
            'os': 'os'
        }

        self._name = name
        self._id = id
        self._key = key
        self._groups = groups
        self._ips = ips
        self._os = os

    @property
    def id(self) -> str:
        """
        :return: Agent id value
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        :param id: Agent id.
        """
        self._id = id

    @property
    def name(self) -> str:
        """
        :return: Agent name
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        :param name: Agent name
        """
        self._name = name

    @property
    def key(self):
        """
        :return: Agent key
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        :param key: Agent key
        """
        if len(key) != 32:
            raise ProblemException(status=400, title='Invalid key length', detail='The key must be 32 characters long')
        self._key = key
    
    @property
    def groups(self):
        """
        :return: Agent groups
        :rtype: str
        """
        return self._groups

    @groups.setter
    def groups(self, groups):
        """
        :param groups: Agent groups
        """
        self._groups = groups

    @property
    def ips(self):
        """
        :return: Agent IP addresses
        :rtype: str
        """
        return self._ips

    @ips.setter
    def ips(self, ips):
        """
        :param ip: Agent IP addresses
        """
        self._ips = ips

    @property
    def os(self):
        """
        :return: Agent operating system
        :rtype: str
        """
        return self._os

    @os.setter
    def os(self, os):
        """
        :param os: Agent operating system
        """
        self._os = os
