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


class OS(Model):
    """Agent OS model."""

    def __init__(self, name: str = None, type: str = None, version: str = None):
        self.swagger_types = {
            'name': str,
            'type': str,
            'version': str
        }

        self.attribute_map = {
            'name': 'name',
            'type': 'type',
            'version': 'version'
        }

        self._name = name
        self._type = type
        self._version = version

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type
        
    @property
    def version(self) -> str:
        return self._version

    @version.setter
    def version(self, version: str):
        self._version = version


class Host(Model):
    """Agent host model."""

    def __init__(self, architecture: str = None, hostname: str = None, ip: List[str] = None, os: OS = None):
        self.swagger_types = {
            'architecture': str,
            'hostname': str,
            'ip': List[str],
            'os': OS,
        }

        self.attribute_map = {
            'architecture': 'architecture',
            'hostname': 'hostname',
            'ip': 'ip',
            'os': 'os',
        }

        self._architecture = architecture
        self._hostname = hostname
        self._ip = ip
        self._os = os

    @property
    def architecture(self) -> str:
        return self._architecture

    @architecture.setter
    def architecture(self, architecture: str):
        self._architecture = architecture

    @property
    def hostname(self) -> str:
        return self._hostname

    @hostname.setter
    def hostname(self, hostname: str):
        self._hostname = hostname

    @property
    def ip(self) -> List[str]:
        return self._ip

    @ip.setter
    def ip(self, ip: List[str]):
        self._ip = ip
    
    @property
    def os(self) -> OS:
        return self._os

    @os.setter
    def os(self, os: OS):
        self._os = os


class AgentRegistrationModel(Body):
    """Agent registration model."""

    def __init__(
        self,
        id: str = None,
        name: str = None,
        key: str = None,
        type: str = None,
        version: str = None,
        groups: List[str] = None,
        host: Host = None,
    ):
        self.swagger_types = {
            'id': str,
            'name': str,
            'key': str,
            'type': str,
            'version': str,
            'groups': List[str],
            'host': Host,
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'key': 'key',
            'type': 'type',
            'version': 'version',
            'groups': 'groups',
            'host': 'host',
        }

        self._id = id
        self._name = name
        self._key = key
        self._type = type
        self._version = version
        self._groups = groups
        self._host = host

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, id: str):
        self._id = id

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def key(self) -> str:
        return self._key

    @key.setter
    def key(self, key: str):
        if len(key) != 32:
            raise ProblemException(status=400, title='Invalid key length', detail='The key must be 32 characters long')
        self._key = key
    
    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type

    @property
    def version(self) -> str:
        return self._version

    @version.setter
    def version(self, version: str):
        self._version = version
    
    @property
    def groups(self) -> List[str]:
        return self._groups

    @groups.setter
    def groups(self, groups: List[str]):
        self._groups = groups

    @property
    def host(self) -> Host:
        return self._host

    @host.setter
    def host(self, host: Host):
        self._host = host
