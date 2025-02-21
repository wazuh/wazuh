# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import Dict, List  # noqa: F401

from connexion import ProblemException

from server_management_api.models.base_model_ import Body, Model

KEY_LENGTH = 32


class OS(Model):
    """Agent OS model."""

    def __init__(self, name: str = None, type: str = None, version: str = None):
        self.swagger_types = {'name': str, 'type': str, 'version': str}

        self.attribute_map = {'name': 'name', 'type': 'type', 'version': 'version'}

        self._name = name
        self._type = type
        self._version = version

    @property
    def name(self) -> str:
        """Get OS name.

        Returns
        -------
        str
            OS name.
        """
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def type(self) -> str:
        """Get OS type.

        Returns
        -------
        str
            OS type.
        """
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type

    @property
    def version(self) -> str:
        """Get OS version.

        Returns
        -------
        str
            OS version.
        """
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
        """Get host architecture.

        Returns
        -------
        str
            Host architecture.
        """
        return self._architecture

    @architecture.setter
    def architecture(self, architecture: str):
        self._architecture = architecture

    @property
    def hostname(self) -> str:
        """Get host name.

        Returns
        -------
        str
            Host name.
        """
        return self._hostname

    @hostname.setter
    def hostname(self, hostname: str):
        self._hostname = hostname

    @property
    def ip(self) -> List[str]:
        """Get host IP addresses.

        Returns
        -------
        List[str]
            Host IPs.
        """
        return self._ip

    @ip.setter
    def ip(self, ip: List[str]):
        self._ip = ip

    @property
    def os(self) -> OS:
        """Get host operating system.

        Returns
        -------
        OS
            Host OS.
        """
        return self._os

    @os.setter
    def os(self, os: OS):
        self._os = os


class AgentEnrollmentModel(Body):
    """Agent enrollment model."""

    def __init__(
        self,
        id: str = None,
        name: str = None,
        key: str = None,
        type: str = None,
        version: str = None,
        host: Host = None,
    ):
        self.swagger_types = {
            'id': str,
            'name': str,
            'key': str,
            'type': str,
            'version': str,
            'host': Host,
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'key': 'key',
            'type': 'type',
            'version': 'version',
            'host': 'host',
        }

        self._id = id
        self._name = name
        self._key = key
        self._type = type
        self._version = version
        self._host = host

    @property
    def id(self) -> str:
        """Get agent ID.

        Returns
        -------
        str
            Agent ID.
        """
        return self._id

    @id.setter
    def id(self, id: str):
        self._id = id

    @property
    def name(self) -> str:
        """Get agent name.

        Returns
        -------
        str
            Agent name.
        """
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def key(self) -> str:
        """Get agent key.

        Returns
        -------
        str
            Agent key.
        """
        return self._key

    @key.setter
    def key(self, key: str):
        if len(key) != 32:
            raise ProblemException(status=400, title='Invalid key length', detail='The key must be 32 characters long')
        self._key = key

    @property
    def type(self) -> str:
        """Get agent type.

        Returns
        -------
        str
            Agent type.
        """
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type

    @property
    def version(self) -> str:
        """Get agent version.

        Returns
        -------
        str
            Agent version.
        """
        return self._version

    @version.setter
    def version(self, version: str):
        self._version = version

    @property
    def host(self) -> Host:
        """Get agent host.

        Returns
        -------
        Host
            Agent host.
        """
        return self._host

    @host.setter
    def host(self, host: Host):
        self._host = host
