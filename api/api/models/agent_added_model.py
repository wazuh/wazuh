# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body, Model


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

    def __init__(self, name: str = None, ip: str = None):
        self.swagger_types = {
            'name': str,
            'ip': str,
            'force': AgentForce
        }

        self.attribute_map = {
            'name': 'name',
            'ip': 'ip',
            'force': 'force'
        }

        self._name = name
        self._ip = ip
        self._force = AgentForce(enabled=False)

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
    def ip(self) -> str:
        """
        :return: Agent IP value
        :rtype: srt
        """
        return self._ip

    @ip.setter
    def ip(self, ip):
        """
        :param ip: Agent IP.
        """
        self._ip = ip

    @property
    def force(self):
        return self._force

    @force.setter
    def force(self, force):
        self._force = force
