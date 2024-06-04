# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import

from typing import Dict

from api.models.agent_added_model import AgentForce
from api.models.base_model_ import Body


class AgentInsertedModel(Body):

    def __init__(self, id=None, name=None, ip=None, agent_id=None, key=None, force=None):
        """AgentAddedModel body model
        :param id: Agent id.
        :type id: str
        :param name: Agent name.
        :type name: str
        :param ip: If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set the option BehindProxyServer to yes at API configuration. Allowed values: IP, IP/NET, ANY
        :type ip: str
        :param agent_id: Agent ID. All posible values since 000 onwards.
        :type agent_id: str
        :param key: Key to use when communicating with the manager. The agent must have the same key on its `client.keys` file.
        :type key: str
        :param force: Remove the old agent with the same name or IP if conditions are met.
        :type force: dict
        """
        self.swagger_types = {
            'id': str,
            'name': str,
            'ip': str,
            'agent_id': str,
            'key': str,
            'force': AgentForce
        }

        self.attribute_map = {
            'id': str,
            'name': 'name',
            'ip': 'ip',
            'agent_id': 'id',
            'key': 'key',
            'force': 'force'
        }

        self._id = id
        self._name = name
        self._ip = ip
        self._agent_id = agent_id
        self._key = key
        self._force = AgentForce(**force or {}).to_dict()

    @property
    def id(self) -> str:
        """
        :return: Agent id
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        :param id: Agent id
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
    def agent_id(self) -> str:
        """
        :return: Agent id
        :rtype: str
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        :param agent_id: Agent id
        """
        self._agent_id = agent_id

    @property
    def key(self) -> str:
        """
        :return: Agent key
        :rtype: srt
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        :param key: Agent key.
        """
        self._key = key

    @property
    def force(self) -> Dict:
        """
        :return: Limit time to disconnect an agent with the same IP.
        :rtype: dict
        """
        return self._force

    @force.setter
    def force(self, force):
        """Limit time to disconnect an agent with the same IP.
        :param force: Remove the old agent with the same name or IP if conditions are met.
        """
        self._force = force
