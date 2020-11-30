# coding: utf-8

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body


class AgentAddedModel(Body):

    def __init__(self, name: str = None, ip: str = None, force_time: int = None):
        """AgentAddedModel body model
        :param name: Agent name.
        :type name: str
        :param ip: If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set the option BehindProxyServer to yes at API configuration. Allowed values: IP, IP/NET, ANY
        :type ip: str
        :param force_time: Remove the old agent with the same IP if disconnected since <force_time> seconds.
        :type force_time: int
        """
        self.swagger_types = {
            'name': str,
            'ip': str,
            'force_time': int
        }

        self.attribute_map = {
            'name': 'name',
            'ip': 'ip',
            'force_time': 'force_time'
        }

        self._name = name
        self._ip = ip
        self._force_time = force_time

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
    def force_time(self) -> int:
        """
        :return: Limit time to disconnect an agent with the same IP.
        :rtype: int
        """
        return self._force_time

    @force_time.setter
    def force_time(self, force_time):
        """Limit time to disconnect an agent with the same IP.
        :param force_time: Agents limit disconnection time. 
        """
        self._force_time = force_time
