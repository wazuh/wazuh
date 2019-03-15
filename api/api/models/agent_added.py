# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util


class AgentAdded(Model):

    def __init__(self, name='', ip='any', force_time=-1):
        """AgentAdded body model
        :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of a command name
        :type command: str
        :param custom: Whether the specified command is a custom command or not
        :type custom: bool
        :param arguments: Command arguments
        :type arguments: str
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

    @classmethod
    def from_dict(cls, dikt) -> Dict:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The Agent of this Agent.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

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
        :param force_time_time: Agents limit disconnection time. 
        """
        self._force_time = force_time