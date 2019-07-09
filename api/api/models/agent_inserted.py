# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime

from typing import List, Dict

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util

#from __future__ import absolute_import
#from datetime import date, datetime  # noqa: F401

#from typing import List, Dict  # noqa: F401

#from api.models.base_model_ import Model
#from api import util


class AgentInserted(Model):

    def __init__(self, name='', ip=None, id='', key='', force_time=-1):
        """AgentAdded body model
        :param name: Agent name.
        :type name: str
        :param ip: If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set the option BehindProxyServer to yes at API configuration. Allowed values: IP, IP/NET, ANY
        :type ip: str
        :param id: Agent ID. All posible values since 000 onwards.
        :type id: str
        :param key: Key to use when communicating with the manager. The agent must have the same key on its `client.keys` file.
        :type key: str
        :param force_time: Remove the old agent with the same IP if disconnected since <force_time> seconds.
        :type force_time: int
        """
        self.swagger_types = {
            'name': str,
            'ip': str,
            'id': str,
            'key': str,
            'force_time': int
        }

        self.attribute_map = {
            'name': 'name',
            'ip': 'ip',
            'id': 'id',
            'key': 'key',
            'force_time': 'force_time'
        }

        self._name = name
        self._ip = ip
        self._id = id
        self._key = key
        self._force_time = force_time

    @classmethod
    def from_dict(cls, dikt) -> 'AgentInserted':
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