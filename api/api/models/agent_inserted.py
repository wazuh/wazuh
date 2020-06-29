# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body


class AgentInsertedModel(Body):

    def __init__(self, id=None, name=None, ip=None, agent_id=None, key=None, force_time=None):
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
        :param force_time: Remove the old agent with the same IP if disconnected since <force_time> seconds.
        :type force_time: int
        """
        self.swagger_types = {
            'id': str,
            'name': str,
            'ip': str,
            'agent_id': str,
            'key': str,
            'force_time': int
        }

        self.attribute_map = {
            'id': str,
            'name': 'name',
            'ip': 'ip',
            'agent_id': 'id',
            'key': 'key',
            'force_time': 'force_time'
        }

        self._id = id
        self._name = name
        self._ip = ip
        self._agent_id = agent_id
        self._key = key
        self._force_time = force_time

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
