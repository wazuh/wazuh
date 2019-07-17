# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_id import AgentId
from api import util


class AgentIdKey(Model):

    def __init__(self, id: AgentId=None, key: str=None):
        """AgentIdKey body model
        :param id: The AgentId of this AgentIdKey
        :type id: AgentId
        :param key: The key of this AgentIdKey.  # noqa: E501
        :type key: str
        """
        self.swagger_types = {
            'id': AgentId,
            'key': str
        }

        self.attribute_map = {
            'id': 'id',
            'key': 'key'
        }

        self._id = id
        self._key = key

    @classmethod
    def from_dict(cls, dikt) -> AgentIdKey:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AgentIdKey of this AgentIdKey.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def id(self) -> AgentId:
        """
        :return: The id of this AgentIdKey
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        :param id: The id of this AgentIdKey.
        """
        self._id = id

    @property
    def key(self) -> str:
        """
        :return: The key of this AgentIdKey.
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        :param key: The key of this AgentIdKey.
        """
        self._key = key