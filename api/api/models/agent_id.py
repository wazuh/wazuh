# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class AgentId(Model):

    def __init__(self, id: str=None):
        """AgentId body model
        :param id: The id of this AgentKey
        :type id: str
        """
        self.swagger_types = {
            'id': str
        }

        self.attribute_map = {
            'id': 'id'
        }

        self._id = id

    @classmethod
    def from_dict(cls, dikt) -> AgentId:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AgentId of this AgentId.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def id(self) -> str:
        """
        :return: The id of this AgentId
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        :param id: The id of this AgentId.
        """
        self._id = id