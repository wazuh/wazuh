# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class AgentList(Model):

    def __init__(self, ids: List[str]=None):
        """AgentList body model
        :param ids: List of agents ID.
        :type ids: List[str]
        """
        self.swagger_types = {
            'ids': List[str]
        }

        self.attribute_map = {
            'ids': 'ids'
        }

        self._ids = ids

    @classmethod
    def from_dict(cls, dikt) -> 'AgentList':
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The AgentList of this AgentList.  # noqa: E501
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def ids(self) -> List[str]:
        """
        :return: List of agents ID
        :rtype: List[str]
        """
        return self._ids

    @ids.setter
    def ids(self, ids):
        """
        :param ids: List of agents ID
        """
        self._ids = ids