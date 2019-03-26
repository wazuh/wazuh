# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class AgentList(Model):

    def __init__(self, agent_id: List[str]=None):
        """AgentList body model
        :param agent_id: List of agents ID.
        :type agent_id: List[str]
        """
        self.swagger_types = {
            'agent_id': List[str]
        }

        self.attribute_map = {
            'agent_id': 'agent_id'
        }

        self._agent_id = agent_id

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
    def agent_id(self) -> List[str]:
        """
        :return: List of agents ID
        :rtype: List[str]
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        :param agent_id: List of agents ID
        """
        self._agent_id = agent_id