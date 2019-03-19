# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util


class ConfirmationMessage(Model):

    def __init__(self, data: str = ''):
        """ApiResponse body model

        :param data: Error code
        :type data: str
        """
        self.swagger_types = {
            'data': str
        }

        self.attribute_map = {
            'data': 'data'
        }

        self._data = data

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
    def data(self) -> str:
        """
        :return: Error code
        :rtype: str
        """
        return self._data

    @error.setter
    def data(self, data: str):
        """Error code

        :param error: Error code
        """
        self._data = data

