# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.api_response import ApiResponse
from api.models.agent_is_sync import AgentIsSync
from api import util


class AgentSync(Model):

    def __init__(self, api_response: ApiResponse=None, data=''):
        """AgentSync body model
        :param api_response: The ApiResponse of this AgentSync
        :type data: ApiResponse
        :param data: The data of this AgentSync.  # noqa: E501
        :type data: AgentIsSync
        """
        self.swagger_types = {
            'api_response': ApiResponse,
            'data': AgentIsSync
        }

        self.attribute_map = {
            'api_response': 'api_response',
            'data': 'data'
        }

        self._api_response = api_response
        self._data = data

    @classmethod
    def from_dict(cls, dikt) -> AgentSync:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AgentSync of this AgentSync.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def api_response(self) -> ApiResponse:
        """
        :return: The api_response of this AgentSync
        :rtype: int
        """
        return self._api_response

    @api_response.setter
    def api_response(self, api_response):
        """
        :param api_response: The api_response of this AgentSync.
        """
        self._api_response = api_response

    @property
    def data(self) -> AgentIsSync:
        """
        :return: The data of this AgentSync.
        :rtype: AgentIsSync
        """
        return self._data

    @data.setter
    def data(self, data):
        """
        :param data: The data of this AgentSync.
        """
        self._data = data