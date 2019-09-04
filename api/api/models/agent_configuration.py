# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.api_response import ApiResponse
from api import util


class AgentConfigurationData(Model):

    def __init__(self, api_response: ApiResponse=None, data=''):
        """AgentConfigurationData body model
        :param api_response: The ApiResponse of this AgentConfigurationData
        :type data: ApiResponse
        :param data: The data of this AgentConfigurationData.  # noqa: E501
        :type data: object
        """
        self.swagger_types = {
            'api_response': ApiResponse,
            'data': object
        }

        self.attribute_map = {
            'api_response': 'api_response',
            'data': 'data'
        }

        self._api_response = api_response
        self._data = data

    @classmethod
    def from_dict(cls, dikt) -> AgentConfigurationData:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AgentConfigurationData of this AgentConfigurationData.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def api_response(self) -> ApiResponse:
        """
        :return: The api_response of this AgentConfigurationData
        :rtype: int
        """
        return self._api_response

    @api_response.setter
    def api_response(self, api_response):
        """
        :param api_response: The api_response of this AgentConfigurationData.
        """
        self._api_response = api_response

    @property
    def data(self) -> object:
        """
        :return: The data of this AgentConfigurationData.
        :rtype: object
        """
        return self._data

    @data.setter
    def data(self, data):
        """
        :param data: The data of this AgentConfigurationData.
        """
        self._data = data