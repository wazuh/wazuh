# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.api_response_model import ApiResponse
from api.models.confirmation_message_model import ConfirmationMessage
from api import util


class ApiResponseData(Model):

    def __init__(self, api_response: ApiResponse = None, confirmation_message: ConfirmationMessage = None):  # noqa: E501
        """ApiResponseData body model

        :param api_response: API response
        :type api_response: ApiResponse
        :param confirmation_message: Confirmation message
        :type confirmation_essage: ConfirmationMessage 
        """
        self.swagger_types = {
            'api_response': ApiResponse,
            'confirmation_message': ConfirmationMessage
        }

        self.attribute_map = {
            'api_response': 'api_response',
            'confirmation_message': 'confirmation_message'
        }

        self._api_response = api_response
        self._confirmation_message = confirmation_message

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
    def api_response(self) -> ApiResponse:
        """
        :return: API response
        :rtype: ApiResponse
        """
        return self._api_response

    @api_response.setter
    def api_response(self, api_response: ApiResponse):
        """Setter for api_response variable

        :param api_response: API response
        """
        self._api_response = api_response

    @property
    def confirmation_message(self) -> ConfirmationMessage:
        """
        :return: Confirmation message
        :rtype: ConfirmationMessage
        """
        return self._confirmation_message

    @confirmation_message.setter
    def confirmation_message(self, confirmation_message: ConfirmationMessage):
        """Setter for confirmation_message variable

        :param confirmation_message: Confirmation message
        """
        self._confirmation_message = confirmation_message

