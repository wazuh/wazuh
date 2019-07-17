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

        self.all_of = [api_response, confirmation_message]
		self.all_of_model = [APIResponse,ConfirmationMessage]

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
        return self.all_of[0]

    @api_response.setter
    def api_response(self, api_response: ApiResponse):
        """Setter for api_response variable

        :param api_response: API response
        """
        self.all_of[0] = api_response

    @property
    def confirmation_message(self) -> ConfirmationMessage:
        """
        :return: Confirmation message
        :rtype: ConfirmationMessage
        """
        return self.all_of[1]

    @confirmation_message.setter
    def confirmation_message(self, confirmation_message: ConfirmationMessage):
        """Setter for confirmation_message variable

        :param confirmation_message: Confirmation message
        """
        self.all_of[1] = confirmation_message