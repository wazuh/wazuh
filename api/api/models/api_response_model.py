# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.agent_os import AgentOs  # noqa: F401,E501
from api.models.agent_status import AgentStatus  # noqa: F401,E501
from api import util


class ApiResponse(Model):

    def __init__(self, error: str = '', message: str = ''):
        """ApiResponse body model

        :param error: Error code
        :type command: str
        :param message: Details about error
        :type message: str
        """
        self.swagger_types = {
            'error': str,
            'message': str
        }

        self.attribute_map = {
            'error': 'error',
            'message': 'message'
        }

        self._error = error
        if message:
            self._message = message

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
    def error(self) -> str:
        """
        :return: Error code
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error: str):
        """Error code

        :param error: Error code
        """
        self._error = error

    @property
    def message(self) -> str:
        """
        :return: Details about error
        :rtype: bool
        """
        return self._message

    @message.setter
    def message(self, message: str):
        """
        :param message: Details about error
        """
        self._message = message
