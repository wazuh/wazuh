# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class ConfirmationMessage(Model):

    def __init__(self, data: str = ''):
        """ApiResponse body model

        :param data: Message to return
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
        :return: Message to return
        :rtype: str
        """
        return self._data

    @data.setter
    def data(self, data: str):
        """Message to return

        :param data: Message to return
        """
        self._data = data

