# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class RulesFiles(Model):

    def __init__(self, file: str=None, path: str=None, status: str=None):
        """Rules body model
        :param : 
        :type : str
        :param :
        :type : str
        :param : 
        :type : str
        :param :
        :type : str
        """
        self.swagger_types = {
            'file': str,
            'path': str,
            'status': str
        }

        self.attribute_map = {
            'file': 'file',
            'path': 'path',
            'status': 'status'
        }

        self._file = file
        self._path = path
        self._status = status

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
    def file(self) -> str:
        """
        :return: 
        :rtype: str
        """
        return self._file

    @file.setter
    def file(self, file: str):
        """
        :param file:
        """
        self._file = file

    @property
    def path(self) -> str:
        """
        :return:
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path: str):
        """
        :param path:
        """
        self._path = path

    @property
    def status(self) -> str:
        """
        :return: 
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status: str):
        """
        :param status:
        """
        self._status = status

