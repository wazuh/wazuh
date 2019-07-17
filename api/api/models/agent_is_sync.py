# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class AgentIsSync(Model):

    def __init__(self, synced):
        """AgentIsSync body model
        :param synced: The synced of this AgentIsSync.  # noqa: E501
        :type synced: bool
        """
        self.swagger_types = {
            'synced': bool
        }

        self.attribute_map = {
            'synced': 'synced'
        }

        self._synced = synced

    @classmethod
    def from_dict(cls, dikt) -> AgentIsSync:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AgentIsSync of this AgentIsSync.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def synced(self) -> bool:
        """
        :return: The synced of this AgentIsSync
        :rtype: bool
        """
        return self._synced

    @synced.setter
    def synced(self, synced):
        """
        :param synced: The synced of this AgentIsSync.
        """
        self._synced = synced