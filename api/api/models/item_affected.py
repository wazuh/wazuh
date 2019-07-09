# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class ItemsAffected(Model):

    def __init__(self, msg: str=None, affected_items: List[str]=None, failed_items: List[str]=None):
        """ItemsAffected body model
        :param msg: Confirmation message.
        :type msg: str
        :param affected_items: Items that successfully applied the API call action.  # noqa: E501
        :type affected_items: List[str]
        :param failed_items: List of items that have failed when doing the requested operation. It's not returned when it's empty.  # noqa: E501
        :type failed_items: List[str]
        """
        self.swagger_types = {
            'msg': str,
            'affected_items': List[str],
            'failed_items': List[str]
        }

        self.attribute_map = {
            'msg': msg,
            'affected_items': affected_items,
            'failed_items': failed_items
        }

        self._msg = msg
        self._affected_items = affected_items
        self._failed_items = failed_items

    @classmethod
    def from_dict(cls, dikt) -> ItemsAffected:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The ItemsAffected of this ItemsAffected.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def msg(self) -> str:
        """
        :return: The msg of this ItemsAffected
        :rtype: str
        """
        return self._msg

    @msg.setter
    def msg(self, msg):
        """
        :param msg: The msg of this ItemsAffected.
        """
        self._msg = msg

    @property
    def affected_items(self) -> List[str]:
        """
        :return: The affected_items of this ItemsAffected.
        :rtype: List[str]
        """
        return self._affected_items

    @affected_items.setter
    def affected_items(self, affected_items):
        """
        :param affected_items: The affected_items of this ItemsAffected.
        """
        self._affected_items = affected_items

    @property
    def failed_items(self) -> List[str]:
        """
        :return: The failed_items of this ItemsAffected.
        :rtype: List[str]
        """
        return self._failed_items

    @failed_items.setter
    def failed_items(self, failed_items):
        """
        :param failed_items: The failed_items of this ItemsAffected.
        """
        self._failed_items = failed_items