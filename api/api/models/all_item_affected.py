# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.item_affected import ItemsAffected
from api import util


class AllItemsAffected(Model):

    def __init__(self, item_affected: ItemsAffected=None, older_than: str=None, total_affected_items: int=None, total_failed_items: int=None):
        """AllItemsAffected body model
        :param item_affected: The item_affected of this AllItemsAffected.
        :type item_affected: ItemsAffected
        :param older_than: Returns older than parameter used. It can be the default value or the parameter send by the user.
        :type older_than: str
        :param total_affected_items: Number of items that have successfully did the requested operation.  # noqa: E501
        :type total_affected_items: int
        :param total_failed_items: Number of items that couldn't do the requested operation. Only returned when it's higher than 0.  # noqa: E501
        :type total_failed_items: int
        """
        self.swagger_types = {
            'item_affected': ItemsAffected,
            'older_than': str,
            'total_affected_items': int,
            'total_failed_items': int
        }

        self.attribute_map = {
            'item_affected': item_affected,
            'older_than': older_than,
            'total_affected_items': total_affected_items,
            'total_failed_items': total_failed_items
        }

        self._item_affected = item_affected
        self._older_than = older_than
        self._total_affected_items = total_affected_items
        self._total_failed_items = total_failed_items

    @classmethod
    def from_dict(cls, dikt) -> AllItemsAffected:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The AllItemsAffected of this AllItemsAffected.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def item_affected(self) -> ItemsAffected:
        """
        :return: The item_affected of this AllItemsAffected
        :rtype: ItemsAffected
        """
        return self._item_affected

    @item_affected.setter
    def item_affected(self, item_affected):
        """
        :param item_affected: The item_affected of this AllItemsAffected.
        """
        self._item_affected = item_affected

    @property
    def older_than(self) -> str:
        """
        :return: The older_than of this AllItemsAffected
        :rtype: str
        """
        return self._older_than

    @older_than.setter
    def older_than(self, older_than):
        """
        :param older_than: The older_than of this AllItemsAffected.
        """
        self._older_than = older_than

    @property
    def total_affected_items(self) -> int:
        """
        :return: The total_affected_items of this AllItemsAffected.
        :rtype: int
        """
        return self._total_affected_items

    @total_affected_items.setter
    def total_affected_items(self, total_affected_items):
        """
        :param total_affected_items: The total_affected_items of this AllItemsAffected.
        """
        self._total_affected_items = total_affected_items

    @property
    def total_failed_items(self) -> int:
        """
        :return: The total_failed_items of this AllItemsAffected.
        :rtype: int
        """
        return self._total_failed_items

    @total_failed_items.setter
    def total_failed_items(self, total_failed_items):
        """
        :param total_failed_items: The total_failed_items of this AllItemsAffected.
        """
        self._total_failed_items = total_failed_items