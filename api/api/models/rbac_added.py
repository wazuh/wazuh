# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class RoleAdded(Model):

    def __init__(self, name='', policies=list(), rule=''):
        """RoleAdded body model
        :param name: Role name.
        :type name: str
        :param rule: Rule of the role
        :type rule: str
        :param rule: List of policies
        :type rule: list
        """
        self.swagger_types = {
            'name': str,
            'rule': str,
            'policies': List[int]
        }

        self.attribute_map = {
            'name': 'name',
            'rule': 'rule',
            'policies': 'policies'
        }

        self._name = name
        self._rule = rule
        self._policies = policies

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
    def name(self) -> str:
        """
        :return: Role name
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        :param name: Role name
        """
        self._name = name

    @property
    def rule(self) -> str:
        """
        :return: Rule of the role
        :rtype: srt
        """
        return self._rule

    @rule.setter
    def rule(self, rule):
        """
        :param rule: Rule of the role
        """
        self._rule = rule

    @property
    def policies(self) -> list:
        """
        :return: List of policies
        :rtype: list
        """
        return self._policies

    @policies.setter
    def policies(self, policies):
        """
        :param policies: List of policies
        """
        self._policies = policies
