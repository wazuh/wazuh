# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import Dict, List  # noqa: F401

from server_management_api.models.base_model_ import Body


class GroupAddedModel(Body):
    def __init__(self, group_id: str = None):
        """GroupAddedModel body model.

        Parameters
        ----------
        group_id : str
            Group name.
        """
        self.swagger_types = {
            'group_id': str,
        }

        self.attribute_map = {
            'group_id': 'group_id',
        }

        self._group_id = group_id

    @property
    def group_id(self) -> str:
        """Group name getter.

        Returns
        -------
        group_id : str
            Group name.
        """
        return self._group_id

    @group_id.setter
    def group_id(self, group_id):
        """Group name setter.

        Parameters
        ----------
        group_id : str
            Group name.
        """
        self._group_id = group_id
