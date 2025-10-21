# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict  # noqa: F401

from api.models.base_model_ import Body


class KVDBModel(Body):
    """Body model for KVDBs."""

    def __init__(self, id: str = None, name: str = None, type: str = None,
                 content: Dict = None, integration_id: str = None):
        self.swagger_types = {
            'type': str,
            'id': str,
            'name': str,
            'content': dict,
            'integration_id': str
        }
        self.attribute_map = {
            'type': 'type',
            'id': 'id',
            'name': 'name',
            'content': 'content',
            'integration_id': 'integration_id'
        }
        self._type = type
        self._id = id
        self._name = name
        self._content = content
        self._integration_id = integration_id

    @property
    def type(self):
        """Policy type."""
        return self._type

    @type.setter
    def type(self, type):
        self._type = type

    @property
    def id(self) -> str:
        """KVDB identifier."""
        return self._id

    @id.setter
    def id(self, value: str):
        self._id = value

    @property
    def name(self) -> str:
        """Human-friendly display name."""
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def content(self) -> Dict:
        """KVDB map content."""
        return self._content

    @content.setter
    def content(self, value: Dict):
        self._content = value

    @property
    def integration_id(self) -> str:
        """Integration identifier."""
        return self._integration_id

    @integration_id.setter
    def integration_id(self, value: str):
        self._integration_id = value
