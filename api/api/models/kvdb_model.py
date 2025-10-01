# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import
from typing import Dict, Optional

from api.models.base_model_ import Body, Model
from wazuh.core.exception import WazuhError


class _Validators:
    @staticmethod
    def _check_no_extra(body: Dict, allowed_keys: set):
        extra = set(body.keys()) - allowed_keys
        if extra:
            raise WazuhError(4000, f"Invalid KVDB payload: unexpected field(s): {', '.join(sorted(extra))}")

    @staticmethod
    def _check_non_empty_str(value: Optional[str], field: str):
        if not isinstance(value, str) or not value:
            raise WazuhError(4000, f"Invalid KVDB payload: '{field}' must be a non-empty string")

    @staticmethod
    def _check_optional_str_or_none(value, field: str):
        if value is not None and not isinstance(value, str):
            raise WazuhError(4000, f"Invalid KVDB payload: '{field}' must be a string or null")

    @staticmethod
    def _check_object(value, field: str):
        if not isinstance(value, dict):
            raise WazuhError(4000, f"Invalid KVDB payload: '{field}' must be an object")


class KVDBCreateModel(Body):
    """
    Body para POST /kvdbs
    Requeridos: id, name, content
    Opcional:  integration_id
    """

    def __init__(self, id: str = None, name: str = None,
                 content: Dict = None, integration_id: Optional[str] = None):
        self.swagger_types = {
            'id': str,
            'name': str,
            'content': dict,
            'integration_id': str
        }
        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'content': 'content',
            'integration_id': 'integration_id'
        }

        self._id = id
        self._name = name
        self._content = content
        self._integration_id = integration_id

    # --- properties ---

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, value: str):
        self._id = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def content(self) -> Dict:
        return self._content

    @content.setter
    def content(self, value: Dict):
        self._content = value

    @property
    def integration_id(self) -> Optional[str]:
        return self._integration_id

    @integration_id.setter
    def integration_id(self, value: Optional[str]):
        self._integration_id = value

    # --- helpers ---

    @classmethod
    def from_dict(cls, body: Dict) -> "KVDBCreateModel":
        """Crea y valida desde un dict, rechazando propiedades extra."""
        model = cls(
            id=body.get('id'),
            name=body.get('name'),
            content=body.get('content'),
            integration_id=body.get('integration_id')
        )
        model.validate(body)
        return model

    def validate(self, raw: Dict = None):
        """Validación estricta: required, tipos y sin props extra."""
        raw = raw if raw is not None else self.to_dict()
        _Validators._check_no_extra(raw, set(self.attribute_map.keys()))
        _Validators._check_non_empty_str(self._id, 'id')
        _Validators._check_non_empty_str(self._name, 'name')
        _Validators._check_object(self._content, 'content')
        _Validators._check_optional_str_or_none(self._integration_id, 'integration_id')


class KVDBUpdateModel(Body):
    """
    Body para PUT /kvdbs
    Requeridos: id, content
    Opcionales: name, integration_id
    """

    def __init__(self, id: str = None, content: Dict = None,
                 name: Optional[str] = None, integration_id: Optional[str] = None):
        self.swagger_types = {
            'id': str,
            'content': dict,
            'name': str,
            'integration_id': str
        }
        self.attribute_map = {
            'id': 'id',
            'content': 'content',
            'name': 'name',
            'integration_id': 'integration_id'
        }

        self._id = id
        self._content = content
        self._name = name
        self._integration_id = integration_id

    # --- properties ---

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, value: str):
        self._id = value

    @property
    def content(self) -> Dict:
        return self._content

    @content.setter
    def content(self, value: Dict):
        self._content = value

    @property
    def name(self) -> Optional[str]:
        return self._name

    @name.setter
    def name(self, value: Optional[str]):
        self._name = value

    @property
    def integration_id(self) -> Optional[str]:
        return self._integration_id

    @integration_id.setter
    def integration_id(self, value: Optional[str]):
        self._integration_id = value

    # --- helpers ---

    @classmethod
    def from_dict(cls, body: Dict) -> "KVDBUpdateModel":
        model = cls(
            id=body.get('id'),
            content=body.get('content'),
            name=body.get('name'),
            integration_id=body.get('integration_id')
        )
        model.validate(body)
        return model

    def validate(self, raw: Dict = None):
        raw = raw if raw is not None else self.to_dict()
        _Validators._check_no_extra(raw, set(self.attribute_map.keys()))
        _Validators._check_non_empty_str(self._id, 'id')
        _Validators._check_object(self._content, 'content')
        _Validators._check_optional_str_or_none(self._name, 'name')
        _Validators._check_optional_str_or_none(self._integration_id, 'integration_id')
