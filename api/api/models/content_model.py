# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from api.models.base_model_ import Body

class ContentFileDataModel(Body):
    """
    Model for content file validation requests.

    Parameters
    ----------
    type : str
        The type of content to validate (e.g., "rule").
    payload : str
        The content file to validate.
    """
    def __init__(self, type: str, payload: str):
        self.swagger_types = {
            'type': str,
            'payload': str
        }

        self.attribute_map = {
            'type': 'type',
            'payload': 'payload'
        }

        self._type = type
        self._payload = payload

    @property
    def type(self) -> str:
        return self._type

    @type.setter
    def type(self, type: str):
        self._type = type

    @property
    def payload(self) -> str:
        return self._payload

    @payload.setter
    def payload(self, payload: str):
        self._payload = payload


class LogTestPayloadModel(Body):
    """
    Model for log test payload requests.

    Parameters
    ----------
    payload : str
        The log payload to test.
    """
    def __init__(self, payload: str):
        self.swagger_types = {
            'payload': str
        }

        self.attribute_map = {
            'payload': 'payload'
        }

        self._payload = payload

    @property
    def payload(self) -> str:
        return self._payload

    @payload.setter
    def payload(self, payload: str):
        self._payload = payload
