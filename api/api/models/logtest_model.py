# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body


class LogtestModel(Body):
    """Run logtest model."""
    def __init__(self, token: str = None, log_format: str = None, location: str = None, event: str = None):
        self.swagger_types = {
            'token': str,
            'log_format': str,
            'location': str,
            'event': str
        }

        self.attribute_map = {
            'token': 'token',
            'log_format': 'log_format',
            'location': 'location',
            'event': 'event'
        }

        self._token = token
        self._log_format = log_format
        self._location = location
        self._event = event

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, tkn):
        self._token = tkn

    @property
    def log_format(self):
        return self._log_format

    @log_format.setter
    def log_format(self, logformat):
        self._log_format = logformat

    @property
    def location(self):
        return self._location

    @location.setter
    def location(self, loc):
        self._location = loc

    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, event_new):
        self._event = event_new
