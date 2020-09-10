# coding: utf-8

from __future__ import absolute_import

from datetime import date, datetime  # noqa: F401
from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Body


class LogtestModel(Body):
    """Run logtest model."""
    def __init__(self, token: str = None, log_format: str = None, location: str = None, log: str = None):
        self.swagger_types = {
            'token': str,
            'log_format': str,
            'location': str,
            'log': str
        }

        self.attribute_map = {
            'token': 'token',
            'log_format': 'log_format',
            'location': 'location',
            'log': 'log'
        }

        self._token = token
        self._log_format = log_format
        self._location = location
        self._log = log

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
    def log(self):
        return self._log

    @log.setter
    def log(self, log_new):
        self._log = log_new
