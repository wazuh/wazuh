# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from __future__ import absolute_import

from api.models.base_model_ import Body, Model


class HTTPSModel(Model):
    def __init__(self, enabled=None, key=None, cert=None, use_ca=None, ca=None):
        self.swagger_types = {
            'enabled': bool,
            'key': str,
            'cert': str,
            'use_ca': bool,
            'ca': str
        }

        self.attribute_map = {
            'enabled': 'enabled',
            'key': 'key',
            'cert': 'cert',
            'use_ca': 'use_ca',
            'ca': 'ca'
        }

        self._enabled = enabled
        self._key = key
        self._cert = cert
        self._use_ca = use_ca
        self._ca = ca

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        self._enabled = enabled

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        self._key = key

    @property
    def cert(self):
        return self._cert

    @cert.setter
    def cert(self, cert):
        self._cert = cert

    @property
    def use_ca(self):
        return self._use_ca

    @use_ca.setter
    def use_ca(self, use_ca):
        self._use_ca = use_ca

    @property
    def ca(self):
        return self._ca

    @ca.setter
    def ca(self, ca):
        self._ca = ca


class SecurityConfigurationModel(Body):
    """Security configuration model."""

    def __init__(self, auth_token_exp_timeout: int = None, rbac_mode: str = None):
        self.swagger_types = {
            'auth_token_exp_timeout': int,
            'rbac_mode': str
        }

        self.attribute_map = {
            'auth_token_exp_timeout': 'auth_token_exp_timeout',
            'rbac_mode': 'rbac_mode'
        }

        self._auth_token_exp_timeout = auth_token_exp_timeout
        self._rbac_mode = rbac_mode

    @property
    def auth_token_exp_timeout(self):
        return self._auth_token_exp_timeout

    @auth_token_exp_timeout.setter
    def auth_token_exp_timeout(self, auth_token_exp_timeout):
        self._auth_token_exp_timeout = auth_token_exp_timeout

    @property
    def rbac_mode(self):
        return self._rbac_mode

    @rbac_mode.setter
    def rbac_mode(self, rbac_mode):
        self._rbac_mode = rbac_mode
