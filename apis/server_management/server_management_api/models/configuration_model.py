# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from __future__ import absolute_import

from server_management_api.models.base_model_ import Body


class SecurityConfigurationModel(Body):
    """Security configuration model."""

    def __init__(self, auth_token_exp_timeout: int = None, rbac_mode: str = None):
        self.swagger_types = {'auth_token_exp_timeout': int, 'rbac_mode': str}

        self.attribute_map = {'auth_token_exp_timeout': 'auth_token_exp_timeout', 'rbac_mode': 'rbac_mode'}

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
