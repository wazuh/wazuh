# coding: utf-8

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from __future__ import absolute_import

from api.models.base_model_ import Body


class CreateUserModel(Body):
    """Create_user model."""
    def __init__(self, username: str = None, password: str = None):
        self.swagger_types = {
            'username': str,
            'password': str
        }

        self.attribute_map = {
            'username': 'username',
            'password': 'password'
        }

        self._username = username
        self._password = password

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, user_name):
        self._username = user_name

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, passw):
        self._password = passw


class UpdateUserModel(CreateUserModel):
    """Update_user model.

    DO NOT MODIFY THIS CLASS. It depends on `CreateUserModel`.
    """
    def __init__(self):
        super().__init__()
        self.swagger_types.pop('username')
        self.attribute_map.pop('username')


class RoleModel(Body):
    """Security role model."""
    def __init__(self, name: str = None):
        self.swagger_types = {
            'name': str
        }

        self.attribute_map = {
            'name': 'name'
        }

        self._name = name

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name


class RuleModel(Body):
    """Security rule model."""
    def __init__(self, name: str = None, rule: dict = None):
        self.swagger_types = {
            'name': str,
            'rule': dict
        }

        self.attribute_map = {
            'name': 'name',
            'rule': 'rule'
        }

        self._name = name
        self._rule = rule

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def rule(self):
        return self._rule

    @rule.setter
    def rule(self, rule):
        self._rule = rule


class PolicyModel(Body):
    """Security policy model."""
    def __init__(self, name: str = None, policy: dict = None):
        self.swagger_types = {
            'name': str,
            'policy': dict,
        }

        self.attribute_map = {
            'name': 'name',
            'policy': 'policy'
        }

        self._name = name
        self._policy = policy

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy
