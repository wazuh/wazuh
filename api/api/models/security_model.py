# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body


class CreateUserModel(Body):
    """Create_user model."""
    def __init__(self, username: str = None, password: str = None):
        self.swagger_types = {
            'username': str,
            'password': str,
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
    """Role model."""
    def __init__(self, name: str = None, rule: str = None):
        self.swagger_types = {
            'name': str,
            'rule': str,
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
    """Policy model."""
    def __init__(self, name: str = None, policy: str = None):
        self.swagger_types = {
            'name': str,
            'policy': str,
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


class SecurityConfigurationModel(Body):
    """Security configuration model."""
    def __init__(self, auth_token_exp_timeout: int = None, rbac_mode: str = None):
        self.swagger_types = {
            'auth_token_exp_timeout': int,
            'rbac_mode': str,
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

    @property
    def rbac_mode(self):
        return self._rbac_mode

    @auth_token_exp_timeout.setter
    def auth_token_exp_timeout(self, auth_token_exp_timeout):
        self._auth_token_exp_timeout = auth_token_exp_timeout

    @rbac_mode.setter
    def rbac_mode(self, rbac_mode):
        self._rbac_mode = rbac_mode
