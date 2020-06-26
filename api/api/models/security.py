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
