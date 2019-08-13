# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from api.authentication import AuthenticationManager
from wazuh.exception import WazuhError, WazuhInternalError


class Users:
    @classmethod
    def format_result(cls, message):
        if isinstance(message, str):
            result = {
                'data': {
                    'message': message
                }
            }
        else:
            result = {
                'data': {
                    'items': message,
                    'totalItems': len(message)
                }
            }

        return result

    @staticmethod
    def get_users():
        """Get the information of all users

        :return: Information about users
        """
        result = None

        with AuthenticationManager() as auth:
            result = auth.get_users()

        if not result or len(result) == 0:
            raise WazuhInternalError(5002)
        else:
            result = Users.format_result(result)

        return result

    @staticmethod
    def get_user_id(username: str = None):
        """Get the information of a specified user

        :param username: Name of the user
        :return: Information about user
        """
        result = None

        with AuthenticationManager() as auth:
            result = auth.get_users(username)

        if not result or len(result) == 0:
            raise WazuhError(5001, extra_message='User {} does not exist'.format(username))
        else:
            result = Users.format_result(result)

        return result

    @staticmethod
    def create_user(username: str, password: str):
        """Create a new user

        :param username: Name for the new user
        :param password: Password for the new user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            if auth.add_user(username, password):
                result = Users.get_user_id(username)

        if result is None:
            raise WazuhError(5000, extra_message='The user \'{}\' could not be created'.format(username))

        return result

    @staticmethod
    def update_user(username: str, password: str):
        """Update a specified user

        :param username: Name for the new user
        :param password: Password for the new user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            query = auth.update_user(username, password)
            if query:
                result = Users.get_user_id(username)
            elif query is None:
                raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
            else:
                raise WazuhError(5003, extra_message='The user \'{}\' could not be updated'.format(username))

        return result

    @staticmethod
    def delete_user(username: str):
        """Delete a specified user

        :param username: Name of the user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            query = auth.delete_user(username)
            if query is True:
                result = Users.format_result('User \'{}\' deleted correctly'.format(username))
            elif query is None:
                raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
            elif query == 'admin':
                raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be removed')

        return result
