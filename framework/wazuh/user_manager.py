# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from api.authentication import AuthenticationManager
from wazuh.exception import WazuhError, WazuhInternalError


# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&-])[A-Za-z\d@$!%*?&-_]{8,}$')


def format_result(message):
    return {'data': {'message': message}} if isinstance(message, str) else \
        {'data': {'items': message, 'totalItems': len(message)}}


def get_users():
    """Get the information of all users

    :return: Information about users
    """
    with AuthenticationManager() as auth:
        result = auth.get_users()

    if not result or len(result) == 0:
        raise WazuhInternalError(5002)
    else:
        result = format_result(result)

    return result


def get_user_id(username: str = None):
    """Get the information of a specified user

    :param username: Name of the user
    :return: Information about user
    """
    with AuthenticationManager() as auth:
        result = auth.get_users(username)

    if not result or len(result) == 0:
        raise WazuhError(5001, extra_message='User {} does not exist'.format(username))
    else:
        result = format_result(result)

    return result


def create_user(username: str = None, password: str = None):
    """Create a new user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    result = None
    with AuthenticationManager() as auth:
        if auth.add_user(username, password):
            result = get_user_id(username)

    if result is None:
        raise WazuhError(5000, extra_message='The user \'{}\' could not be created'.format(username))

    return result


def update_user(username: str, password: str):
    """Update a specified user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    with AuthenticationManager() as auth:
        query = auth.update_user(username, password)
        if query is True:
            return get_user_id(username)
        elif query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be updated')


def delete_user(username: str):
    """Delete a specified user

    :param username: Name of the user
    :return: Status message
    """
    with AuthenticationManager() as auth:
        import pydevd_pycharm
        pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
        query = auth.delete_user(username)
        if query is True:
            return format_result('User \'{}\' deleted correctly'.format(username))
        elif query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be removed')
