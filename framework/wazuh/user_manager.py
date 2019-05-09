

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from wazuh.exception import WazuhException, WazuhInternalError
from glob import glob
from wazuh import common
from wazuh.database import Connection
from werkzeug.security import generate_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from api.authentication import AuthenticationManager
import os
from shutil import chown


def create_exception_dic(id, e):
    """
    Creates a dictionary with a list of agent ids and it's error codes.
    """
    exception_dic = {}
    exception_dic['id'] = id
    exception_dic['error'] = {'message': e.message}

    if isinstance(e, WazuhException):
        exception_dic['error']['code'] = e.code
    else:
        exception_dic['error']['code'] = 1000


    return exception_dic


class Users:
    @classmethod
    def format_result(cls, message):
        result = None
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
    def get_users(wait_for_complete=None, pretty=None):
        """
        Get the information of all users
        :return: Information about users
        """
        result = None

        with AuthenticationManager() as auth:
            result = auth.get_users()

        if result is None:
            result = Users.format_result('')
        else:
            result = Users.format_result(result)

        return result

    @staticmethod
    def get_user_id(username: str = None, wait_for_complete=None, pretty=None):
        """
        get the information of a specified user
        :param username: Name of the user
        :return: Information about user
        """
        result = None

        with AuthenticationManager() as auth:
            result = auth.get_users(username)

        if result is None:
            result = Users.format_result('')
        else:
            result = Users.format_result(result)

        return result


    @staticmethod
    def create_user(username: str, password: str, wait_for_complete= None, pretty= None):
        """
        Create a new user
        :param username: Name for the new user
        :param password: Password for the new user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            if auth.add_user(username, password):
                result = Users.format_result('User created correctly')

        if result is None:
            result = Users.format_result('The user could not be created')

        return result

    @staticmethod
    def update_user(username: str, password: str, wait_for_complete=None, pretty=None):
        """
        Create a new user
        :param username: Name for the new user
        :param password: Password for the new user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            query = auth.update_user(username, password)
            if query:
                result = Users.format_result('User updated correctly')
            elif query is None:
                result = Users.format_result('The user not exist')
            else:
                result = Users.format_result('The user could not be updated')

        return result

    @staticmethod
    def delete_user(username: str, wait_for_complete=None, pretty=None):
        """
        Delete a specified user
        :param username: Name of the user
        :return: Status message
        """
        result = None

        with AuthenticationManager() as auth:
            query = auth.delete_user(username)
            if query is True:
                result = Users.format_result('User deleted correctly')
            elif query is None:
                result = Users.format_result('User not exists')
            elif query == 'admin':
                result = Users.format_result('The users wazuh and wazuh-app can not be deleted')
            else:
                result = Users.format_result('The user could not be deleted')

        return result
