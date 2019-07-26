# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import re

import connexion

from api.authentication import generate_token
from api.models.token_response import TokenResponse  # noqa: E501
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.user_manager import Users
from ..util import remove_nones_to_dict, exception_handler, raise_if_exc

logger = logging.getLogger('wazuh')
loop = asyncio.get_event_loop()
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


def login_user(user):  # noqa: E501
    """User/password authentication to get an access token
    This method should be called to get an API token. This token will expire at some time. # noqa: E501

    :rtype: TokenResponse
    """
    return TokenResponse(token=generate_token(user)), 200


@exception_handler
def get_users():
    """Get username of a specified user"""
    dapi = DistributedAPI(f=Users.get_users,
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_user(username=None):
    """Get username of a specified user

    :param username: Username of an user
    """
    f_kwargs = {'username': username}

    dapi = DistributedAPI(f=Users.get_user_id,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def create_user():
    """Create a new user in all nodes.
    This method will create a user in the master node and propagate it to all available workers.
    """
    f_kwargs = {**{}, **connexion.request.get_json()}

    dapi = DistributedAPI(f=Users.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def update_user(username=None):
    """Modify an existent user in all nodes.
    This method will modify the password of an user in the master node and propagate it to all available workers.
    """
    f_kwargs = {'username': username, **{}, **connexion.request.get_json()}

    dapi = DistributedAPI(f=Users.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_user(username=None):
    """Delete an existent user in all nodes.
    This method will modify the password of an user in the master node and propagate it to all available workers.
    """
    f_kwargs = {'username': username}

    dapi = DistributedAPI(f=Users.delete_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200
