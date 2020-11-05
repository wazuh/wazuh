# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import concurrent.futures
import copy
import logging
import os
from secrets import token_urlsafe
from shutil import chown
from time import time

from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized

import api.configuration as conf
from api.constants import SECURITY_CONFIG_PATH
from api.constants import SECURITY_PATH
from api.util import raise_if_exc
from wazuh import WazuhInternalError
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.rbac.orm import AuthenticationManager, TokenManager, UserRolesManager, Roles
from wazuh.rbac.preprocessor import optimize_resources

pool = concurrent.futures.ThreadPoolExecutor()


def check_user_master(user, password):
    """This function must be executed in master node.

    Parameters
    ----------
    user : str
        Unique username
    password : str
        User password

    Returns
    -------
    Dict with the result of the query
    """
    with AuthenticationManager() as auth_:
        if auth_.check_user(user, password):
            return {'result': True}

    return {'result': False}


def check_user(user, password, required_scopes=None):
    """Convenience method to use in OpenAPI specification

    Parameters
    ----------
    user : str
        Unique username
    password : str
        User password
    required_scopes

    Returns
    -------
    Dict with the username and his status
    """
    dapi = DistributedAPI(f=check_user_master,
                          f_kwargs={'user': user, 'password': password},
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logging.getLogger('wazuh')
                          )
    data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

    if data['result']:
        return {'sub': user,
                'active': True
                }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_ALGORITHM = 'HS256'
_secret_file_path = os.path.join(SECURITY_PATH, 'jwt_secret')


def generate_secret():
    """Generate secret file to keep safe or load existing secret."""
    try:
        if not os.path.exists(_secret_file_path):
            jwt_secret = token_urlsafe(512)
            with open(_secret_file_path, mode='x') as secret_file:
                secret_file.write(jwt_secret)
            try:
                chown(_secret_file_path, 'ossec', 'ossec')
            except PermissionError:
                pass
            os.chmod(_secret_file_path, 0o640)
        else:
            with open(_secret_file_path, mode='r') as secret_file:
                jwt_secret = secret_file.readline()
    except IOError:
        raise WazuhInternalError(6003)

    return jwt_secret


def change_secret():
    """Generate new JWT secret."""
    new_secret = token_urlsafe(512)
    with open(_secret_file_path, mode='w') as jwt_secret:
        jwt_secret.write(new_secret)


def get_security_conf():
    conf.security_conf.update(conf.read_yaml_config(config_file=SECURITY_CONFIG_PATH,
                                                    default_conf=conf.default_security_configuration))
    return copy.deepcopy(conf.security_conf)


def generate_token(user_id=None, data=None, run_as=False):
    """Generate an encoded jwt token. This method should be called once a user is properly logged on.

    Parameters
    ----------
    user_id : str
        Unique username
    data : dict
        Roles permissions for the user
    run_as : bool
        Indicate if the user has logged in with run_as or not

    Returns
    -------
    JWT encode token
    """
    dapi = DistributedAPI(f=get_security_conf,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logging.getLogger('wazuh')
                          )
    result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).dikt
    timestamp = int(time())

    payload = {
        "iss": JWT_ISSUER,
        "aud": "Wazuh API REST",
        "nbf": int(timestamp),
        "exp": int(timestamp + result['auth_token_exp_timeout']),
        "sub": str(user_id),
        "run_as": run_as,
        "rbac_roles": data['roles'],
        "rbac_mode": result['rbac_mode']
    }

    return jwt.encode(payload, generate_secret(), algorithm=JWT_ALGORITHM)


def check_token(username, roles, token_nbf_time, run_as):
    """Check the validity of a token with the current time and the generation time of the token.

    Parameters
    ----------
    username : str
        Unique username
    roles : list
        List of roles related with the current token
    token_nbf_time : int
        Issued at time of the current token
    run_as : bool
        Indicate if the token has been granted through run_as endpoint

    Returns
    -------
    Dict with the result
    """
    # Check that the user exists
    with AuthenticationManager() as am:
        user = am.get_user(username=username)
        if not user:
            return {'valid': False}
        user_id = user['id']

        with UserRolesManager() as urm:
            user_roles = [role['id'] for role in map(Roles.to_dict, urm.get_all_roles_from_user(user_id=user_id))]
            if not am.user_allow_run_as(user['username']) and set(user_roles) != set(roles):
                return {'valid': False}
            with TokenManager() as tm:
                for role in user_roles:
                    if not tm.is_token_valid(role_id=role, user_id=user_id, token_nbf_time=int(token_nbf_time),
                                             run_as=run_as):
                        return {'valid': False}

    policies = optimize_resources(roles)

    return {'valid': True, 'policies': policies}


def decode_token(token):
    """Decode a jwt formatted token and add processed policies. Raise an Unauthorized exception in case validation fails.

    Parameters
    ----------
    token : str
        JWT formatted token

    Returns
    -------
    Dict payload ot the token
    """
    try:
        # Decode JWT token with local secret
        payload = jwt.decode(token, generate_secret(), algorithms=[JWT_ALGORITHM], audience='Wazuh API REST')

        # Check token and add processed policies in the Master node
        dapi = DistributedAPI(f=check_token,
                              f_kwargs={'username': payload['sub'],
                                        'roles': payload['rbac_roles'], 'token_nbf_time': payload['nbf'],
                                        'run_as': payload['run_as']},
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=True,
                              logger=logging.getLogger('wazuh')
                              )
        data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).to_dict()

        if not data['result']['valid']:
            raise Unauthorized
        payload['rbac_policies'] = data['result']['policies']
        payload['rbac_policies']['rbac_mode'] = payload.pop('rbac_mode')

        # Detect local changes
        dapi = DistributedAPI(f=get_security_conf,
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=True,
                              logger=logging.getLogger('wazuh')
                              )
        result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

        current_rbac_mode = result['rbac_mode']
        current_expiration_time = result['auth_token_exp_timeout']
        if payload['rbac_policies']['rbac_mode'] != current_rbac_mode \
                or (payload['exp'] - payload['nbf']) != current_expiration_time:
            raise Unauthorized

        return payload
    except JWTError as e:
        raise Unauthorized from e
