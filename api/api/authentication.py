# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import concurrent.futures
import json
import logging
import os
from secrets import token_urlsafe
from shutil import chown
from time import time

from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized

from api import configuration
from api.api_exception import APIException
from api.constants import SECURITY_PATH
from api.util import raise_if_exc
from wazuh.core.cluster import local_client
from wazuh.core.cluster.common import WazuhJSONEncoder
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.rbac.orm import AuthenticationManager
from wazuh.rbac.orm import TokenManager

pool = concurrent.futures.ThreadPoolExecutor()


def check_user_master(user, password):
    with AuthenticationManager() as auth_:
        if auth_.check_user(user, password):
            return {'result': 'success'}


def check_user(user, password, required_scopes=None):
    """Convenience method to use in openapi specification
    :param user: string Unique username
    :param password: string user password
    :param required_scopes:
    :return:
    """
    lc = local_client.LocalClient()
    input_json = {'f': check_user_master,
                  'f_kwargs': {'user': user, 'password': password},
                  'from_cluster': False,
                  'wait_for_complete': True
                  }

    result = json.loads(pool.submit(asyncio.run, lc.execute(command=b'dapi',
                                                            data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                                            wait_for_complete=False)).result())

    if '__wazuh_exception__' not in result.keys():
        return {'sub': user,
                'active': True
                }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_ALGORITHM = 'HS256'
_secret_file_path = os.path.join(SECURITY_PATH, 'jwt_secret')


# Generate secret file to keep safe or load existing secret
def generate_secret():
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
        raise APIException(2002)

    return jwt_secret


def change_secret():
    """Generate new JWT secret"""
    new_secret = token_urlsafe(512)
    with open(_secret_file_path, mode='w') as jwt_secret:
        jwt_secret.write(new_secret)


def get_token_blacklist():
    """Get all token rules"""
    with TokenManager() as tm:
        return tm.get_all_rules()


def generate_token(user_id=None, rbac_policies=None):
    """Generates an encoded jwt token. This method should be called once a user is properly logged on.

    :param user_id: Unique username
    :param auth_context: Authorization context of the current user
    :param rbac_policies: Permissions for the user
    :return: string jwt formatted string
    """
    timestamp = int(time())
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + configuration.api_conf['auth_token_exp_timeout']),
        "sub": str(user_id),
        "rbac_policies": rbac_policies
    }

    return jwt.encode(payload, generate_secret(), algorithm=JWT_ALGORITHM)


def check_token(username, token_iat_time):
    with TokenManager() as tm:
        result = tm.is_token_valid(username=username, token_iat_time=token_iat_time)

    return {'valid': result}


def decode_token(token):
    """Decodes a jwt formatted token. Raise an Unauthorized exception in case validation fails.

    :param token: string jwt formatted token
    :return: dict payload ot the token
    """
    try:
        payload = jwt.decode(token, generate_secret(), algorithms=[JWT_ALGORITHM])
        dapi = DistributedAPI(f=check_token,
                              f_kwargs={'username': payload['sub'], 'token_iat_time': payload['iat']},
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=True,
                              logger=logging.getLogger('wazuh')
                              )
        data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

        if not data.to_dict()['result']['valid']:
            raise Unauthorized

        return payload
    except JWTError as e:
        raise Unauthorized from e


def get_permissions(header):
    """Extracts RBAC info from JWT token in request header

    :param header: Connexion request header
    :return: RBAC mode (white or black list) and user permissions
    """
    # We strip "Bearer " from the Authorization header of the request to get the token
    jwt_token = header[7:]

    payload = decode_token(jwt_token)

    permissions = payload['rbac_policies']

    return permissions
