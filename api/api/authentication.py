# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized

import api.configuration as conf
import wazuh.core.utils as core_utils
import wazuh.rbac.utils as rbac_utils
from api.constants import SECURITY_CONFIG_PATH
from api.constants import SECURITY_PATH
from api.util import raise_if_exc
from wazuh import WazuhInternalError
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.cluster.utils import read_config
from wazuh.core.common import wazuh_uid, wazuh_gid
from wazuh.rbac.orm import AuthenticationManager, TokenManager, UserRolesManager
from wazuh.rbac.preprocessor import optimize_resources

pool = ThreadPoolExecutor(max_workers=1)


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
                          wait_for_complete=False,
                          logger=logging.getLogger('wazuh-api')
                          )
    data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

    if data['result']:
        return {'sub': user,
                'active': True
                }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_ALGORITHM = 'ES512'
_private_key_path = os.path.join(SECURITY_PATH, 'private_key.pem')
_public_key_path = os.path.join(SECURITY_PATH, 'public_key.pem')


def generate_keypair():
    """Generate key files to keep safe or load existing public and private keys."""
    try:
        if not os.path.exists(_private_key_path) or not os.path.exists(_public_key_path):
            private_key, public_key = change_keypair()
            try:
                os.chown(_private_key_path, wazuh_uid(), wazuh_gid())
                os.chown(_public_key_path, wazuh_uid(), wazuh_gid())
            except PermissionError:
                pass
            os.chmod(_private_key_path, 0o640)
            os.chmod(_public_key_path, 0o640)
        else:
            with open(_private_key_path, mode='r') as key_file:
                private_key = key_file.read()
            with open(_public_key_path, mode='r') as key_file:
                public_key = key_file.read()
    except IOError:
        raise WazuhInternalError(6003)

    return private_key, public_key


def change_keypair():
    """Generate key files to keep safe."""
    key_obj = ec.generate_private_key(ec.SECP521R1())
    private_key = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key = key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    with open(_private_key_path, mode='w') as key_file:
        key_file.write(private_key)
    with open(_public_key_path, mode='w') as key_file:
        key_file.write(public_key)

    return private_key, public_key


def get_security_conf():
    conf.security_conf.update(conf.read_yaml_config(config_file=SECURITY_CONFIG_PATH,
                                                    default_conf=conf.default_security_configuration))
    return conf.security_conf


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
                          wait_for_complete=False,
                          logger=logging.getLogger('wazuh-api')
                          )
    result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).dikt
    timestamp = int(core_utils.get_utc_now().timestamp())

    payload = {
        "iss": JWT_ISSUER,
        "aud": "Wazuh API REST",
        "nbf": timestamp,
        "exp": timestamp + result['auth_token_exp_timeout'],
        "sub": str(user_id),
        "run_as": run_as,
        "rbac_roles": data['roles'],
        "rbac_mode": result['rbac_mode']
    }

    return jwt.encode(payload, generate_keypair()[0], algorithm=JWT_ALGORITHM)


@rbac_utils.token_cache(rbac_utils.tokens_cache)
def check_token(username, roles, token_nbf_time, run_as):
    """Check the validity of a token with the current time and the generation time of the token.

    Parameters
    ----------
    username : str
        Unique username
    roles : tuple
        Tuple of roles related with the current token
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
            user_roles = [role.id for role in urm.get_all_roles_from_user(user_id=user_id)]
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
    """Decode a jwt formatted token and add processed policies.
    Raise an Unauthorized exception in case validation fails.

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
        payload = jwt.decode(token, generate_keypair()[1], algorithms=[JWT_ALGORITHM], audience='Wazuh API REST')

        # Check token and add processed policies in the Master node
        dapi = DistributedAPI(f=check_token,
                              f_kwargs={'username': payload['sub'],
                                        'roles': tuple(payload['rbac_roles']), 'token_nbf_time': payload['nbf'],
                                        'run_as': payload['run_as'], 'origin_node_type': read_config()['node_type']},
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=False,
                              logger=logging.getLogger('wazuh-api')
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
                              wait_for_complete=False,
                              logger=logging.getLogger('wazuh-api')
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
