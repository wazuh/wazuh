# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Union

import jwt
import wazuh.core.utils as core_utils
import wazuh.rbac.utils as rbac_utils
from connexion.exceptions import Unauthorized
from wazuh.core.authentication import JWT_ALGORITHM, JWT_ISSUER, get_keypair
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.rbac.preprocessor import optimize_resources

from server_management_api.util import raise_if_exc

INVALID_TOKEN = 'Invalid token'
EXPIRED_TOKEN = 'Token expired'
pool = ThreadPoolExecutor(max_workers=1)


async def check_user_master(name: str, password: str) -> dict:
    """Validate a username-password pair.

    This function must be executed in the master node.

    Parameters
    ----------
    name : str
        Unique username.
    password : str
        User password.

    Returns
    -------
    dict
        Dictionary with the result of the query.
    """
    async with get_indexer_client() as indexer_client:
        users_query = {IndexerKey.TERM: {'user.name': name}}
        users = await indexer_client.users.search({IndexerKey.QUERY: users_query}, limit=1)
        if len(users) == 0:
            return {'result': False}

        user = users[0]
        if not user.check_password(password):
            return {'result': False}

        return {'result': True}


def check_user(name: str, password: str) -> Union[dict, None]:
    """Validate a username-password pair.

    Convenience method to use in OpenAPI specification.

    Parameters
    ----------
    name : str
        Unique username.
    password : str
        User password.

    Returns
    -------
    dict or None
        Dictionary with the username and its status or None.
    """
    dapi = DistributedAPI(
        f=check_user_master,
        f_kwargs={'name': name, 'password': password},
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=logging.getLogger('wazuh-api'),
    )
    data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

    if data['result']:
        return {'sub': name, 'active': True}


def get_security_conf() -> dict:
    """Read the security configuration file.

    Returns
    -------
    dict
        Dictionary with the content of the security.yaml file.
    """
    management_api_config = CentralizedConfig.get_management_api_config()
    return {
        'auth_token_exp_timeout': management_api_config.jwt_expiration_timeout,
        'rbac_mode': management_api_config.rbac_mode,
    }


def generate_token(user_id: str = None, data: dict = None, auth_context: dict = None) -> str:
    """Generate an encoded JWT token. This method should be called once a user is properly logged on.

    Parameters
    ----------
    user_id : str
        Unique username.
    data : dict
        Roles permissions for the user.
    auth_context : dict
        Authorization context used in the run as login request.

    Returns
    -------
    str
        Encoded JWT token.
    """
    dapi = DistributedAPI(
        f=get_security_conf,
        request_type='local_master',
        is_async=False,
        wait_for_complete=False,
        logger=logging.getLogger('wazuh-api'),
    )
    result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).dikt
    timestamp = int(core_utils.get_utc_now().timestamp())

    payload = {
        'iss': JWT_ISSUER,
        'aud': 'Wazuh API REST',
        'nbf': timestamp,
        'exp': timestamp + result['auth_token_exp_timeout'],
        'sub': str(user_id),
        'run_as': auth_context is not None,
        'rbac_roles': data['roles'],
        'rbac_mode': result['rbac_mode'],
    } | (
        {'hash_auth_context': hashlib.blake2b(json.dumps(auth_context).encode(), digest_size=16).hexdigest()}
        if auth_context is not None
        else {}
    )
    private_key, _ = get_keypair()

    return jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)


@rbac_utils.token_cache(rbac_utils.tokens_cache)
async def check_token(username: str, roles: tuple, token_nbf_time: int, run_as: bool) -> dict:
    """Check the validity of a token with the current time and the generation time of the token.

    Parameters
    ----------
    username : str
        Unique username.
    roles : tuple
        Tuple of roles related with the current token.
    token_nbf_time : int
        Issued at time of the current token.
    run_as : bool
        Indicate if the token has been granted through authorization context endpoint.

    Returns
    -------
    dict
        Dictionary with the result.
    """
    # Check that the user exists
    async with get_indexer_client() as indexer_client:
        users_query = {
            IndexerKey.QUERY: {IndexerKey.BOOL: {IndexerKey.FILTER: {IndexerKey.TERM: {'user.name': username}}}}
        }
        users = await indexer_client.users.search(users_query, limit=1)
        if len(users) == 0:
            return {'valid': False}

        user = users[0]

        roles_query = {
            IndexerKey.QUERY: {IndexerKey.BOOL: {IndexerKey.FILTER: {IndexerKey.TERMS: {IndexerKey._ID: user.roles}}}}
        }
        user_roles = await indexer_client.roles.search({IndexerKey.QUERY: roles_query})

        if not user.allow_run_as and set(user_roles) != set(roles):
            return {'valid': False}

    policies = optimize_resources(roles)

    return {'valid': True, 'policies': policies}


def decode_token(token: str) -> dict:
    """Decode a JWT formatted token and add processed policies.
    Raise an Unauthorized exception in case validation fails.

    Parameters
    ----------
    token : str
        JWT formatted token.

    Raises
    ------
    Unauthorized
        If the token validation fails.

    Returns
    -------
    dict
        Dictionary with the token payload.
    """
    try:
        # Decode JWT token with local secret
        _, public_key = get_keypair()
        payload = jwt.decode(token, public_key, algorithms=[JWT_ALGORITHM], audience='Wazuh API REST')

        # Check token and add processed policies in the Master node
        server_config = CentralizedConfig.get_server_config()
        dapi = DistributedAPI(
            f=check_token,
            f_kwargs={
                'username': payload['sub'],
                'roles': tuple(payload['rbac_roles']),
                'token_nbf_time': payload['nbf'],
                'run_as': payload['run_as'],
                'origin_node_type': server_config.node.type,
            },
            request_type='local_master',
            is_async=True,
            wait_for_complete=False,
            logger=logging.getLogger('wazuh-api'),
        )
        data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).to_dict()

        if not data['result']['valid']:
            raise Unauthorized(INVALID_TOKEN)
        payload['rbac_policies'] = data['result']['policies']
        payload['rbac_policies']['rbac_mode'] = payload.pop('rbac_mode')

        # Detect local changes
        dapi = DistributedAPI(
            f=get_security_conf,
            request_type='local_master',
            is_async=False,
            wait_for_complete=False,
            logger=logging.getLogger('wazuh-api'),
        )
        result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

        current_rbac_mode = result['rbac_mode']
        current_expiration_time = result['auth_token_exp_timeout']
        if (
            payload['rbac_policies']['rbac_mode'] != current_rbac_mode
            or (payload['exp'] - payload['nbf']) != current_expiration_time
        ):
            raise Unauthorized(EXPIRED_TOKEN)

        return payload
    except jwt.exceptions.PyJWTError as exc:
        raise Unauthorized(INVALID_TOKEN) from exc
