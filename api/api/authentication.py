# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import fcntl
import hashlib
import json
import jwt
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from connexion.exceptions import Unauthorized

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
from wazuh.core.decorators import dapi_allower

INVALID_TOKEN = "Invalid token"
EXPIRED_TOKEN = "Token expired"
pool = ThreadPoolExecutor(max_workers=1)


@dapi_allower()
def check_user_master(user: str, password: str) -> dict:
    """Validate a username-password pair.

    This function must be executed in the master node.

    Parameters
    ----------
    user : str
        Unique username.
    password : str
        User password.

    Returns
    -------
    dict
        Dictionary with the result of the query.
    """
    with AuthenticationManager() as auth_:
        if auth_.check_user(user, password):
            return {'result': True}

    return {'result': False}


def check_user(user: str, password: str, required_scopes=None) -> Union[dict, None]:
    """Validate a username-password pair.

    Convenience method to use in OpenAPI specification.

    Parameters
    ----------
    user : str
        Unique username.
    password : str
        User password.

    Returns
    -------
    dict or None
        Dictionary with the username and its status or None.
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
        return {'sub': user, 'active': True }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_ALGORITHM = 'ES512'
_private_key_path = os.path.join(SECURITY_PATH, 'private_key.pem')
_public_key_path = os.path.join(SECURITY_PATH, 'public_key.pem')
_keypair_lock_path = os.path.join(SECURITY_PATH, '.keypair.lock')

# Keypair cached by this process, tagged with the identity of the files it was read from.
#
# This used to be a plain `functools.cache`, cleared by `change_keypair()` only in the process that
# happened to handle the revocation. `revoke_tokens` runs in the `process_pool` while `jwt.decode`
# runs in the API's main process, so every other process kept signing and verifying with the old
# keys and `PUT /security/user/revoke` did not end the sessions it reported ending. Stamping the
# cache with the files' identity makes each process notice a rotation on its own next use,
# whichever process performed it.
#
# Holds `(stamp, keypair, deadline)`, where `deadline` is the `time.monotonic()` value past which
# the entry is re-read regardless of its stamp.
_keypair_cache = None

# Maximum time a process serves a cached keypair without re-reading it from disk, in seconds.
#
# The stamp is not by itself enough to tell every two generations apart: `_write_new_keypair()`
# rewrites both files in place, so the inode never changes, and PEM-encoded SECP521R1 keys have a
# fixed length, so neither does the size. That leaves `st_mtime_ns`, which comes from a coarse
# clock, so two rotations landing within the same tick share a stamp, as does a restore that
# preserves timestamps (`cp -p`, `rsync -a`). Without a lifetime, such a collision would make this
# process reject every token signed with the current key until it is restarted; with one, it
# recovers on its own.
_KEYPAIR_CACHE_TTL = 5


def _keypair_stamp():
    """Build the identity of the keypair currently on disk.

    Returns
    -------
    tuple or None
        Modification time, inode and size of the private and public key files, or None if either
        of them is missing.
    """
    try:
        private_stat = os.stat(_private_key_path)
        public_stat = os.stat(_public_key_path)
    except OSError:
        return None

    return (private_stat.st_mtime_ns, private_stat.st_ino, private_stat.st_size,
            public_stat.st_mtime_ns, public_stat.st_ino, public_stat.st_size)


def _clear_keypair_cache():
    """Drop the keypair cached by this process."""
    global _keypair_cache
    _keypair_cache = None


def generate_keypair():
    """Generate key files to keep safe or load existing public and private keys.

    The result is cached per process and tagged with the identity of the key files it was read
    from, so a rotation performed by any process, or outside the API altogether, is picked up on
    the next call instead of being masked until the process restarts. The entry is also re-read
    every `_KEYPAIR_CACHE_TTL` seconds, so a rotation the stamp cannot distinguish from the
    previous one is not masked for good either.

    Uses file-based locking to prevent race conditions between reading and writing keypairs.
    This ensures that if keys are regenerated (e.g., via revoke_tokens) while reading,
    we won't cache stale keys.

    Raises
    ------
    WazuhInternalError(6003)
        If there was an error trying to load the JWT secret, or if only one of the two key files
        is present on disk.
    """
    global _keypair_cache

    # Taken before the keys are read on purpose: if a rotation lands between this stat and the
    # read, the fresh keys end up tagged with the superseded stamp and are reloaded on the next
    # call. Stamping afterwards would instead tag stale keys as current.
    stamp = _keypair_stamp()
    if _keypair_cache is not None and _keypair_cache[0] == stamp and time.monotonic() < _keypair_cache[2]:
        return _keypair_cache[1]

    lock_file = None
    try:
        # Try to acquire lock file (best-effort, only if security dir exists)
        try:
            if os.path.isdir(os.path.dirname(_keypair_lock_path)):
                lock_file = open(_keypair_lock_path, 'a+')
        except (OSError, IOError):
            pass  # Continue without locking

        private_key_exists = os.path.exists(_private_key_path)
        public_key_exists = os.path.exists(_public_key_path)
        if private_key_exists and public_key_exists:
            # Keys exist - acquire shared lock for reading (if available)
            private_key, public_key = _read_keypair_locked(lock_file)
        elif private_key_exists or public_key_exists:
            # Only one of the two files is there: a half-written or half-restored install. Creating
            # a keypair here would silently rotate the keys and end every session in every process,
            # so report the inconsistency instead of hiding it behind a rotation nobody asked for.
            raise WazuhInternalError(6003)
        else:
            # Need to create keys - acquire exclusive lock if available
            if lock_file:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except (OSError, IOError):
                    pass  # Continue without exclusive lock
            # Double-check after acquiring lock (another process might have created them)
            if not os.path.exists(_private_key_path) or not os.path.exists(_public_key_path):
                private_key, public_key = _write_new_keypair()
            else:
                private_key, public_key = _read_keypair_locked(lock_file)
    except IOError:
        raise WazuhInternalError(6003)
    finally:
        if lock_file:
            lock_file.close()

    keypair = (private_key, public_key)
    # `stamp` is None only when the key files did not exist yet and have just been written by this
    # call, so their identity has to be taken now.
    _keypair_cache = (stamp if stamp is not None else _keypair_stamp(), keypair,
                      time.monotonic() + _KEYPAIR_CACHE_TTL)

    return keypair


# Kept as an attribute so that the callers written against `functools.cache` (`change_keypair` and
# the inotify watcher in `api.signals`) keep working unchanged.
generate_keypair.cache_clear = _clear_keypair_cache


def _read_keypair_locked(lock_file):
    """Read keypair with shared lock (if available).

    Parameters
    ----------
    lock_file : file or None
        Open lock file descriptor, or None if locking not available.

    Returns
    -------
    tuple
        (private_key, public_key) strings.
    """
    if lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
        except (OSError, IOError):
            pass  # Continue without shared lock
    with open(_private_key_path, mode='r') as key_file:
        private_key = key_file.read()
    with open(_public_key_path, mode='r') as key_file:
        public_key = key_file.read()
    return private_key, public_key


def _write_new_keypair():
    """Generate and write new keypair (exclusive lock already held).

    Returns
    -------
    tuple
        (private_key, public_key) strings.
    """
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

    try:
        os.chown(_private_key_path, wazuh_uid(), wazuh_gid())
        os.chown(_public_key_path, wazuh_uid(), wazuh_gid())
    except PermissionError:
        pass
    os.chmod(_private_key_path, 0o640)
    os.chmod(_public_key_path, 0o640)

    return private_key, public_key


def change_keypair():
    """Generate key files to keep safe.

    Uses exclusive file locking to prevent race conditions with concurrent reads.
    Clears the cache after writing new keys to ensure they are reloaded.

    Returns
    -------
    tuple
        (private_key, public_key) strings.
    """
    lock_file = None
    try:
        # Try to acquire lock file (best-effort, only if security dir exists)
        try:
            if os.path.isdir(os.path.dirname(_keypair_lock_path)):
                lock_file = open(_keypair_lock_path, 'a+')
                # Acquire exclusive lock for writing
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except (OSError, IOError):
                    pass  # Continue without exclusive lock
        except (OSError, IOError):
            pass  # Continue without locking

        private_key, public_key = _write_new_keypair()
        # Clear cache so next call to generate_keypair() loads new keys
        generate_keypair.cache_clear()
    except IOError:
        raise WazuhInternalError(6003)
    finally:
        if lock_file:
            lock_file.close()

    return private_key, public_key


@dapi_allower()
def get_security_conf() -> dict:
    """Read the security configuration file.

    Returns
    -------
    dict
        Dictionary with the content of the security.yaml file.
    """
    conf.security_conf.update(conf.read_yaml_config(config_file=SECURITY_CONFIG_PATH,
                                                    default_conf=conf.default_security_configuration))
    return conf.security_conf


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
    dapi = DistributedAPI(f=get_security_conf,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=False,
                          logger=logging.getLogger('wazuh-api')
                          )
    result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).dikt
    # Get timestamp with millisecond precision directly
    now_ms = int(core_utils.get_utc_now().timestamp() * 1000)
    now_seconds = now_ms // 1000

    payload = {
                  "iss": JWT_ISSUER,
                  "aud": "Wazuh API REST",
                  "nbf": now_seconds,  # Standard claim: integer seconds since epoch (RFC 7519)
                  "nbf_ms": now_ms,  # Private claim: milliseconds for precise validation
                  "exp": now_seconds + result['auth_token_exp_timeout'],
                  "sub": str(user_id),
                  "run_as": auth_context is not None,
                  "rbac_roles": data['roles'],
                  "rbac_mode": result['rbac_mode']
              } | ({"hash_auth_context": hashlib.blake2b(json.dumps(auth_context).encode(),
                                                         digest_size=16).hexdigest()}
                   if auth_context is not None else {})

    return jwt.encode(payload, generate_keypair()[0], algorithm=JWT_ALGORITHM)


@rbac_utils.policies_cache()
def get_optimized_policies(roles: tuple) -> dict:
    """Obtain the RBAC policies granted by a set of roles.

    This is the expensive half of `check_token` and the only half that is cached. It depends solely
    on the roles and on the policies linked to them, never on whether the account behind the token
    still exists or whether the token has been revoked, so a cache hit cannot authenticate anyone.

    Parameters
    ----------
    roles : tuple
        Tuple of roles related with the current token.

    Returns
    -------
    dict
        Optimized policies granted by `roles`.
    """
    return optimize_resources(roles)


@dapi_allower()
def check_token(username: str, roles: tuple, token_nbf_time: int, run_as: bool,
                origin_node_type: str) -> dict:
    """Check the validity of a token with the current time and the generation time of the token.

    The validity decision is never cached. Caching it meant that deleting a user, changing its
    password or revoking its token did not end the session: the checks below were skipped for as
    long as the cached decision lived, which was the token's own lifetime. Only the policy
    preprocessing is cached, in `get_optimized_policies`.

    Parameters
    ----------
    username : str
        Unique username.
    roles : tuple
        Tuple of roles related with the current token.
    token_nbf_time : int
        Issued at time of the current token (milliseconds).
    run_as : bool
        Indicate if the token has been granted through authorization context endpoint.
    origin_node_type : str
        Type of the node the request originated from. Only requests coming from the master node
        may be served the cached policies.

    Returns
    -------
    dict
        Dictionary with the result.
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
                # Always validate the user and run_as blacklists, even when the token carries no roles.
                if not tm.is_token_valid(user_id=user_id, token_nbf_time=int(token_nbf_time), run_as=run_as):
                    return {'valid': False}
                # Validate every role carried by the token, not only the statically-linked ones.
                # run_as users have their roles assigned dynamically, so those roles travel in the
                # token (roles) instead of being returned by get_all_roles_from_user (user_roles).
                for role in set(user_roles) | set(roles):
                    if not tm.is_token_valid(role_id=role, user_id=user_id, token_nbf_time=int(token_nbf_time),
                                             run_as=run_as):
                        return {'valid': False}

    policies = get_optimized_policies(roles=roles, origin_node_type=origin_node_type)

    # Copied for safety only. The caller adds `rbac_mode` to this dictionary (see `decode_token`)
    # and, on the master path, `get_optimized_policies` hands back the cached entry itself, but that
    # mutation cannot reach the cache: the DAPI layer deep-copies the result (`WazuhResult.to_dict`)
    # before `decode_token` gets to see it. The copy keeps correctness here from depending on what a
    # distant layer happens to do.
    return {'valid': True, 'policies': dict(policies)}


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
        payload = jwt.decode(token, generate_keypair()[1], algorithms=[JWT_ALGORITHM], audience='Wazuh API REST')

        # Check token and add processed policies in the Master node
        # Use nbf_ms for millisecond precision validation, fallback to nbf * 1000 for backward compatibility
        token_nbf_time = payload.get('nbf_ms', int(payload['nbf'] * 1000))
        dapi = DistributedAPI(f=check_token,
                              f_kwargs={'username': payload['sub'],
                                        'roles': tuple(payload['rbac_roles']), 'token_nbf_time': token_nbf_time,
                                        'run_as': payload['run_as'], 'origin_node_type': read_config()['node_type']},
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=False,
                              logger=logging.getLogger('wazuh-api')
                              )
        data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).to_dict()

        if not data['result']['valid']:
            raise Unauthorized(INVALID_TOKEN)
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
                or (payload['exp'] - int(payload['nbf'])) != current_expiration_time:
            raise Unauthorized(EXPIRED_TOKEN)

        return payload
    except jwt.exceptions.PyJWTError as exc:
        raise Unauthorized(INVALID_TOKEN) from exc
