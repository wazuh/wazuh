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

from cryptography.exceptions import UnsupportedAlgorithm
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


def _keypair_file_ready(path):
    """Whether a key file is on disk with content in it.

    Every writer truncates before writing, so an interrupted write leaves a zero-byte file rather
    than a missing one. Classifying that as present is what would send it to a read that returns an
    unusable key instead of to the recovery below.

    Parameters
    ----------
    path : str
        Path of the key file.

    Returns
    -------
    bool
        True if the file exists and is not empty.
    """
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


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
    previous one is not masked for good either. Nothing is cached when that identity cannot be
    established, which is the case for keys this call had to write or rebuild without holding the
    exclusive lock.

    Uses file-based locking to prevent race conditions between reading and writing keypairs.
    This ensures that if keys are regenerated (e.g., via revoke_tokens) while reading,
    we won't cache stale keys.

    Raises
    ------
    WazuhInternalError(6003)
        If there was an error trying to load the JWT secret, or if the private key file is missing
        or empty while the public one holds a key.
    """
    global _keypair_cache

    # Taken before the keys are read on purpose: if a rotation lands between this stat and the
    # read, the fresh keys end up tagged with the superseded stamp and are reloaded on the next
    # call. Stamping afterwards would instead tag stale keys as current.
    stamp = _keypair_stamp()
    # Bound once instead of read three times: `cache_clear()` sets this global to None and can run
    # on another thread of this very process, since the API falls back to a single
    # `ThreadPoolExecutor` for every local request when `/dev/shm` is not accessible. Re-reading the
    # global between the guard and the subscripts would then raise `TypeError` on a request that has
    # nothing to do with the rotation.
    cached_keypair = _keypair_cache
    if cached_keypair is not None and cached_keypair[0] == stamp and time.monotonic() < cached_keypair[2]:
        return cached_keypair[1]

    lock_file = None
    try:
        # Try to acquire lock file (best-effort, only if security dir exists)
        try:
            if os.path.isdir(os.path.dirname(_keypair_lock_path)):
                lock_file = open(_keypair_lock_path, 'a+')
        except (OSError, IOError):
            pass  # Continue without locking

        if _keypair_file_ready(_private_key_path) and _keypair_file_ready(_public_key_path):
            if stamp is None:
                # The files were not there when the stat at entry ran, so that None is not their
                # identity: another process finished writing them in between, which is what two
                # processes starting at once do. Re-stat before reading, never after.
                stamp = _keypair_stamp()
            # Keys exist - acquire shared lock for reading (if available)
            private_key, public_key = _read_keypair_locked(lock_file)
        else:
            # Either no keys at all or only one of them. Nothing can be concluded yet: the pair is
            # written one file at a time, so a writer holding the exclusive lock has a window where
            # only the private key is on disk. Take the lock before classifying the situation.
            locked_exclusively = False
            if lock_file:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    locked_exclusively = True
                except (OSError, IOError):
                    pass  # Continue without exclusive lock
            private_key_ready = _keypair_file_ready(_private_key_path)
            public_key_ready = _keypair_file_ready(_public_key_path)
            if private_key_ready and public_key_ready:
                # The pair was written while this process waited. Its identity has to be taken now,
                # before the read: the stat done on entry saw the directory incomplete.
                stamp = _keypair_stamp()
                private_key, public_key = _read_keypair_locked(lock_file)
            elif private_key_ready:
                # The public key is fully determined by the private one, so this half of the
                # inconsistency is repairable: rebuilding it recovers a write interrupted between
                # its two files, or a partial restore, without rotating the keypair and without
                # ending a single session. It also covers a writer caught mid-write when no lock
                # could be taken, since `_write_new_keypair` stores the private key first and the
                # key rebuilt here is the very one it is about to write.
                private_key, public_key = _restore_public_key(persist=locked_exclusively)
                stamp = _keypair_stamp() if locked_exclusively else None
            elif public_key_ready:
                # Nothing can be derived from a public key. Creating a pair here would silently
                # rotate the keys and end every session in every process, so report the
                # inconsistency instead of hiding it behind a rotation nobody asked for, and name
                # the file: 6003 alone gives an operator nothing to act on.
                #
                # Only the exclusive lock makes the diagnosis conclusive. Without it, a routine
                # rotation looks identical: `_write_new_keypair` truncates the private key before
                # writing it, so for an instant the private half is empty while the public one
                # still holds the previous key. Telling an operator to restore from a backup
                # because of that would be a false alarm.
                if locked_exclusively:
                    remediation = (f"Restore '{_private_key_path}' from a backup, or remove "
                                   f"'{_public_key_path}' to have a new keypair generated, which will "
                                   f"end every active session")
                    logging.getLogger('wazuh-api').error(
                        f"Incomplete JWT keypair: '{_private_key_path}' is missing or empty while "
                        f"'{_public_key_path}' holds a key. {remediation}."
                    )
                    raise WazuhInternalError(6003,
                                             extra_message=f"'{_private_key_path}' is missing or empty "
                                                           f"while '{_public_key_path}' holds a key",
                                             extra_remediation=remediation)

                logging.getLogger('wazuh-api').debug(
                    f"'{_private_key_path}' is missing or empty while '{_public_key_path}' holds a "
                    f"key, and the exclusive lock could not be taken to tell a keypair being "
                    f"written from an incomplete one."
                )
                raise WazuhInternalError(6003, extra_message=f"'{_private_key_path}' is missing or "
                                                             f"empty, or is being written")
            else:
                private_key, public_key = _write_new_keypair()
                # Stamping after the write is only sound while the exclusive lock is held: no
                # rotation can have slipped in between. Without the lock there is no identity that
                # can be trusted, so the entry is left uncached and the next call reads again.
                stamp = _keypair_stamp() if locked_exclusively else None
    except IOError:
        raise WazuhInternalError(6003)
    finally:
        if lock_file:
            lock_file.close()

    keypair = (private_key, public_key)
    # `stamp` is None when the identity of these files could not be established: they were written
    # by this very call and no lock protected the window in which they had to be stat'ed. There is
    # nothing to invalidate such an entry against, and None is also what `_keypair_stamp()` returns
    # once the files are gone, so caching it would keep serving a keypair that no longer exists.
    # Whatever is already cached is left alone rather than overwritten with None: it carries a stamp
    # of its own and is checked against the disk on the next call, and another thread may have just
    # stored it.
    if stamp is not None:
        _keypair_cache = (stamp, keypair, time.monotonic() + _KEYPAIR_CACHE_TTL)

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


def _restore_public_key(persist):
    """Rebuild a missing public key from the surviving private key.

    Reachable when a write was interrupted after truncating or creating the public key file, when a
    restore brought back only one of the two files, or -- with no lock held -- while another process
    is between the two writes of `_write_new_keypair`. The public key carries no information the
    private key does not, so rebuilding it is not a rotation: every active session stays valid.

    Parameters
    ----------
    persist : bool
        Whether the rebuilt key may be stored. Only true while the exclusive lock is held: without
        it another process may be writing the pair, and truncating the public key file here would
        let a concurrent reader, which holds a shared lock at most, pick up an empty key.

    Returns
    -------
    tuple
        (private_key, public_key) strings.

    Raises
    ------
    WazuhInternalError(6003)
        If the surviving private key cannot be loaded.
    """
    with open(_private_key_path, mode='r') as key_file:
        private_key = key_file.read()

    try:
        key_obj = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)
    # `UnsupportedAlgorithm` is neither a `ValueError` nor an `OSError`, so it would otherwise reach
    # the API untranslated.
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise WazuhInternalError(6003, extra_message=f"'{_public_key_path}' is missing and "
                                                     f"'{_private_key_path}' cannot be loaded to "
                                                     f"rebuild it") from exc

    public_key = key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    if persist:
        with open(_public_key_path, mode='w') as key_file:
            key_file.write(public_key)

        try:
            os.chown(_public_key_path, wazuh_uid(), wazuh_gid())
        except PermissionError:
            pass
        # Guarded here, unlike in `_write_new_keypair`: the key has already been written and is
        # correct, so raising would discard a repair that succeeded and repeat it on every call,
        # and what it would be protecting is the public half of the pair.
        try:
            os.chmod(_public_key_path, 0o640)
        except PermissionError:
            pass

        logging.getLogger('wazuh-api').warning(
            f"Rebuilt the missing JWT public key '{_public_key_path}' from '{_private_key_path}'. "
            f"Active sessions are unaffected."
        )
    else:
        # Not a warning: with no lock held this is most often a writer caught between its two
        # files, which is transient and would flood the log at request rate.
        logging.getLogger('wazuh-api').debug(
            f"Rebuilt the missing JWT public key '{_public_key_path}' in memory, since the "
            f"exclusive lock needed to store it could not be taken."
        )

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
                # Only the role rule is asked for here: `is_token_valid` reads one row per
                # argument it is given, and the user and run_as rules were checked just above.
                for role in set(user_roles) | set(roles):
                    if not tm.is_token_valid(role_id=role, token_nbf_time=int(token_nbf_time)):
                        return {'valid': False}

    policies = get_optimized_policies(roles=roles, origin_node_type=origin_node_type)

    # Shallow copy: it isolates the cached entry from the top-level `rbac_mode` key the caller adds
    # (see `decode_token`), which is the only mutation on this path, and which on the master path
    # would otherwise land on the cached dictionary `get_optimized_policies` hands back. The nested
    # per-action dictionaries stay shared with the cache, so no caller may mutate them in place.
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
