# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import hashlib
import json
import os
import sys
import threading
import time
from copy import deepcopy
from unittest.mock import patch, MagicMock, ANY, call

from cachetools import TTLCache
from connexion.exceptions import Unauthorized
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.results import WazuhResult

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.utils as rbac_utils
        from wazuh.core.exception import WazuhInternalError
        from api.authentication import (generate_keypair, check_user_master, check_user, change_keypair,
                                        _private_key_path, _public_key_path, wazuh_uid, wazuh_gid, get_security_conf,
                                        generate_token, check_token, decode_token, get_optimized_policies)
        del sys.modules['wazuh.rbac.orm']


test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')

security_conf = WazuhResult({
    'auth_token_exp_timeout': 900,
    'rbac_mode': 'black'
})
decoded_payload = {
    "iss": 'wazuh',
    "aud": 'Wazuh API REST',
    "nbf": 0,
    "nbf_ms": 0,
    "exp": security_conf['auth_token_exp_timeout'],
    "sub": '001',
    "rbac_policies": {'value': 'test', 'rbac_mode': security_conf['rbac_mode']},
    "rbac_roles": [1],
    'run_as': False
}

original_payload = {
    "iss": "wazuh",
    "aud": "Wazuh API REST",
    "nbf": 0,
    "nbf_ms": 0,
    "exp": security_conf['auth_token_exp_timeout'],
    "sub": "001",
    "run_as": False,
    "rbac_roles": [1],
    "rbac_mode": security_conf['rbac_mode']
}

@pytest.fixture(autouse=True)
def clear_generate_keypair_cache():
    generate_keypair.cache_clear()


@pytest.fixture(autouse=True)
def clear_policies_cache():
    """Keep the module-level policies cache from leaking between tests."""
    rbac_utils.POLICIES_CACHE.clear()
    yield
    rbac_utils.POLICIES_CACHE.clear()

def test_check_user_master():
    result = check_user_master('test_user', 'test_pass')
    assert result == {'result': True}


@pytest.mark.asyncio
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_check_user(mock_raise_if_exc, mock_distribute_function, mock_dapi):
    """Verify if result is as expected"""
    result = check_user('test_user', 'test_pass')

    assert result == {'sub': 'test_user', 'active': True}, 'Result is not as expected'
    mock_dapi.assert_called_once_with(f=ANY, f_kwargs={'user': 'test_user', 'password': 'test_pass'},
                                      request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()


@patch('api.authentication._write_new_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                               '-----BEGIN PUBLIC KEY-----'))
def test_generate_keypair(mock_write_keypair):
    """Verify generate_keypair creates keys when they don't exist"""
    with patch('os.path.exists', return_value=False):
        result = generate_keypair()
        assert result == ('-----BEGIN PRIVATE KEY-----',
                          '-----BEGIN PUBLIC KEY-----')
        mock_write_keypair.assert_called_once()


def test_generate_keypair_reads_existing_keys(tmp_path):
    """Verify generate_keypair reads the keys already on disk instead of creating new ones."""
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('priv_key')
    public_path.write_text('pub_key')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        assert generate_keypair() == ('priv_key', 'pub_key')

    mock_write_keypair.assert_not_called()


def test_generate_keypair_ko():
    """Verify expected exception is raised when IOError"""
    with patch('builtins.open'):
        with patch('os.chmod'):
            with patch('api.authentication.wazuh_uid', return_value=0):
                with patch('api.authentication.wazuh_gid', return_value=0):
                    with patch('os.chown', side_effect=PermissionError):
                        assert generate_keypair()


def test_generate_keypair_cache_no_keys(tmp_path):
    """Verify caching works when the keys have to be created."""
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'

    def write_keypair():
        private_path.write_text('priv')
        public_path.write_text('pub')
        return 'priv', 'pub'

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair', side_effect=write_keypair) as mock_write_keypair:
        first = generate_keypair()
        cached = generate_keypair()

    assert first == ('priv', 'pub')
    assert first is cached
    # The keys written by the first call are read from the cache by the second one.
    mock_write_keypair.assert_called_once()

def test_generate_keypair_cache(tmp_path):
    """Verify caching works when keys exist."""
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('priv')
    public_path.write_text('pub')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')):
        first = generate_keypair()
        cached = generate_keypair()

    assert first == ('priv', 'pub')
    # A re-read would build a new tuple, so identity is what proves the second call was a hit.
    assert first is cached

@patch('api.authentication._write_new_keypair', return_value=('new_priv', 'new_pub'))
def test_change_keypair(mock_write_keypair):
    """Verify change_keypair generates new keys and clears cache"""
    result = change_keypair()
    assert isinstance(result[0], str)
    assert isinstance(result[1], str)
    assert result == ('new_priv', 'new_pub')
    mock_write_keypair.assert_called_once()


def test_get_security_conf():
    """Check that returned object is as expected"""
    result = get_security_conf()
    assert isinstance(result, dict)
    assert all(x in result.keys() for x in ('auth_token_exp_timeout', 'rbac_mode'))


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_context', [{'name': 'initial_auth'}, None])
@patch('api.authentication.jwt.encode', return_value='test_token')
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_generate_token(mock_raise_if_exc, mock_distribute_function, mock_dapi, mock_generate_keypair,
                        mock_encode, auth_context):
    """Verify if result is as expected"""

    class NewDatetime:
        def timestamp(self) -> float:
            return 0

    mock_raise_if_exc.return_value = security_conf
    with patch('api.authentication.core_utils.get_utc_now', return_value=NewDatetime()):
        result = generate_token(user_id='001', data={'roles': [1]}, auth_context=auth_context)
    assert result == 'test_token', 'Result is not as expected'

    # Check all functions are called with expected params
    mock_dapi.assert_called_once_with(f=ANY, request_type='local_master', is_async=False, wait_for_complete=False,
                                      logger=ANY)
    mock_distribute_function.assert_called_once_with()
    mock_raise_if_exc.assert_called_once()
    mock_generate_keypair.assert_called_once()
    expected_payload = original_payload | (
        {"hash_auth_context": hashlib.blake2b(json.dumps(auth_context).encode(),
                                              digest_size=16).hexdigest(), "run_as": True} if auth_context is not None else {})
    mock_encode.assert_called_once_with(expected_payload, '-----BEGIN PRIVATE KEY-----', algorithm='ES512')


@patch('api.authentication.TokenManager')
def test_check_token(mock_tokenmanager):
    result = check_token(username='wazuh_user', roles=tuple([1]), token_nbf_time=3600, run_as=False,
                                        origin_node_type='master')
    assert result == {'valid': ANY, 'policies': ANY}


def _orm_manager_mock(instance):
    """Return a MagicMock whose context-manager protocol yields `instance`."""
    manager = MagicMock()
    manager.return_value.__enter__.return_value = instance
    return manager


@patch('api.authentication.optimize_resources', return_value={})
def test_check_token_runas_revoked_at_user_level(mock_optimize):
    """A run_as user with no statically-linked roles must be validated against the token blacklist.

    This covers logout and user-level revocation, whose blacklist entry is keyed on the user and
    was never consulted when the per-role loop iterated over an empty user_roles list.
    """
    am = MagicMock()
    am.get_user.return_value = {'id': 101, 'username': 'rauser'}
    am.user_allow_run_as.return_value = True
    urm = MagicMock()
    urm.get_all_roles_from_user.return_value = []
    tm = MagicMock()
    tm.is_token_valid.return_value = False

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        result = check_token(username='rauser', roles=tuple([1]), token_nbf_time=100,
                                            run_as=True, origin_node_type='master')

    assert result == {'valid': False}
    tm.is_token_valid.assert_any_call(user_id=101, token_nbf_time=100, run_as=True)


@patch('api.authentication.optimize_resources', return_value={})
def test_check_token_runas_revoked_dynamic_role(mock_optimize):
    """Revoking a dynamically-granted role must invalidate a run_as token carrying it.

    The role travels in the token (roles) and is absent from user_roles, so the validity check
    must be driven by the token's roles, not only the statically-linked ones.
    """
    am = MagicMock()
    am.get_user.return_value = {'id': 101, 'username': 'rauser'}
    am.user_allow_run_as.return_value = True
    urm = MagicMock()
    urm.get_all_roles_from_user.return_value = []
    tm = MagicMock()
    tm.is_token_valid.side_effect = lambda **kwargs: kwargs.get('role_id') != 1

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        result = check_token(username='rauser', roles=tuple([1]), token_nbf_time=200,
                                            run_as=True, origin_node_type='master')

    assert result == {'valid': False}
    # The user and run_as rules are checked once, before the loop; the role iterations ask only
    # for the role rule so that they do not re-read the same two rows per role.
    tm.is_token_valid.assert_any_call(user_id=101, token_nbf_time=200, run_as=True)
    tm.is_token_valid.assert_any_call(role_id=1, token_nbf_time=200)


def _authentication_mocks(user, roles, token_valid=True):
    """Build the ORM manager mocks `check_token` reads its decision from."""
    am = MagicMock()
    am.get_user.return_value = user
    am.user_allow_run_as.return_value = False
    urm = MagicMock()
    urm.get_all_roles_from_user.return_value = [MagicMock(id=role) for role in roles]
    tm = MagicMock()
    tm.is_token_valid.return_value = token_valid
    return am, urm, tm


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_check_token_not_cached_after_user_deletion(mock_optimize):
    """A token whose account has been deleted must be refused on the very next request.

    Regression for the authorisation bypass: `check_token` used to be memoized under a TTL equal to
    the token lifetime, so once a token had been used enough times to be cached, deleting the
    account (or changing its password) did not end the session. No invalidation is signalled here
    on purpose: the identity check must run unconditionally, whether or not the cache was flushed.
    """
    am, urm, tm = _authentication_mocks({'id': 101, 'username': 'qattl'}, roles=[1])

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        # Warm whatever caches exist, as a token in real use would.
        for _ in range(5):
            assert check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                               origin_node_type='master') == {'valid': True, 'policies': {'policy': 'test'}}

        # The account is deleted. Nothing else changes and nothing is invalidated.
        am.get_user.return_value = None

        assert check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                           origin_node_type='master') == {'valid': False}


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_check_token_not_cached_after_token_revocation(mock_optimize):
    """A blacklisted token must be refused on the next request, without an invalidation signal."""
    am, urm, tm = _authentication_mocks({'id': 101, 'username': 'qattl'}, roles=[1])

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        for _ in range(5):
            assert check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                               origin_node_type='master')['valid'] is True

        tm.is_token_valid.return_value = False

        assert check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                           origin_node_type='master') == {'valid': False}


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_check_token_caches_only_the_policies(mock_optimize):
    """The policy preprocessing is cached; the validity checks are re-read on every request."""
    am, urm, tm = _authentication_mocks({'id': 101, 'username': 'qattl'}, roles=[1])

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        for _ in range(3):
            check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                        origin_node_type='master')

    assert mock_optimize.call_count == 1, 'The expensive policy preprocessing must still be cached'
    assert am.get_user.call_count == 3, 'The identity must be re-read on every request'
    assert tm.is_token_valid.call_count >= 3, 'The blacklist must be consulted on every request'


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_check_token_does_not_return_the_cached_policies(mock_optimize):
    """The returned policies must not alias the cached entry, which `decode_token` mutates."""
    am, urm, tm = _authentication_mocks({'id': 101, 'username': 'qattl'}, roles=[1])

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        first = check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                            origin_node_type='master')
        first['policies']['rbac_mode'] = 'black'

        second = check_token(username='qattl', roles=tuple([1]), token_nbf_time=100, run_as=False,
                             origin_node_type='master')

    assert second['policies'] == {'policy': 'test'}


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_get_optimized_policies_invalidated_across_processes(mock_optimize):
    """One revocation must flush the policies cache of every process, not only the first reader."""
    cache_a = TTLCache(maxsize=10, ttl=900)
    cache_b = TTLCache(maxsize=10, ttl=900)
    lookup_a = rbac_utils.policies_cache(cache=cache_a)(get_optimized_policies.__wrapped__)
    lookup_b = rbac_utils.policies_cache(cache=cache_b)(get_optimized_policies.__wrapped__)

    assert lookup_a(roles=(1,), origin_node_type='master') == {'policy': 'test'}
    assert lookup_b(roles=(1,), origin_node_type='master') == {'policy': 'test'}
    assert mock_optimize.call_count == 2

    mock_optimize.return_value = {'policy': 'updated'}
    rbac_utils.clear_tokens_cache()

    assert lookup_a(roles=(1,), origin_node_type='master') == {'policy': 'updated'}
    assert lookup_b(roles=(1,), origin_node_type='master') == {'policy': 'updated'}


def test_generate_keypair_cache_read_survives_a_concurrent_clear(tmp_path):
    """A rotation landing mid-read must not break the request that was reading the cache.

    `cache_clear()` sets the cached entry to None and runs on another thread of this process
    whenever the API falls back to a single thread pool for local requests, so the entry has to be
    bound once rather than re-read between the guard and each subscript.
    """
    authentication = sys.modules['api.authentication']

    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('priv')
    public_path.write_text('pub')

    class ClearingEntry(tuple):
        """Cache entry that is dropped from under the reader as soon as it is subscripted."""

        def __getitem__(self, index):
            authentication._keypair_cache = None
            return tuple.__getitem__(self, index)

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')):
        first = generate_keypair()
        authentication._keypair_cache = ClearingEntry(authentication._keypair_cache)

        assert generate_keypair() == first


def test_generate_keypair_reloads_after_rotation(tmp_path):
    """A keypair rotated by another process must be picked up instead of masked by the cache.

    Regression for GHSA-g66v-pj9q-26fw: `generate_keypair` was a plain `functools.cache` cleared
    only in the process that handled the rotation, so `PUT /security/user/revoke` left every other
    process signing and verifying with the superseded keys.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('old_priv')
    public_path.write_text('old_pub')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)):
        assert generate_keypair() == ('old_priv', 'old_pub')
        # Served from this process's cache while the files are untouched.
        assert generate_keypair() == ('old_priv', 'old_pub')

        # Another process rotates the keys. Nothing clears this process's cache.
        private_path.write_text('new_priv')
        public_path.write_text('new_pub')
        os.utime(private_path, ns=(2 * 10 ** 9, 2 * 10 ** 9))
        os.utime(public_path, ns=(2 * 10 ** 9, 2 * 10 ** 9))

        assert generate_keypair() == ('new_priv', 'new_pub')


def test_generate_keypair_reloads_after_indistinguishable_rotation(tmp_path):
    """A rotation the stamp cannot tell apart from the previous one must not be masked for good.

    `_write_new_keypair` rewrites both files in place and PEM-encoded SECP521R1 keys are
    fixed-length, so neither the inode nor the size ever changes. Two rotations landing in the same
    `st_mtime_ns` tick, or a restore that preserves timestamps, therefore share a stamp. The cache
    entry's lifetime is what keeps this process from rejecting every token signed with the current
    key until it restarts.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('old_priv')
    public_path.write_text('old_pub')
    frozen_ns = 7 * 10 ** 9
    os.utime(private_path, ns=(frozen_ns, frozen_ns))
    os.utime(public_path, ns=(frozen_ns, frozen_ns))

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')):
        assert generate_keypair() == ('old_priv', 'old_pub')

        # Another process rotates the keys, leaving the stamp exactly as it was.
        private_path.write_text('new_priv')
        public_path.write_text('new_pub')
        os.utime(private_path, ns=(frozen_ns, frozen_ns))
        os.utime(public_path, ns=(frozen_ns, frozen_ns))

        # Stale while the entry is still live: the bounded window, not the fix.
        assert generate_keypair() == ('old_priv', 'old_pub')

        # Once the entry's lifetime is up the files are read again, stamp or no stamp.
        with patch('api.authentication.time') as mock_time:
            mock_time.monotonic.return_value = float('inf')
            assert generate_keypair() == ('new_priv', 'new_pub')


def test_generate_keypair_orphan_public_key_ko(tmp_path):
    """A public key whose private counterpart is missing must be reported, not rotated.

    Nothing can be derived from a public key, and creating a pair here would replace it and end
    every session in every process, which is a much worse outcome for a half-restored install than
    a failed request.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    public_path.write_text('old_pub')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    # The generic 6003 message leaves an operator with nothing to act on, so the missing file is
    # named in the error and in the log.
    assert str(private_path) in exc_info.value.message
    mock_write_keypair.assert_not_called()
    assert public_path.read_text() == 'old_pub'
    assert not private_path.exists()


def _build_keypair():
    """Build a PEM keypair of the same kind `_write_new_keypair` stores.

    Returns
    -------
    tuple
        (private_key, public_key) strings.
    """
    key_obj = ec.generate_private_key(ec.SECP521R1())
    private_pem = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def test_generate_keypair_rebuilds_a_missing_public_key(tmp_path):
    """A missing public key must be rebuilt from the private one instead of failing every request.

    The public key carries nothing the private key does not, so an install left half-written by an
    interrupted `_write_new_keypair` recovers without rotating the keypair, which would have ended
    every active session.
    """
    private_pem, public_pem = _build_keypair()
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text(private_pem)

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication.wazuh_uid', return_value=0), \
            patch('api.authentication.wazuh_gid', return_value=0), \
            patch('os.chown'), patch('os.chmod'), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        assert generate_keypair() == (private_pem, public_pem)

    mock_write_keypair.assert_not_called()
    assert private_path.read_text() == private_pem
    assert public_path.read_text() == public_pem


def test_generate_keypair_unloadable_private_key_ko(tmp_path):
    """A private key that cannot be loaded cannot be used to rebuild the public one either."""
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('not a PEM')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    mock_write_keypair.assert_not_called()
    assert not public_path.exists()


def test_generate_keypair_waits_for_a_concurrent_writer(tmp_path):
    """A keypair in the middle of being written must not be reported as half-present.

    `_write_new_keypair` creates the two files one after the other, so a reader that classifies the
    directory before taking the exclusive lock can catch the writer between both calls and answer
    6003 to a request that only had to wait for the lock.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    lock_path = tmp_path / '.keypair.lock'
    half_written = threading.Event()

    def write_keypair():
        with open(lock_path, 'a+') as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            private_path.write_text('new_priv')
            half_written.set()
            time.sleep(0.5)
            public_path.write_text('new_pub')
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    writer = threading.Thread(target=write_keypair)
    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(lock_path)), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        writer.start()
        assert half_written.wait(timeout=5)
        try:
            assert generate_keypair() == ('new_priv', 'new_pub')
        finally:
            writer.join()

    mock_write_keypair.assert_not_called()


def test_generate_keypair_rebuilds_without_persisting_when_unlocked(tmp_path):
    """A public key rebuilt without the exclusive lock must not be written to disk.

    The lock is best-effort, and holding it is what proves no other process is between the two
    writes of `_write_new_keypair`. Truncating the public key file without it would let a concurrent
    reader, which holds a shared lock at most, pick up an empty key.
    """
    private_pem, public_pem = _build_keypair()
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text(private_pem)

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / 'absent' / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        assert generate_keypair() == (private_pem, public_pem)

    mock_write_keypair.assert_not_called()
    assert not public_path.exists()


def test_generate_keypair_rebuilds_a_truncated_public_key(tmp_path):
    """A public key file left empty by an interrupted write must be rebuilt, not read.

    Every writer truncates before writing, so the realistic artefact of an interrupted rotation is a
    zero-byte file rather than a missing one, and reading it yields a key nothing can verify with.
    """
    private_pem, public_pem = _build_keypair()
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text(private_pem)
    public_path.write_text('')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication.wazuh_uid', return_value=0), \
            patch('api.authentication.wazuh_gid', return_value=0), \
            patch('os.chown'), patch('os.chmod'), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        assert generate_keypair() == (private_pem, public_pem)

    mock_write_keypair.assert_not_called()
    assert public_path.read_text() == public_pem


def test_generate_keypair_rebuild_survives_a_failed_chmod(tmp_path):
    """A repair that already wrote the key must not be discarded by the permissions call.

    Raising there would throw away a rebuild that succeeded and repeat it on every request, over a
    file that is correct on disk.
    """
    private_pem, public_pem = _build_keypair()
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text(private_pem)

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication.wazuh_uid', return_value=0), \
            patch('api.authentication.wazuh_gid', return_value=0), \
            patch('os.chown', side_effect=PermissionError), \
            patch('os.chmod', side_effect=PermissionError), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        assert generate_keypair() == (private_pem, public_pem)

    mock_write_keypair.assert_not_called()
    assert public_path.read_text() == public_pem


def test_generate_keypair_rotation_in_progress_is_not_reported_as_broken(tmp_path):
    """An empty private key must not be called a broken install when no lock could be taken.

    `_write_new_keypair` truncates the private key before writing it, so a rotation in flight looks
    exactly like an install that lost its private key. Only the exclusive lock tells them apart, and
    telling an operator to restore from a backup because of a routine rotation is a false alarm.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('')
    public_path.write_text('old_pub')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / 'absent' / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    assert 'is being written' in exc_info.value.message
    assert 'Restore' not in (exc_info.value.remediation or '')
    mock_write_keypair.assert_not_called()


def test_generate_keypair_truncated_private_key_ko(tmp_path):
    """A private key file left empty must be reported, not treated as a key that is there."""
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('')
    public_path.write_text('old_pub')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    assert str(private_path) in exc_info.value.message
    # Held the lock, so the diagnosis is conclusive and says what to do about it.
    assert f"Restore '{private_path}'" in exc_info.value.remediation
    mock_write_keypair.assert_not_called()
    assert public_path.read_text() == 'old_pub'


def test_generate_keypair_unlocked_rebuild_keeps_the_cached_entry(tmp_path):
    """A call that cannot stamp what it built must leave the cache alone, not blank it.

    The entry it would overwrite carries a stamp of its own and is checked against the disk on the
    next call, and another thread may have stored it moments earlier.
    """
    authentication = sys.modules['api.authentication']
    private_pem, public_pem = _build_keypair()
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text(private_pem)
    entry = ('stamp-stored-by-another-thread', ('priv', 'pub'), time.monotonic() + 5)

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / 'absent' / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        authentication._keypair_cache = entry
        # Nothing can be persisted or stamped without the lock, so the rebuilt key is used as is.
        assert generate_keypair() == (private_pem, public_pem)
        assert authentication._keypair_cache == entry

    mock_write_keypair.assert_not_called()
    assert not public_path.exists()


def test_generate_keypair_unsupported_private_key_ko(tmp_path):
    """`UnsupportedAlgorithm` is neither a ValueError nor an OSError, so it needs its own handling.

    Left untranslated it would reach the API as an unhandled exception instead of a 6003.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('irrelevant, the loader is mocked')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication.serialization.load_pem_private_key',
                  side_effect=UnsupportedAlgorithm('unsupported curve')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    mock_write_keypair.assert_not_called()
    assert not public_path.exists()


@patch('api.authentication.optimize_resources', return_value={'policy': 'test'})
def test_check_token_runas_valid(mock_optimize):
    """A run_as user with a non-revoked token remains valid."""
    am = MagicMock()
    am.get_user.return_value = {'id': 101, 'username': 'rauser'}
    am.user_allow_run_as.return_value = True
    urm = MagicMock()
    urm.get_all_roles_from_user.return_value = []
    tm = MagicMock()
    tm.is_token_valid.return_value = True

    with patch('api.authentication.AuthenticationManager', _orm_manager_mock(am)), \
            patch('api.authentication.UserRolesManager', _orm_manager_mock(urm)), \
            patch('api.authentication.TokenManager', _orm_manager_mock(tm)):
        result = check_token(username='rauser', roles=tuple([1]), token_nbf_time=300,
                                            run_as=True, origin_node_type='master')

    assert result == {'valid': True, 'policies': {'policy': 'test'}}


@pytest.mark.asyncio
@patch('api.authentication.jwt.decode')
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', return_value=True)
@patch('api.authentication.raise_if_exc', side_effect=None)
async def test_decode_token(mock_raise_if_exc, mock_distribute_function, mock_dapi, mock_generate_keypair,
                      mock_decode):

    mock_decode.return_value = deepcopy(original_payload)
    mock_raise_if_exc.side_effect = [WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                     WazuhResult(security_conf)]

    result = decode_token('test_token')
    assert result == decoded_payload

    # Check all functions are called with expected params
    calls = [call(f=ANY, f_kwargs={'username': original_payload['sub'], 'token_nbf_time': int(original_payload['nbf'] * 1000),
                                   'run_as': False, 'roles': tuple(original_payload['rbac_roles']),
                                   'origin_node_type': 'master'},
                  request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY),
             call(f=ANY, request_type='local_master', is_async=False, wait_for_complete=False, logger=ANY)]
    mock_dapi.assert_has_calls(calls)
    mock_generate_keypair.assert_called_once()
    mock_decode.assert_called_once_with('test_token', '-----BEGIN PUBLIC KEY-----',
                                        algorithms=['ES512'],
                                        audience='Wazuh API REST')
    assert mock_distribute_function.call_count == 2
    assert mock_raise_if_exc.call_count == 2


@pytest.mark.asyncio
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function', side_effect=None)
@patch('api.authentication.raise_if_exc', side_effect=None)
@patch('api.authentication.generate_keypair', return_value=('-----BEGIN PRIVATE KEY-----',
                                                            '-----BEGIN PUBLIC KEY-----'))
async def test_decode_token_ko(mock_generate_keypair, mock_raise_if_exc, mock_distribute_function):
    """Assert exceptions are handled as expected inside decode_token()"""
    with pytest.raises(Unauthorized):
        decode_token(token='test_token')

    with patch('api.authentication.jwt.decode') as mock_decode:
        with patch('api.authentication.generate_keypair',
                   return_value=('-----BEGIN PRIVATE KEY-----',
                                 '-----BEGIN PUBLIC KEY-----')):
            with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.__init__', return_value=None):
                with patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.distribute_function'):
                    with patch('api.authentication.raise_if_exc') as mock_raise_if_exc:
                        mock_decode.return_value = deepcopy(original_payload)

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [WazuhResult({'valid': False})]
                            decode_token(token='test_token')

                        with pytest.raises(Unauthorized):
                            mock_raise_if_exc.side_effect = [
                                WazuhResult({'valid': True, 'policies': {'value': 'test'}}),
                                WazuhResult({'auth_token_exp_timeout': 900,
                                             'rbac_mode': 'white'})]
                            decode_token(token='test_token')
