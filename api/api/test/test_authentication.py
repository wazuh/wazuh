# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import json
import os
import sys
from copy import deepcopy
from unittest.mock import patch, MagicMock, ANY, call

from cachetools import TTLCache
from connexion.exceptions import Unauthorized

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

    generate_keypair.cache_clear()

    # Test reading existing keys
    with patch('os.path.exists', return_value=True):
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read = MagicMock(side_effect=['priv_key', 'pub_key'])
            mock_file.fileno = MagicMock(return_value=99)
            mock_open.return_value = mock_file

            result = generate_keypair()
            assert result == ('priv_key', 'pub_key')


def test_generate_keypair_ko():
    """Verify expected exception is raised when IOError"""
    with patch('builtins.open'):
        with patch('os.chmod'):
            with patch('api.authentication.wazuh_uid', return_value=0):
                with patch('api.authentication.wazuh_gid', return_value=0):
                    with patch('os.chown', side_effect=PermissionError):
                        assert generate_keypair()


@patch("api.authentication._write_new_keypair", return_value=("priv", "pub"))
@patch("os.path.exists", return_value=False)
def test_generate_keypair_cache_no_keys(mock_exists, mock_write_keypair):
    """Verify caching works when keys don't exist"""
    first = generate_keypair()
    cached = generate_keypair()

    assert first == ("priv", "pub")
    assert first is cached

    # First call checks both private and public key paths, then both again under the lock
    assert mock_exists.call_count == 3
    # But _write_new_keypair is called only once due to caching
    mock_write_keypair.assert_called_once()

@patch("os.path.exists", return_value=True)
def test_generate_keypair_cache(mock_exists, clear_generate_keypair_cache):
    """Verify caching works when keys exist"""
    with patch('builtins.open', create=True) as mock_open:
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=mock_file)
        mock_file.__exit__ = MagicMock(return_value=False)
        mock_file.read = MagicMock(side_effect=["priv", "pub"])
        mock_file.fileno = MagicMock(return_value=99)
        mock_open.return_value = mock_file

        first = generate_keypair()
        cached = generate_keypair()

        assert first == ("priv", "pub")
        assert first is cached

        assert mock_exists.call_count == 2
        # Should read files twice (private + public) only once due to caching
        assert mock_file.read.call_count == 2

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
    tm.is_token_valid.assert_any_call(role_id=1, user_id=101, token_nbf_time=200, run_as=True)


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


def test_generate_keypair_half_present_ko(tmp_path):
    """A keypair with one file missing must be reported instead of silently rotated.

    Creating one here would replace the surviving key and end every session in every process, which
    is a much worse outcome for a half-restored install than a failed request.
    """
    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'
    private_path.write_text('old_priv')

    with patch('api.authentication._private_key_path', str(private_path)), \
            patch('api.authentication._public_key_path', str(public_path)), \
            patch('api.authentication._keypair_lock_path', str(tmp_path / '.keypair.lock')), \
            patch('api.authentication._write_new_keypair') as mock_write_keypair:
        with pytest.raises(WazuhInternalError) as exc_info:
            generate_keypair()

    assert exc_info.value.code == 6003
    mock_write_keypair.assert_not_called()
    assert private_path.read_text() == 'old_priv'
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
