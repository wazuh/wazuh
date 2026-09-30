#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import statistics
from unittest.mock import MagicMock, patch
from sqlalchemy.exc import OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

import pytest


class MockUser:
    """Mock User object for testing."""
    def __init__(self, username, password_hash, user_id=1):
        self.id = user_id
        self.username = username
        self.password = password_hash


class TestCheckUserConsistency:
    """Test suite to verify check_user() follows consistent code paths."""

    def test_valid_credentials_return_true(self):
        """Verify that valid username and password return True."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        real_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        mock_result.first.return_value = MockUser("admin", real_hash)
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "admin", real_password)

        assert result is True, "Valid credentials should return True"

    def test_valid_user_wrong_password_returns_false(self):
        """Verify that valid username with wrong password returns False."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        real_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        mock_result.first.return_value = MockUser("admin", real_hash)
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "admin", "wrong_password")

        assert result is False, "Wrong password should return False"

    def test_invalid_user_returns_false(self):
        """Verify that non-existent username returns False."""
        from wazuh.rbac.orm import AuthenticationManager

        manager = MagicMock()
        mock_result = MagicMock()
        mock_result.first.return_value = None
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "nonexistent_user", "any_password")

        assert result is False, "Non-existent user should return False"

    @pytest.mark.parametrize('username,password,user_exists', [
        ('admin', 'test123', True),
        ('wazuh', 'wazuh456', True),
        ('user001', 'pass789', False),
        ('invalid_user', 'any_password', False),
    ])
    def test_various_username_password_combinations(self, username, password, user_exists):
        """Test various username/password combinations execute consistent code path."""
        from wazuh.rbac.orm import AuthenticationManager

        real_hash = generate_password_hash(password)

        manager = MagicMock()
        mock_result = MagicMock()
        manager.session.scalars.return_value = mock_result

        if user_exists:
            mock_result.first.return_value = MockUser(username, real_hash)
        else:
            mock_result.first.return_value = None

        result = AuthenticationManager.check_user(manager, username, password)

        assert isinstance(result, bool), f"check_user should always return bool"

    def test_execution_time_consistency(self):
        """Verify that valid and invalid username attempts take similar time."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "test_password_123"
        real_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        manager.session.scalars.return_value = mock_result

        # Measure timing for valid username
        valid_user_times = []
        for _ in range(5):
            mock_result.first.return_value = MockUser("valid_user", real_hash)

            t0 = time.perf_counter()
            result = AuthenticationManager.check_user(manager, "valid_user", "wrong_password")
            elapsed = (time.perf_counter() - t0) * 1000
            valid_user_times.append(elapsed)

            assert result is False

        valid_median = statistics.median(valid_user_times)

        # Measure timing for invalid username
        invalid_user_times = []
        for _ in range(5):
            mock_result.first.return_value = None

            t0 = time.perf_counter()
            result = AuthenticationManager.check_user(manager, "invalid_user", "wrong_password")
            elapsed = (time.perf_counter() - t0) * 1000
            invalid_user_times.append(elapsed)

            assert result is False

        invalid_median = statistics.median(invalid_user_times)

        ratio = valid_median / invalid_median if invalid_median > 0 else 1.0

        assert ratio < 2.0, (
            f"Execution time inconsistency detected. "
            f"Valid: {valid_median:.2f}ms, Invalid: {invalid_median:.2f}ms, Ratio: {ratio:.1f}×"
        )

    def test_dummy_hash_constant_exists(self):
        """Verify that _DUMMY_HASH constant is defined."""
        from wazuh.rbac.orm import _DUMMY_HASH

        assert _DUMMY_HASH is not None
        assert isinstance(_DUMMY_HASH, str)
        assert len(_DUMMY_HASH) > 50, "_DUMMY_HASH should be a bcrypt hash"


LEGACY_METHODS = ['pbkdf2:sha256:150000', 'pbkdf2:sha256:260000']


def _manager_returning(user):
    manager = MagicMock()
    manager.session.scalars.return_value.first.return_value = user
    return manager


class TestCheckUserLegacyHashRehash:
    """Test suite to verify check_user() upgrades legacy password hashes on login."""

    @pytest.mark.parametrize('method', LEGACY_METHODS)
    def test_legacy_hash_rehashed_on_successful_login(self, method):
        """A legacy hash is rehashed to the current default once the password is verified.

        The UPDATE is conditioned on the exact hash that was just verified, so it cannot overwrite a password
        change committed concurrently by another process.
        """
        from wazuh.rbac.orm import AuthenticationManager, _DEFAULT_HASH_PREFIX

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method=method)
        manager = _manager_returning(MockUser("legacy_user", legacy_hash, user_id=42))

        result = AuthenticationManager.check_user(manager, "legacy_user", real_password)

        assert result is True
        manager.session.query.return_value.filter_by.assert_called_once_with(
            id=42, password=legacy_hash)
        update_call = manager.session.query.return_value.filter_by.return_value.update
        update_call.assert_called_once()
        new_hash = update_call.call_args[0][0]['password']
        assert new_hash.startswith(f"{_DEFAULT_HASH_PREFIX}$")
        assert check_password_hash(new_hash, real_password)
        manager.session.commit.assert_called_once()

    def test_legacy_hash_not_rehashed_on_failed_login(self):
        """A legacy hash is left untouched when the password does not match."""
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        legacy_hash = generate_password_hash("correct_password", method=LEGACY_METHODS[0])
        manager = _manager_returning(MockUser("legacy_user", legacy_hash))

        with patch.object(orm_module, "sleep"):
            result = AuthenticationManager.check_user(manager, "legacy_user", "wrong_password")

        assert result is False
        manager.session.query.assert_not_called()
        manager.session.commit.assert_not_called()

    def test_default_hash_not_rehashed(self):
        """A hash already using the current default method is not rewritten on login."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        manager = _manager_returning(MockUser("current_user", generate_password_hash(real_password)))

        result = AuthenticationManager.check_user(manager, "current_user", real_password)

        assert result is True
        manager.session.query.assert_not_called()
        manager.session.commit.assert_not_called()

    def test_legacy_hash_login_succeeds_despite_rehash_write_failure(self):
        """A successful login is not turned into a failure by a rehash write error.

        The rehash is opportunistic; if the database can't be written right now (disk full, rbac.db locked past
        SQLite's busy timeout, read-only file), the login that already passed the real hash check must still succeed.
        """
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method=LEGACY_METHODS[0])
        manager = _manager_returning(MockUser("legacy_user", legacy_hash, user_id=42))
        manager.session.commit.side_effect = OperationalError("UPDATE", {}, Exception("database is locked"))

        result = AuthenticationManager.check_user(manager, "legacy_user", real_password)

        assert result is True
        manager.session.rollback.assert_called_once()


class TestCheckUserFailedCheckFloor:
    """Test suite to verify every failed check_user() call lasts the same calibrated floor."""

    @pytest.mark.parametrize('stored', [None, 'default', *LEGACY_METHODS])
    def test_failed_login_is_padded_to_floor(self, stored):
        """A missing user and a wrong password against any stored format sleep up to the same floor."""
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        if stored is None:
            user = None
        else:
            method = {} if stored == 'default' else {'method': stored}
            user = MockUser("user", generate_password_hash("correct_password", **method))
        manager = _manager_returning(user)

        # 0.02s elapsed against a 0.05s floor: sleep until 2 ms before the deadline, then spin until 10.05
        with patch.object(orm_module, "perf_counter", side_effect=[10.0, 10.02, 10.049, 10.05]), \
                patch.object(orm_module, "_failed_check_floor", return_value=0.05), \
                patch.object(orm_module, "sleep") as mock_sleep:
            result = AuthenticationManager.check_user(manager, "user", "wrong_password")

        assert result is False
        mock_sleep.assert_called_once_with(pytest.approx(0.028))
        manager.session.query.assert_not_called()

    @pytest.mark.parametrize('elapsed', [0.049, 0.08])
    def test_failed_login_near_or_past_floor_does_not_sleep(self, elapsed):
        """A check that ends within 2 ms of the floor only spins, and one that ends past it returns at once."""
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        manager = _manager_returning(None)

        clock = [10.0, 10.0 + elapsed, 10.0 + elapsed, 10.05]
        with patch.object(orm_module, "perf_counter", side_effect=clock) as mock_clock, \
                patch.object(orm_module, "_failed_check_floor", return_value=0.05), \
                patch.object(orm_module, "sleep") as mock_sleep:
            assert AuthenticationManager.check_user(manager, "user", "wrong_password") is False

        mock_sleep.assert_not_called()
        assert mock_clock.call_count == (4 if elapsed < 0.05 else 3)

    @pytest.mark.parametrize('method', [None, *LEGACY_METHODS])
    def test_successful_login_is_not_padded(self, method):
        """A successful login returns as soon as the check (and any rehash) is done."""
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        kwargs = {'method': method} if method else {}
        manager = _manager_returning(MockUser("user", generate_password_hash("correct_password", **kwargs)))

        with patch.object(orm_module, "sleep") as mock_sleep:
            assert AuthenticationManager.check_user(manager, "user", "correct_password") is True

        mock_sleep.assert_not_called()

    def test_floor_covers_slowest_format_and_is_calibrated_once(self):
        """The floor is 1.5 times the median cost of the slowest known format, even when a legacy format costs
        more than the current default, and it is measured only once per process.
        """
        import wazuh.rbac.orm as orm_module

        # Three samples per format, in order: current default, 150000, 260000
        durations = [0.05, 0.05, 0.05, 0.03, 0.03, 0.03, 0.07, 0.09, 0.08]
        clock = []
        for d in durations:
            clock += [0.0, d]

        with patch.object(orm_module, "_failed_check_seconds", None), \
                patch.object(orm_module, "perf_counter", side_effect=clock), \
                patch.object(orm_module, "check_password_hash") as mock_check:
            assert orm_module._failed_check_floor() == pytest.approx(1.5 * 0.08)
            assert orm_module._failed_check_floor() == pytest.approx(1.5 * 0.08)

        assert mock_check.call_count == len(durations)
        checked_methods = {c.args[0].split('$', 1)[0] for c in mock_check.call_args_list}
        assert checked_methods == {orm_module._DEFAULT_HASH_PREFIX, *LEGACY_METHODS}
