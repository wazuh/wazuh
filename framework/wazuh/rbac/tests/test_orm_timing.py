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


class TestCheckUserLegacyHashRehash:
    """Test suite to verify check_user() upgrades legacy password hashes on login."""

    def test_legacy_hash_rehashed_on_successful_login(self):
        """A legacy hash is rehashed to the current default once the password is verified.

        The UPDATE must be a compare-and-swap conditioned on the exact hash that was
        just verified, not a blind write of `user`, so it can't clobber a password
        change committed concurrently by another process between the read and this
        write (see the race this guards against in orm.py).
        """
        from wazuh.rbac.orm import AuthenticationManager, _DEFAULT_HASH_METHOD

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash, user_id=42)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "legacy_user", real_password)

        assert result is True
        manager.session.query.return_value.filter_by.assert_called_once_with(
            id=42, password=legacy_hash)
        update_call = manager.session.query.return_value.filter_by.return_value.update
        update_call.assert_called_once()
        new_hash = update_call.call_args[0][0]['password']
        assert new_hash.startswith(f"{_DEFAULT_HASH_METHOD}:")
        assert check_password_hash(new_hash, real_password)
        manager.session.commit.assert_called_once()

    def test_legacy_hash_not_rehashed_on_failed_login(self):
        """A legacy hash is left untouched when the password does not match."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "legacy_user", "wrong_password")

        assert result is False
        manager.session.query.assert_not_called()
        manager.session.commit.assert_not_called()

    def test_legacy_hash_failed_login_is_padded_to_current_default_cost(self):
        """A wrong password against a legacy hash is padded up to the calibrated
        current-default cost instead of leaking the account's presence for as long
        as it never logs in successfully.
        """
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        with patch.object(orm_module, "sleep") as mock_sleep:
            result = AuthenticationManager.check_user(manager, "legacy_user", "wrong_password")

        assert result is False
        mock_sleep.assert_called_once()
        assert mock_sleep.call_args[0][0] >= 0.0
        manager.session.query.assert_not_called()
        manager.session.commit.assert_not_called()

    def test_default_hash_failed_login_is_not_padded(self):
        """A wrong password against an already-current hash is not padded — the
        padding only applies to accounts still on a legacy method.
        """
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        real_password = "correct_password"
        default_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("current_user", default_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        with patch.object(orm_module, "sleep") as mock_sleep:
            result = AuthenticationManager.check_user(manager, "current_user", "wrong_password")

        assert result is False
        mock_sleep.assert_not_called()

    def test_default_hash_check_refreshes_live_calibration(self):
        """Every check against the current-default method updates the padding
        target with its live cost, instead of leaving it frozen at whatever was
        measured once when the process started.
        """
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        real_password = "correct_password"
        default_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("current_user", default_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        # perf_counter() is called twice in check_user before the branch under
        # test: once for check_start, once right after for check_elapsed.
        with patch.object(orm_module, "perf_counter", side_effect=[100.0, 100.123]):
            AuthenticationManager.check_user(manager, "current_user", real_password)

        assert orm_module._DEFAULT_HASH_CHECK_SECONDS == pytest.approx(0.123)

    def test_legacy_hash_check_does_not_update_live_calibration(self):
        """A check against a legacy hash is not a valid sample of the current
        default's cost, so it must not overwrite the padding target.
        """
        from wazuh.rbac.orm import AuthenticationManager
        import wazuh.rbac.orm as orm_module

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        orm_module._DEFAULT_HASH_CHECK_SECONDS = 0.42
        with patch.object(orm_module, "sleep"):
            AuthenticationManager.check_user(manager, "legacy_user", "wrong_password")

        assert orm_module._DEFAULT_HASH_CHECK_SECONDS == 0.42

    def test_default_hash_not_rehashed(self):
        """A hash already using the current default method is not rewritten on login."""
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        default_hash = generate_password_hash(real_password)

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("current_user", default_hash)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result

        result = AuthenticationManager.check_user(manager, "current_user", real_password)

        assert result is True
        manager.session.query.assert_not_called()
        manager.session.commit.assert_not_called()

    def test_legacy_hash_rehash_skipped_on_concurrent_password_change(self):
        """If the stored hash changed since it was read, the compare-and-swap UPDATE
        matches zero rows instead of overwriting the concurrently-set password.

        This does not need to be asserted here (the real UPDATE's WHERE clause does
        the work against the actual database), but check_user must still commit
        without raising so a concurrent change isn't masked by an exception.
        """
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash, user_id=42)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result
        # Simulate the UPDATE matching no rows because another process already
        # changed the password (rowcount 0), as SQLAlchemy would report it.
        manager.session.query.return_value.filter_by.return_value.update.return_value = 0

        result = AuthenticationManager.check_user(manager, "legacy_user", real_password)

        assert result is True
        manager.session.commit.assert_called_once()

    def test_legacy_hash_login_succeeds_despite_rehash_write_failure(self):
        """A successful login is not turned into a failure by a rehash write error.

        The rehash is opportunistic; if the database can't be written right now
        (disk full, rbac.db locked past SQLite's busy timeout, read-only file), the
        login that already passed the real hash check must still succeed.
        """
        from wazuh.rbac.orm import AuthenticationManager

        real_password = "correct_password"
        legacy_hash = generate_password_hash(real_password, method="pbkdf2:sha256:150000")

        manager = MagicMock()
        mock_result = MagicMock()
        user = MockUser("legacy_user", legacy_hash, user_id=42)
        mock_result.first.return_value = user
        manager.session.scalars.return_value = mock_result
        manager.session.commit.side_effect = OperationalError("UPDATE", {}, Exception("database is locked"))

        result = AuthenticationManager.check_user(manager, "legacy_user", real_password)

        assert result is True
        manager.session.rollback.assert_called_once()
