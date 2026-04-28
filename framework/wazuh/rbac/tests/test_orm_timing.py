#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import statistics
from unittest.mock import MagicMock
from werkzeug.security import generate_password_hash

import pytest


class MockUser:
    """Mock User object for testing."""
    def __init__(self, username, password_hash):
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
