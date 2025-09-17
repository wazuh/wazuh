# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh.core.exception import WazuhInternalError
from wazuh.core.cti import CTIAuthTokenStatus, CTI, get_cti_client


class TestCTIAuthTokenStatus:
    """Unit tests for CTIAuthTokenStatus enum."""

    @pytest.mark.parametrize(
        "status, short_desc, long_desc",
        [
            (CTIAuthTokenStatus.PENDING, "pending", "Registration process was not started and never tried."),
            (CTIAuthTokenStatus.POLLING, "polling", "Registration process is being carried out."),
            (CTIAuthTokenStatus.DENIED, "denied", "Registration process denied due to expired `device_code`."),
            (CTIAuthTokenStatus.AVAILABLE, "available", "Registration process was finished successfuly."),
        ],
    )
    def test_enum_descriptions(self, status, short_desc, long_desc):
        """Check that each enum value has the expected short and long description."""
        assert status.short_desc == short_desc
        assert status.long_desc == long_desc


class TestCTI:
    """Unit tests for CTI class."""

    def test_get_auth_token_status_default(self):
        """Check that get_auth_token_status returns PENDING by default."""
        client = CTI()
        result = client.get_auth_token_status()
        assert result == CTIAuthTokenStatus.PENDING

    @pytest.mark.parametrize(
        "status",
        [
            CTIAuthTokenStatus.PENDING,
            CTIAuthTokenStatus.POLLING,
            CTIAuthTokenStatus.DENIED,
            CTIAuthTokenStatus.AVAILABLE,
        ],
    )
    def test_get_auth_token_status_parametrized(self, monkeypatch, status):
        """Check that get_auth_token_status can be simulated with different states."""

        cti = CTI()

        monkeypatch.setattr(CTI, "get_auth_token_status", lambda self: status)

        assert cti.get_auth_token_status() == status


class TestGetCTIClient:
    """Unit tests for get_cti_client context manager."""

    def test_get_cti_client_success(self):
        """Check that the context manager yields a CTI instance successfully."""
        with get_cti_client() as client:
            assert isinstance(client, CTI)

    def test_get_cti_client_raises_internal_error_on_exception(self):
        """Check that exceptions inside the context are wrapped in WazuhInternalError."""

        with pytest.raises(WazuhInternalError) as excinfo:
            with get_cti_client() as client:
                raise RuntimeError("simulated error")

        assert excinfo.value.code == 1000
