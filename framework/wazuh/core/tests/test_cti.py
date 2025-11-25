from unittest.mock import AsyncMock, call, MagicMock

import pytest
from wazuh.core.cti import cti, CTIAuthTokenStatus
from wazuh.core.exception import WazuhError


class TestCTI:
    """Test the functionality of the `CTI` class."""

    @pytest.mark.parametrize(
        "status",
        [
            CTIAuthTokenStatus.PENDING,
            CTIAuthTokenStatus.POLLING,
            CTIAuthTokenStatus.DENIED,
            CTIAuthTokenStatus.AVAILABLE,
        ],
    )
    def test_get_auth_token_status(self, status):
        """Check that the `get_auth_token_status` method returns the expected status."""
        cti.status = status  # simulate different states
        assert cti.get_auth_token_status() == status
