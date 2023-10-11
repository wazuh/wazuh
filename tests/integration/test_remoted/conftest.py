import pytest

from wazuh_testing.utils import services


@pytest.fixture
def restart_wazuh_expect_error() -> None:
    try:
        services.control_service('restart')
    except:
        pass

    yield

    services.control_service('stop')
