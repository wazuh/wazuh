import pytest

from typing import Generator

from wazuh_testing.tools.simulators import AuthdSimulator, RemotedSimulator

@pytest.fixture()
def authd_simulator() -> Generator:
    authd = AuthdSimulator()
    authd.start()
    
    yield authd
    
    authd.shutdown()
    
@pytest.fixture()
def remoted_simulator() -> Generator:
    remoted = RemotedSimulator()
    # remoted.start()
    
    yield remoted
    
    # remoted.shutdown()
    
