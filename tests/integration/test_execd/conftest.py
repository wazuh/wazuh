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
    remoted.start()
    remoted.send_special_response(b'#!-execd {"version":1,"origin":{"name":"","module":"wazuh-analysisd"},"command":"restart-wazuh0","parameters":{"extra_args":[],"alert":{"rule":{"level":5,"description":"Test.","id":554}}}}')

    yield

    remoted.shutdown()
