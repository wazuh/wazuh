import distro
import pytest
import re
import subprocess
import sys

from typing import Any
from pathlib import Path

from wazuh_testing.constants.daemons import WAZUH_MANAGER
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.fim.patterns import MONITORING_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.services import get_service


@pytest.fixture()
def file_to_monitor(test_metadata: dict) -> Any:
    path = test_metadata.get('file_to_monitor')
    file.write_file(path) if path else None

    yield path

    file.remove_file(path) if path else None


@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    file.create_folder(path) if path else None

    yield path

    file.delete_path_recursively(path) if path else None


@pytest.fixture()
def fill_folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    amount = test_metadata.get('files_amount')
    amount = 2 if not amount else amount

    [file.write_file(Path(path, f'test{i}.log')) for i in range(amount)]

    yield

    [file.remove_file(Path(path, f'test{i}.log')) for i in range(amount)]


@pytest.fixture()
def start_monitoring() -> None:
    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(MONITORING_PATH))


@pytest.fixture(scope='module', autouse=True)
def set_agent_config(request: pytest.FixtureRequest):
    if not hasattr(request.module, 'test_configuration'):
        return
    if get_service() is WAZUH_MANAGER:
        return
    configurations = getattr(request.module, 'test_configuration')
    agent_conf = {"section": "client", "elements": [
        {"server": {"elements": [
            {"address": {"value": "127.0.0.1"}},
            {"port": {"value": 1514}},
            {"protocol": {"value": "tcp"}}]}}]}

    for index, _ in enumerate(configurations):
        configurations[index]['sections'].append(agent_conf)

    request.module.test_configuration = configurations


@pytest.fixture(scope='session', autouse=True)
def install_audit():
    """Automatically install auditd before test session on linux distros."""
    if sys.platform == WINDOWS:
        return

    # Check distro
    linux_distro = distro.id()

    if re.match(linux_distro, "centos"):
        package_management = "yum"
        audit = "audit"
        option = "--assumeyes"
    elif re.match(linux_distro, "ubuntu") or re.match(linux_distro, "debian"):
        package_management = "apt-get"
        audit = "auditd"
        option = "--yes"
    else:
        raise ValueError(
            f"Linux distro ({linux_distro}) not supported for install audit")

    subprocess.run([package_management, "install", audit, option], check=True)
    subprocess.run(["service", "auditd", "start"], check=True)


@pytest.fixture(autouse=True)
def start_simulators(request: pytest.FixtureRequest) -> None:
    """
    Fixture for starting simulators.

    This fixture starts both Authd and Remoted simulators. If the service is not WAZUH_MANAGER,
     both simulators are started. After the test function finishes, both simulators are shut down.

     Returns:
         None

     """
    create_authd = 'authd_simulator' not in request.fixturenames
    create_remoted = 'authd_simulator' not in request.fixturenames

    if get_service() is not WAZUH_MANAGER:
        authd = AuthdSimulator() if create_authd else None
        remoted = RemotedSimulator() if create_remoted else None

        authd.start() if authd else None
        remoted.start() if create_remoted else None

    yield

    if get_service() is not WAZUH_MANAGER:
        authd.shutdown() if authd else None
        remoted.shutdown() if create_remoted else None
