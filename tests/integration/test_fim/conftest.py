"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
from time import sleep
import distro
import pytest
import re
import subprocess
import sys

from typing import Any
from pathlib import Path

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
    path = os.path.abspath(path)
    data = test_metadata.setdefault('content', '')
    isBinary = test_metadata.setdefault('binary_content', False)

    if isBinary:
        data = data.encode('utf-8')

    file.write_file(path, data)

    yield path

    file.remove_file(path)


@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    path = os.path.abspath(path)

    file.recursive_directory_creation(path)

    yield path

    file.delete_path_recursively(path)


@pytest.fixture()
def fill_folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    amount = test_metadata.get('files_amount')
    amount = 2 if not amount else amount

    if not file.exists(path):
        file.recursive_directory_creation(path)

    [file.write_file(Path(path, f'test{i}.log'), 'content') for i in range(amount)]
        # file.write_file(Path(path, f'test{i}.log'), 'content')

    yield

    [file.remove_file(Path(path, f'test{i}.log')) for i in range(amount)]


@pytest.fixture()
def start_monitoring() -> None:
    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(MONITORING_PATH))


@pytest.fixture(scope='module', autouse=True)
def set_agent_config(request: pytest.FixtureRequest):
    if not hasattr(request.module, 'test_configuration'):
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


@pytest.fixture()
def create_links_to_file(folder_to_monitor: str, file_to_monitor: str, test_metadata: dict) -> None:
    hardlink_amount = test_metadata.get('hardlink_amount', 0)
    symlink_amount = test_metadata.get('symlink_amount', 0)

    def hardlink(i: int):
        Path(folder_to_monitor, f'test_h{i}').symlink_to(file_to_monitor)

    def symlink(i: int):
        Path(folder_to_monitor, f'test_s{i}').hardlink_to(file_to_monitor)

    [hardlink(i) for i in range(hardlink_amount)]
    [symlink(i) for i in range(symlink_amount)]

    yield

    [file.remove_file(f'test_h{i}') for i in range(hardlink_amount)]
    [file.remove_file(f'test_s{i}') for i in range(symlink_amount)]
