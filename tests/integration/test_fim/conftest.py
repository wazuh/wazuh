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

if sys.platform == 'win32':
    import win32con

from typing import Any
from pathlib import Path

from wazuh_testing.constants.paths.databases import FIM_DB_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS, MACOS, CENTOS, UBUNTU, DEBIAN
from wazuh_testing.modules.fim.patterns import MONITORING_PATH, FIM_SCAN_END
from wazuh_testing.modules.fim.utils import create_registry, delete_registry
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
    max_retries = 3
    retry_delay = 1

    if not file.exists(path):
        file.recursive_directory_creation(path)

    [file.write_file(Path(path, f'test{i}.log'), 'content') for i in range(amount)]

    yield

    for i in range(amount):
        retry_count = 0
        while retry_count < max_retries:
            try:
                file.remove_file(Path(path, f'test{i}.log'))
                break
            except Exception as e:
                print(f"Error deleting file {i}: {e}")
                retry_count += 1
                if retry_count == max_retries:
                    print(f"Failed to delete file {i} after {max_retries} attempts.")
                    break
                else:
                    print(f"Retrying in {retry_delay} seconds...")
                    sleep(retry_delay)

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
    if sys.platform == WINDOWS or sys.platform == MACOS:
        return

    # Check distro
    linux_distro = distro.id()

    if re.match(linux_distro, CENTOS):
        package_management = "yum"
        audit = "audit"
        option = "--assumeyes"
    elif re.match(linux_distro, UBUNTU) or re.match(linux_distro, DEBIAN):
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


@pytest.fixture()
def create_registry_key(test_metadata: dict) -> None:
    key = win32con.HKEY_LOCAL_MACHINE
    sub_key = test_metadata.get('sub_key')
    arch = win32con.KEY_WOW64_64KEY if test_metadata.get('arch') == 'x64' else win32con.KEY_WOW64_32KEY

    create_registry(key, sub_key, arch)

    yield

    delete_registry(key, sub_key, arch)


@pytest.fixture()
def detect_end_scan(test_metadata: dict) -> None:
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(timeout=60, callback=generate_callback(FIM_SCAN_END))
    assert wazuh_log_monitor.callback_result


@pytest.fixture()
def create_paths_files(test_metadata: dict) -> str:
    to_edit = test_metadata.get('path_or_files_to_create')

    if not isinstance(to_edit, list):
        raise TypeError(f"`files` should be a 'list', not a '{type(to_edit)}'")

    created_files = []
    for item in to_edit:
        item_path = Path(item)
        if item_path.exists():
            raise FileExistsError(f"`{item_path}` already exists.")

        # If file does not have suffixes, consider it a directory
        if item_path.suffixes == []:
            # Add a dummy file to the target directory to create the directory
            created_files.extend(file.create_parent_directories(
                Path(item_path).joinpath('dummy.file')))
        else:
            created_files.extend(file.create_parent_directories(item_path))

            file.write_file(file_path=item_path, data='')
            created_files.append(item_path)

    yield to_edit

    for item in to_edit:
        item_path = Path(item)
        file.delete_path_recursively(item_path)


@pytest.fixture()
def clean_fim_db():
    """
    Fixture to delete the persistent FIM DB file (fim.db) before each test.
    Works on both Linux and Windows agents.
    """
    try:
        if os.path.exists(FIM_DB_PATH):
            os.remove(FIM_DB_PATH)
    except Exception as e:
        pytest.fail(f"Failed to delete FIM DB file at {FIM_DB_PATH}: {e}")
