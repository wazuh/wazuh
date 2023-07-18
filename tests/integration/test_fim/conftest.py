from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import distro
from psutil import WINDOWS
import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def file_to_monitor(test_metadata: dict) -> Any:
    path = test_metadata.get('file_to_monitor')
    file.write_file(path) if path else None

    yield path

    file.remove_file(path) if path else None


@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    if isinstance(path, list):
        [file.create_folder(p) for p in path if path]
    else:
        file.create_folder(path) if path else None

    yield path

    if isinstance(path, list):
        [file.delete_path_recursively(p) for p in path if path]
    else:
        file.delete_path_recursively(path) if path else None


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
