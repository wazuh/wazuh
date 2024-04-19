# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import distro
import re
import pytest
import subprocess

from wazuh_testing.constants.platforms import CENTOS, UBUNTU, DEBIAN

@pytest.fixture(scope='module')
def uninstall_audit():
    """Uninstall auditd before test and install after test"""

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
        raise ValueError(f"Linux distro ({linux_distro}) not supported for uninstall audit")

    # Uninstall audit
    subprocess.run([package_management, "remove", audit, option], check=True)

    yield

    # Install audit and start the service
    subprocess.run([package_management, "install", audit, option], check=True)
    subprocess.run(["service", "auditd", "start"], check=True)
