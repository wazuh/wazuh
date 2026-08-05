'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that the 'wazuh-manager-authd' daemon drops root privileges and runs
       as the 'wazuh-manager' user by default, instead of running as 'root' for its entire lifetime
       as it did before TLS 1.3 enforcement was added.

components:
    - authd

suite: drop_privileges

targets:
    - manager

daemons:
    - wazuh-manager-authd
    - wazuh-manager-db
    - wazuh-manager-modulesd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-manager-authd.html

tags:
    - enrollment
'''
import os
import pwd

import pytest

from wazuh_testing.constants.daemons import AUTHD_DAEMON
from wazuh_testing.utils.services import search_process_by_command

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Variables
EXPECTED_DEFAULT_USER = 'wazuh-manager'

daemons_handler_configuration = {'daemons': [AUTHD_DAEMON], 'ignore_errors': True}


# Tests
def test_authd_drops_privileges_by_default(truncate_monitored_files, daemons_handler, wait_for_authd_startup):
    '''
    description:
        Checks that 'wazuh-manager-authd', started with its default flags (no '-u'/'-g' override),
        drops root privileges shortly after startup and ends up running as the 'wazuh-manager' user.

    wazuh_min_version:
        5.0.0

    tier: 0

    test_phases:
        - setup:
            - Truncate the log files.
            - Start 'wazuh-manager-authd' with its default configuration and flags.
            - Wait until authd is accepting connections.
        - test:
            - Search the 'wazuh-manager-authd' process and verify it is present.
            - Get the current owning user of the process via '/proc/<pid>'.
            - Check that the user is 'wazuh-manager', not 'root'.
        - teardown:
            - Stop 'wazuh-manager-authd'.
            - Truncate the log files.

    parameters:
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.

    assertions:
        - Verify that the running 'wazuh-manager-authd' process is owned by the 'wazuh-manager' user,
          not 'root'.

    input_description:
        No external test cases are used. This test only exercises the default (no CLI override)
        startup path, since the standard daemon-lifecycle fixtures used across this suite start
        daemons through 'wazuh-manager-control', which does not support passing custom '-u'/'-g'
        arguments to a specific daemon.

    expected_output:
        - r'Accepting connections on port 1515' (authd startup marker used by 'wait_for_authd_startup')

    tags:
        - enrollment
    '''
    authd_process = search_process_by_command(AUTHD_DAEMON)
    assert authd_process is not None, f"The process '{AUTHD_DAEMON}' could not be found"

    process_stat_file = os.stat(f"/proc/{authd_process.pid}")
    uid = process_stat_file.st_uid
    username = pwd.getpwuid(uid)[0]

    assert username == EXPECTED_DEFAULT_USER, (
        f"Expected '{AUTHD_DAEMON}' to have dropped privileges to '{EXPECTED_DEFAULT_USER}', "
        f"but it is running as '{username}'"
    )
