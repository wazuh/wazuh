'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       Wazuh-db confirms that is able to save, update and erase the necessary information into the corresponding
       databases, using the proper commands and response strings.

components:
    - wazuh_db

targets:
    - manager

daemons:
    - wazuh-db

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
import time
import pytest

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Variables
receiver_sockets_params = [(WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT = 20

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Tests
def test_wazuh_db_timeout(daemons_handler_module, connect_to_sockets_module,
                          pre_insert_packages, pre_set_sync_info):
    """Check that effectively the socket is closed after timeout is reached"""
    wazuh_db_send_sleep = 2
    command = 'agent 000 package get'
    receiver_sockets[0].send(command, size=True)

    # Waiting Wazuh-DB to process command
    time.sleep(wazuh_db_send_sleep)

    socket_closed = False
    cmd_counter = 0
    status = 'due'
    while not socket_closed and status == 'due':
        cmd_counter += 1
        response = receiver_sockets[0].receive(size=True).decode()
        if response == '':
            socket_closed = True
        else:
            status = response.split()[0]

    assert socket_closed, f"Socket never closed. Received {cmd_counter} commands. Last command: {response}"
