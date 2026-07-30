'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a
       socket to receive requests and provide information. When a client sends a message bigger than the maximum
       allowed size (OS_MAXSTR, 65536 bytes), wazuh-db must close that connection instead of leaving it open and
       unanswered, otherwise the client is left waiting forever for a response that will never arrive.

components:
    - wazuh_db

targets:
    - manager

daemons:
    - wazuh-db

os_platform:
    - linux

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
import socket
import pytest

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Variables
receiver_sockets_params = [(WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

OS_MAXSTR = 65536
RECEIVE_TIMEOUT = 10

def build_oversized_global_query(pairs=900):
    """Build a 'global sql select ...' wazuh-db query whose payload exceeds OS_MAXSTR bytes."""
    condition = "(version != 'Wazuh v4.14.2' collate nocase) and (name = 'agent{:06x}' collate nocase)"
    conditions = ' or '.join(condition.format(i) for i in range(pairs))
    sql = f"select count(*) from agent where (id != '000' collate nocase) and ({conditions})   order by id asc"
    query = f"global sql {sql}"

    assert len(query) > OS_MAXSTR, f"Generated query ({len(query)} bytes) does not exceed OS_MAXSTR, increase `pairs`"

    return query


def test_wazuh_db_closes_peer_on_oversized_message(daemons_handler_module, connect_to_sockets_module):
    """Check wazuh-db closes the connection after receiving a message bigger than OS_MAXSTR."""
    receiver_sockets[0].sock.settimeout(RECEIVE_TIMEOUT)
    receiver_sockets[0].send(build_oversized_global_query(), size=True)

    try:
        response = receiver_sockets[0].receive(size=True)
    except socket.timeout:
        pytest.fail(
            f"wazuh-db did not close the connection within {RECEIVE_TIMEOUT}s of receiving an oversized message. "
            "The worker thread handling it most likely exited without closing the peer socket (see the "
            "OS_SOCKTERR branch of run_worker() in src/wazuh_db/src/main.c)."
        )
    except ConnectionResetError:
        # wazuh-db closes the peer without ever draining the oversized payload still sitting in the socket's
        # receive buffer, so the kernel sends a RST instead of a graceful FIN. That is still a closed connection.
        return

    assert response == b'', f"Expected the connection to be closed (empty read), got: {response!r}"
