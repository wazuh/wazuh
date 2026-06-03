'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db exposes a socket to receive requests and provide information. Some commands stream their result
       row by row, pushing each row as a "due {payload}" message with a blocking send bounded by
       WDB_BLOCK_SEND_TIMEOUT_S. If the client stops reading, the send buffer fills up, wazuh-db blocks on send and
       tears the connection down once the timeout is reached. This test verifies that behaviour with
       `global get-all-agents context`, which streams every agent row through the blocking send path. The `context`
       variant is required: `last_id` is client-driven pagination and never fills the buffer.

components:
    - wazuh_db

targets:
    - manager

daemons:
    - wazuh-manager-db

os_platform:
    - linux

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-manager-db.html

tags:
    - wazuh_db
'''
import time
import pytest

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH
from wazuh_testing.utils.database import query_wdb

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Variables
receiver_sockets_params = [(WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Insert enough agents that the streamed `global get-all-agents context` response exceeds the socket
# send buffer (SO_SNDBUF). The count is intentionally generous so the buffer fills regardless of the
# environment's SO_SNDBUF.
AGENTS_TO_INSERT = 20000
INSERT_BATCH = 1000


@pytest.fixture()
def pre_insert_agents():
    """Bulk-insert agents so `global get-all-agents context` streams enough "due" blocks to fill the buffer."""
    # Start from a clean agent table so leftovers from a previous run don't break the bulk insert
    # with a UNIQUE constraint error.
    query_wdb('global sql DELETE FROM agent WHERE id > 0')

    for start in range(1, AGENTS_TO_INSERT + 1, INSERT_BATCH):
        end = min(start + INSERT_BATCH, AGENTS_TO_INSERT + 1)
        values = ','.join(f"({i},'Agent{i}',1)" for i in range(start, end))
        response = query_wdb(f'global sql INSERT INTO agent (id, name, date_add) VALUES {values}')
        assert not (isinstance(response, str) and response.startswith('err')), \
            f"Bulk agent insert failed: {response}"

    yield

    query_wdb('global sql DELETE FROM agent WHERE id > 0')


# Tests
def test_wazuh_db_timeout(daemons_handler_module, connect_to_sockets_module, pre_insert_agents):
    '''
    description: Check that wazuh-db aborts a large streamed response once the block-send timeout is reached
                 because the client stopped reading. The timeout terminates the paginated stream with an error
                 response.

    wazuh_min_version: 5.0.0

    tier: 0

    parameters:
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of the 'connect_to_sockets' fixture.
        - pre_insert_agents:
            type: fixture
            brief: Insert enough agents to force a streamed multi-block response from `global get-all-agents context`.

    assertions:
        - Verify that, after some 'due' blocks are delivered, the stream is aborted by the send timeout
          instead of completing with 'ok'.

    input_description:
        - The streamed `global get-all-agents context` command over a populated agent table.

    tags:
        - wazuh_db
        - wdb_socket
    '''
    wazuh_db_send_sleep = 2
    command = 'global get-all-agents context'
    receiver_sockets[0].send(command, size=True)

    # Let wazuh-db fill the socket send buffer while the client does not read.
    time.sleep(wazuh_db_send_sleep)

    socket_closed = False
    cmd_counter = 0
    due_blocks = 0
    status = 'due'
    response = ''
    while not socket_closed and status == 'due':
        cmd_counter += 1
        response = receiver_sockets[0].receive(size=True).decode()
        if response == '':
            socket_closed = True
        else:
            status = response.split()[0]
            if status == 'due':
                due_blocks += 1

    # Once the client stops reading, the blocking send in wdb_exec_stmt_send (wdb.c) hits WDB_BLOCK_SEND_TIMEOUT_S
    # and returns an error, which the get-all-agents context handler reports as "err Error getting agents from
    # global.db." (wdb_parser.c). The socket_closed branch is a defensive fallback. Either outcome, after partial
    # 'due' delivery, confirms the timeout fired rather than the stream completing with 'ok'.
    stream_aborted = socket_closed or status == 'err'
    assert stream_aborted and due_blocks > 0, (
        f"Expected the stream to be aborted by the send timeout after partial delivery. "
        f"due_blocks={due_blocks}, last status={status!r}, socket_closed={socket_closed}, "
        f"received {cmd_counter} responses. Last: {response}"
    )
