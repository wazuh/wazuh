# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.sockets import QUEUE_DB_PATH
from wazuh_testing.modules.modulesd import patterns
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.manage_agents import remove_agents
from wazuh_testing.utils.services import control_service
from wazuh_testing.tools.db_administrator import DatabaseAdministrator
from wazuh_testing.tools.simulators.agent_simulator import connect, create_agents

def inject_rootcheck_events(agents):
    injectors = []

    for agent in agents:
        agent.modules['rootcheck']['status'] = 'enabled'
        _, injector = connect(agent)
        injectors.append(injector)
        agents.append(agent)

    # Let rootcheck events to be sent for 60 seconds
    time.sleep(60)

    for injector in injectors:
        injector.stop_receive()

    # Service needs to be stopped otherwise db lock will be held by Wazuh db
    control_service('stop')

def retrieve_rootcheck_rows(agent_id):
    db_connection = DatabaseAdministrator(os.path.join(QUEUE_DB_PATH, f'{agent_id}.db'))
    rows = db_connection.select("pm_event")
    db_connection.cursor.close()
    db_connection.connection.close()
    return rows

@pytest.fixture()
def wait_for_rootcheck_start():
    # Wait for module rootcheck starts
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(patterns.MODULESD_STARTED, {
                              'integration': 'rootcheck'
                          }))
    assert (wazuh_log_monitor.callback_result == None), f'Error invalid configuration event not detected'

@pytest.fixture(scope="function")
def load_agents(request):
    agents = []
    for _ in range(request.getfixturevalue("test_metadata")["agents_number"]):
       agent = create_agents(1, 'localhost')[0]

    inject_rootcheck_events(agents)

    yield agents
    # Stop and delete simulated agent
    control_service('start')
    for agent in agents:
        remove_agents(agent.id,'manage_agents')
    control_service('stop')
