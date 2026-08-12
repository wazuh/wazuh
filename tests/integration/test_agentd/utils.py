# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import *
from wazuh_testing.modules.agentd.utils import parse_state_file
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks


def wait_keepalive(timeout=100, poll_interval=1):
    """
        Poll the state file until "last_keepalive" is populated.

        The legacy "Sending keep alive" log line has no HTTPS equivalent:
        bridge_on_manager_config_hash() (https_client_bridge.c) updates the state file's
        last_keepalive on every accepted Notify (its own comment: "An accepted Notify is
        the agent's keepalive"), but never logs it as text -- it's a state update, not a
        message. The state file is the real source of truth here, so poll that directly
        instead of a log line that no longer exists.
    """
    deadline = time.time() + timeout
    last_keepalive = ''

    while time.time() < deadline:
        try:
            last_keepalive = parse_state_file().get('last_keepalive', '')
        except FileNotFoundError:
            last_keepalive = ''

        if last_keepalive:
            return

        time.sleep(poll_interval)

    assert last_keepalive, f'Sending keep alive not found'


def wait_connect():
    """
        Watch ossec.log until the HTTPS startup is accepted (the legacy "Connected to the
        server" line has no equivalent under the /control path; see
        AGENTD_HTTPS_STARTUP_ACCEPTED's own comment, agentd/patterns.py).
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_HTTPS_STARTUP_ACCEPTED), timeout = 150)
    assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'


def wait_state_update():
    """
        Watch ossec.log until "Updating state file" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_UPDATING_STATE_FILE))
    assert (wazuh_log_monitor.callback_result != None), f'State file update not found'


def wait_enrollment():
    """
        Watch ossec.log until "Valid key received" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_RECEIVED_VALID_KEY), timeout = 150)
    assert (wazuh_log_monitor.callback_result != None), 'Agent never enrolled'


def wait_enrollment_try():
    """
        Watch ossec.log until "Requesting a key" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_REQUESTING_KEY,{'IP':''}), timeout = 150)
    assert (wazuh_log_monitor.callback_result != None), f'Enrollment retry was not sent'


def wait_server_rollback():
    """
        Watch ossec.log until "Unable to connect to any server" message is found'
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UNABLE_TO_CONNECT_TO_ANY), timeout = 120)
    assert (wazuh_log_monitor.callback_result != None), f'Unable to connect to any server message not found'


def check_module_stop():
    """
        Watch ossec.log until "Unable to access queue" message is not found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_MODULE_STOPPED))
    assert (wazuh_log_monitor.callback_result == None), f'Unable to access queue message found'


def check_connection_try():
    """
        Watch ossec.log until "Trying to connect to server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    matched_line = wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_TRYING_CONNECT,{'IP':'','PORT':''}), return_matched_line = True)
    assert (wazuh_log_monitor.callback_result != None), f'Trying to connect to server message not found'
    return matched_line
