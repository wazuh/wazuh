# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import *
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks, file


def _log_since(start_pos):
    """Everything appended to ossec.log from `start_pos` onward, for diagnostics attached to
    a failed wait_connect().

    Read at the moment of the actual timeout: the end-of-module CI diagnostic step runs
    after a later test's truncate_monitored_files has already reset the log, so it never
    sees the state that actually mattered (wazuh#38088 Windows agentd investigation). Anchored
    to a byte position captured right before the wait started, rather than a fixed line
    count, since debug2 (enabled by every caller of wait_connect()) can produce enough
    output during a 150s timeout to push the actual evidence out of a fixed-size tail.
    """
    try:
        encoding = file.get_file_encoding(WAZUH_LOG_PATH)
        with open(WAZUH_LOG_PATH, 'rb') as f:
            f.seek(start_pos)
            content = f.read().decode(encoding, errors='replace')
        return (f'Contents of {WAZUH_LOG_PATH} written during this wait:\n{content}' if content
                else f'No new content was written to {WAZUH_LOG_PATH} during this wait.')
    except Exception as e:
        return f'<could not read {WAZUH_LOG_PATH}: {e}>'


def wait_connect():
    """
        Watch ossec.log until the agent connects to the server -- either the legacy TCP
        "Connected to the server" line, or the HTTPS client's "startup accepted" milestone
        (wazuh/wazuh#37831; both paths run side by side during the migration).
    """
    try:
        start_pos = os.path.getsize(WAZUH_LOG_PATH)
    except OSError:
        start_pos = 0

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    connected_pattern = fr'({AGENTD_CONNECTED_TO_SERVER}|{AGENTD_HTTPS_STARTUP_ACCEPTED})'
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(connected_pattern), timeout = 150)
    assert (wazuh_log_monitor.callback_result != None), \
        f'Connected to the server message not found. {_log_since(start_pos)}'


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
