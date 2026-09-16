# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import *
from wazuh_testing.modules.agentd.utils import parse_state_file
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks, file


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


def log_position():
    """ossec.log's current size, to anchor a later wait to.

    Capture this BEFORE the event you are waiting for can possibly happen -- before the
    RemotedSimulator that provokes it is even constructed -- and hand it to wait_connect() or
    wait_enrollment() as `since`. Letting those anchor themselves is a window, not a fix: they
    take the offset when they are called, which is already after the listener came up, so an
    agent whose retry loop reconnects in the microseconds before the call still writes its
    once-only line below the anchor and is never seen. See _wait_for_pattern_since().
    """
    try:
        return os.path.getsize(WAZUH_LOG_PATH)
    except OSError:
        return 0


def _wait_for_pattern_since(pattern, timeout=150, poll_interval=0.1, since=None):
    """Scan ossec.log for `pattern` from `since`, or from a byte offset captured on entry.

    Deliberately not FileMonitor(only_new_events=True), which seeks to whatever the file's end
    is at the moment .start() runs: for a message that is logged exactly once and never repeats
    (connection/enrollment acceptance), if the agent's own already-running retry loop wins the
    race and writes that line in the gap between this function being entered and the monitor
    seeking to EOF, only_new_events=True misses it permanently and burns the full timeout
    waiting for a line that already came and went. Reproduced live on Windows for both
    AGENTD_HTTPS_STARTUP_ACCEPTED and AGENTD_RECEIVED_VALID_KEY: the line landed before the
    monitor attached, then never recurred, timing out the wait despite having already happened.
    """
    start_pos = log_position() if since is None else since

    callback = callbacks.generate_callback(pattern)
    encoding = file.get_file_encoding(WAZUH_LOG_PATH)
    deadline = time.time() + timeout

    with open(WAZUH_LOG_PATH, encoding=encoding, errors='ignore') as f:
        f.seek(start_pos)
        while time.time() < deadline:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            if callback(line):
                return True

    return False


def wait_connect(timeout=150, poll_interval=0.1, since=None):
    """
        Watch ossec.log until the HTTPS startup is accepted (the legacy "Connected to the
        server" line has no equivalent under the /control path; see
        AGENTD_HTTPS_STARTUP_ACCEPTED's own comment, agentd/patterns.py).

        Pass `since` from log_position(), taken before the simulator this is waiting on was
        started, whenever the agent may already be looping fast enough to connect the instant
        the listener appears.
    """
    matched = _wait_for_pattern_since(AGENTD_HTTPS_STARTUP_ACCEPTED, timeout, poll_interval, since)
    assert matched, f'Connected to the server message not found'


def wait_state_update():
    """
        Watch ossec.log until "Updating state file" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_UPDATING_STATE_FILE))
    assert (wazuh_log_monitor.callback_result != None), f'State file update not found'


def wait_enrollment(timeout=150, poll_interval=0.1, since=None):
    """
        Watch ossec.log until "Valid key received" message is found. `since` as wait_connect().
    """
    matched = _wait_for_pattern_since(AGENTD_RECEIVED_VALID_KEY, timeout, poll_interval, since)
    assert matched, 'Agent never enrolled'


def wait_enrollment_try():
    """
        Watch ossec.log until the 401-triggered re-enrollment warning is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_REENROLLING), timeout = 150)
    assert (wazuh_log_monitor.callback_result != None), f'Enrollment retry was not sent'


def wait_enrollment_retry_backoff():
    """
        Watch ossec.log until the initial (no pre-existent key) enrollment loop logs its
        retry-backoff line -- there is no distinct "attempt started" announcement, so this
        is the closest observable signal that a first-time enrollment attempt failed and is
        about to retry.
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_ENROLLMENT_RETRY_BACKOFF), timeout = 150)
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
