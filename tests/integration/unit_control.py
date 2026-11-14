"""
Copyright (C) Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Drive a systemd unit and wait for what it does, for the suites that test wazuh-agent.service and
wazuh-manager.service (test_agent_control, test_manager_control).
"""
import subprocess
import time

import pytest

POLL_SECONDS = 0.1


def systemctl(*args, check=True):
    """Run systemctl with the given arguments. Raise if it fails, unless check is False."""
    return subprocess.run(['systemctl', *args], check=check, capture_output=True, text=True)


def unit_property(unit, name):
    """Return the value of one property of a unit, as 'systemctl show' prints it."""
    return systemctl('show', '-p', name, '--value', unit).stdout.strip()


def journal_time():
    """Return the current time in the form journalctl's --since takes."""
    return time.strftime('%Y-%m-%d %H:%M:%S')


def control_process_killed(unit, since):
    """Tell whether systemd killed a control process of the unit since the given journal time, as it does
    to a reload's script when it merges a restart into the running reload."""
    journal = subprocess.run(['journalctl', '-u', unit, '--since', since, '-o', 'cat', '--no-pager'],
                             capture_output=True, text=True).stdout
    return 'Control process exited, code=killed' in journal


def wait_for(condition, timeout, failure):
    """Poll condition until it returns a truthy value, and return that value. Fail the test with
    the failure message if timeout seconds go by first."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(POLL_SECONDS)
    pytest.fail(failure)
