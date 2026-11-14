'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check the stale-lock recovery of 'wazuh-manager-control' (lock() in
       src/init/wazuh-server.sh). The script serializes start/stop/status with a mkdir-based
       mutex, 'var/start-script-lock', and records the owner's pid in a file inside it in a
       separate step. Regression tests for #39114: a lock left behind without that pid file
       (the owner died between the two steps) was never reclaimed, so every later 'start' and
       'status' failed with 'Another instance is locking this process' until the directory was
       removed by hand. They also pin the guards the recovery relies on: a lock whose owner has
       not written its pid yet is live, not stale, and the exclusive marker that serializes the
       recovery itself is only removed once its holder is gone. The tests live in
       tests/integration/start_lock.py, shared with the agent's wazuh-control.

components:
    - manager

suite: manager_control

targets:
    - manager

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/39114

tags:
    - manager_control
'''
import pytest

from start_lock import (free_lock, live_owner, test_dead_pid_lock_is_reclaimed,  # noqa: F401
                        test_dead_pid_rounds_do_not_open_the_pidless_gate,
                        test_leaked_marker_is_only_removed_after_consecutive_busy_rounds,
                        test_lock_mid_acquisition_is_not_stolen, test_marker_of_a_dead_reclaimer_is_removed,
                        test_marker_of_a_live_reclaimer_is_kept, test_pidless_lock_is_reclaimed)

# Marks
pytestmark = [pytest.mark.server, pytest.mark.linux, pytest.mark.tier(level=0)]
