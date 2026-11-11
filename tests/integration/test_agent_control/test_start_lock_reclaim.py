'''
copyright: Copyright (C) Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests check that wazuh-control reclaims a start-script lock its owner left behind: a lock
       directory with no pid file, which an owner killed between creating it and writing its pid
       leaves (a systemctl restart merged into a running reload kills the reload's script at any
       point), and a lock whose pid is dead. The manager's wazuh-manager-control already did this;
       the agent's waited out its 40 rounds and failed, so the unit could not start again.
       They also pin the guards the recovery relies on, as for the manager: a lock whose owner has
       not written its pid yet is live, and the reclaim marker is only removed once its holder is
       gone. The tests live in tests/integration/start_lock.py, shared with wazuh-manager-control.

components:
    - agentd

suite: agent_control

targets:
    - agent

daemons:
    - wazuh-agentd

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/41047
    - https://github.com/wazuh/wazuh/issues/39114

tags:
    - agent_control
'''
import pytest

from start_lock import (free_lock, live_owner, test_dead_pid_lock_is_reclaimed,  # noqa: F401
                        test_dead_pid_rounds_do_not_open_the_pidless_gate,
                        test_leaked_marker_is_only_removed_after_consecutive_busy_rounds,
                        test_lock_mid_acquisition_is_not_stolen, test_marker_of_a_dead_reclaimer_is_removed,
                        test_marker_of_a_live_reclaimer_is_kept, test_pidless_lock_is_reclaimed)

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]
