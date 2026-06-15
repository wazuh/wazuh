'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Regression test for issue #36134. When a realtime <directories> rule
       is removed from ossec.conf and the agent is restarted, the previously
       monitored files still live in the local fim.db with sync=0. The agent's
       fim_initialize() promote loop must drop those orphaned rows up front
       rather than calling build_stateful_event_file() with the current
       directories list (which would log
       "ERROR: Failed to get configuration for path: <path>"). The orphan-
       cleanup path in the next scheduled scan is responsible for emitting
       the real DELETE event.

       The test seeds a small file under both <directories> before the agent
       starts so the baseline scan promotes at least one row to sync=1; that
       satisfies the outer guard of fim_initialize's promote branch on the
       next restart (it only runs when the table has at least one synced
       row). A second <directories> entry stays in the configuration after
       the realtime one is removed, so the post-restart scheduled scan walks
       at least one path and reaches handle_orphaned_delete instead of the
       "no directories configured" DataClean shortcut.

components:
    - fim

suite: basic_usage

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - linux

references:
    - https://github.com/wazuh/wazuh/issues/36134
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

tags:
    - fim
    - realtime
'''
import sys
import time

import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.fim.configuration import SYSCHECK_DEBUG
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import configuration, file, services
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import TEST_CASES_PATH, CONFIGS_PATH


# Pytest marks: linux agent, tier 0.
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_orphan_promote.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_orphan_promote.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

# Local internal options: surface syscheck.debug=2 so the helper's mdebug2
# lines and the merror this test guards against both appear in ossec.log.
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS:
    local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


# Log patterns specific to this regression — not (yet) exposed by
# wazuh_testing.modules.fim.patterns.
FAILED_TO_GET_CONFIG_PATTERN = r'.*ERROR: Failed to get configuration for path: (\S+)'
SKIPPING_PROMOTION_PATTERN = (
    r'.*Skipping promotion of orphaned path \(no active configuration\): (\S+)'
)
HANDLE_ORPHANED_DELETE_PATTERN = (
    r".*Generating delete event for orphaned file '(\S+)' \(path removed from configuration\)"
)
DOCUMENT_LIMIT_CHANGED_PATTERN = r'.*Document limit (increased|decreased)'


@pytest.fixture()
def _setup_orphan_test_folders(test_metadata: dict):
    """Create both monitored folders before the agent starts and pre-seed
    one file in each so the agent's initial baseline scheduled scan
    promotes them to sync=1. Without a sync=1 row, the promote branch
    of fim_initialize() short-circuits and the regression code path
    isn't reached.

    Yields the absolute path of the realtime folder.
    """
    realtime_folder = Path(test_metadata['realtime_folder'])
    keep_folder = Path(test_metadata['keep_folder'])
    seed_file = realtime_folder / test_metadata['seed_file']
    keep_seed_file = keep_folder / test_metadata['keep_seed_file']

    file.recursive_directory_creation(str(realtime_folder))
    file.recursive_directory_creation(str(keep_folder))
    file.write_file(str(seed_file), 'baseline-seed')
    file.write_file(str(keep_seed_file), 'baseline-keep')

    yield realtime_folder

    file.delete_path_recursively(str(realtime_folder))
    file.delete_path_recursively(str(keep_folder))


def _remove_directories_section_from_ossec_conf(target_value: str) -> None:
    """Strip every <directories ...>target_value</directories> line from
    ossec.conf. Cheap textual edit — keeps the file otherwise intact so
    the agent picks up the same configuration except for the one rule we
    drop. The surrounding `set_wazuh_configuration` fixture restores the
    file from a snapshot at teardown.
    """
    conf_lines = configuration.get_wazuh_conf()
    pruned = [
        line for line in conf_lines
        if not (
            '<directories' in line
            and f'>{target_value}<' in line
        )
    ]
    configuration.write_wazuh_conf(pruned)


@pytest.mark.parametrize(
    'test_configuration, test_metadata',
    zip(test_configuration, test_metadata),
    ids=cases_ids,
)
def test_orphan_promote_after_config_removal(
    test_configuration,
    test_metadata,
    set_wazuh_configuration,
    truncate_monitored_files,
    configure_local_internal_options,
    _setup_orphan_test_folders,
    daemons_handler,
    start_monitoring,
):
    '''
    description: Reproduce issue #36134 and verify the fix.

                 The agent is started with two <directories> rules: one
                 realtime path that the test will drop later, and one
                 scheduled path that stays in the config. Both folders are
                 pre-seeded with a sentinel file so the initial baseline
                 scan promotes at least one row to sync=1. The test then
                 creates a file under the realtime folder via inotify (so
                 the row lands in fim.db with sync=0), stops the agent,
                 strips the realtime <directories> entry from ossec.conf,
                 and restarts the agent.

                 The fixed agent must:
                   1) not log "ERROR: Failed to get configuration for path"
                      for the orphaned file,
                   2) log the helper's
                      "Skipping promotion of orphaned path (no active
                      configuration): <file>" debug line,
                   3) still emit the orphan delete event via
                      handle_orphaned_delete on the next scheduled scan.

    wazuh_min_version: 5.0.0

    tier: 0
    '''
    realtime_folder = Path(test_metadata['realtime_folder'])
    target_file = realtime_folder / test_metadata['test_file']

    # Step 1: agent is up via daemons_handler. The baseline scan has
    # already visited both folders and promoted the seed files to sync=1
    # (start_monitoring blocks until the first sync finishes).
    #
    # Create the realtime-tracked file. inotify queues an "added" event;
    # the row lands in fim.db with sync=0 (the realtime path does not
    # flush the sync flag).
    file.write_file(str(target_file), 'evidence-36134')
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(EVENT_TYPE_ADDED),
        timeout=30,
    )

    # Step 2: stop the agent, drop the realtime <directories> rule from
    # ossec.conf, truncate the log, restart. This is the configuration
    # change that the upstream bug report describes (an agent group with
    # a realtime FIM rule getting unassigned).
    services.control_service('stop')
    _remove_directories_section_from_ossec_conf(str(realtime_folder))
    file.truncate_file(WAZUH_LOG_PATH)
    services.control_service('start')

    # Wait for fim_initialize() to log its "Document limit (increased|
    # decreased)" line — that signals the promote loop ran with our
    # docs_to_promote in hand. If this never appears the promote branch
    # was short-circuited (e.g. no sync=1 rows) and the test setup is
    # wrong.
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(DOCUMENT_LIMIT_CHANGED_PATTERN),
        timeout=60,
    )

    # Give fim_initialize a beat to finish so the orphan-skip mdebug2
    # lands in the log file before we read it.
    time.sleep(2)

    log_text = Path(WAZUH_LOG_PATH).read_text()

    # Assertion 1 (the regression itself): no ERROR for any orphaned path.
    # We match by directory prefix because both the seed_file and the
    # realtime-added test file are orphans now — neither should produce
    # a merror.
    failed_lines = [
        line for line in log_text.splitlines()
        if 'ERROR: Failed to get configuration for path' in line
        and str(realtime_folder) in line
    ]
    assert not failed_lines, (
        f'Unexpected "Failed to get configuration" ERROR lines for '
        f'{realtime_folder}:\n' + '\n'.join(failed_lines)
    )

    # Assertion 2: the fix's debug line fired for the realtime-added
    # file (the one with sync=0 that gets fed to docs_to_promote).
    skip_lines = [
        line for line in log_text.splitlines()
        if 'Skipping promotion of orphaned path' in line and str(target_file) in line
    ]
    assert skip_lines, (
        f'Expected "Skipping promotion of orphaned path" line for '
        f'{target_file}, got none. ossec.log tail:\n{log_text[-2000:]}'
    )

    # Assertion 3: the existing orphan-delete path still handles cleanup
    # on the first scheduled scan after restart.
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(HANDLE_ORPHANED_DELETE_PATTERN),
        timeout=90,
    )
