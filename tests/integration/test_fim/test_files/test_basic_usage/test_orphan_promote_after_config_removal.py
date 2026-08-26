'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Regression test for issue #36134. When a realtime <directories> rule
       is removed from ossec.conf and the agent is restarted, an orphaned row
       (its directory no longer resolves in the current configuration) must
       not make fim_initialize's promote loop log
       "ERROR: Failed to get configuration for path: <path>". The orphan-
       cleanup path in the next scheduled scan is responsible for emitting
       the real DELETE event.

       Also covers #38522: until it was fixed, every file first seen through
       a realtime event landed in fim.db with sync=0 (the non-transactional
       insert path never flushed the sync flag). That same missing sync flag
       meant the orphan-delete path's own persistence gate
       (validate_and_persist_fim_event) silently dropped the resulting
       DELETE too — the underlying #38522 bug, just reached through a
       different trigger than a plain on-disk delete. This test asserts that
       sync=1 gets queued for the realtime-added file as soon as it's
       created, and that the orphan-delete path actually persists a
       stateful DELETE for it (not just logs that it tried to) once its
       directory is dropped from the configuration.

       NOTE on #36134 coverage: with #38522 fixed, a realtime insert under
       the default (unlimited) file_limit gets sync=1 immediately, so it's
       never a docs_to_promote candidate and never reaches #36134's
       orphan-drop-on-promote branch (drop_orphaned_promoted_documents) —
       that branch only fires for rows dbsync still has as sync=0.
       Reproducing that specific branch needs a file_limit increase between
       two agent starts (the promote loop's own outer gate is
       "synced_docs < limit", which a constant limit with a still-throttled
       row never satisfies), which is a materially different scenario from
       "a realtime rule got dropped". This test keeps the general "no ERROR
       for an orphaned path" assertion as a cheap regression guard, but a
       dedicated test exercising drop_orphaned_promoted_documents itself
       (via a genuine file_limit increase) is a separate, still-open gap —
       not something this PR's scope covers.

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
    - https://github.com/wazuh/wazuh/issues/38522
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

tags:
    - fim
    - realtime
'''
import re
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
HANDLE_ORPHANED_DELETE_PATTERN = (
    r".*Generating delete event for orphaned file '(\S+)' \(path removed from configuration\)"
)
DOCUMENT_LIMIT_CHANGED_PATTERN = r'.*Document limit (increased|decreased)'
# #38522: the non-transactional (realtime/whodata) insert path now queues the
# sync flag update as soon as the file is first seen, instead of leaving the
# row at sync=0 forever. version is left as \d+ since dbsync assigns it, not
# this test.
SYNC_FLAG_QUEUED_PATTERN = r'.*Added item to pending sync list: {path} \(version: \d+, sync: 1\)'
# #38522: confirms handle_orphaned_delete's stateful event actually cleared
# validate_and_persist_fim_event's sync gate, not just that the function was
# entered — the "Generating delete event" line alone fires unconditionally,
# before that gate is checked.
PERSISTING_FIM_EVENT_PATTERN = r'.*Persisting FIM event: .*"path":\s*"{path}"'


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
    description: Reproduce issue #36134 and verify the fix, plus lock in #38522's
                 fix for the same realtime insert path.

                 The agent is started with two <directories> rules: one
                 realtime path that the test will drop later, and one
                 scheduled path that stays in the config. Both folders are
                 pre-seeded with a sentinel file so the initial baseline
                 scan promotes at least one row to sync=1. The test then
                 creates a file under the realtime folder via inotify, stops
                 the agent, strips the realtime <directories> entry from
                 ossec.conf, and restarts the agent.

                 The fixed agent must:
                   1) queue the sync flag update for the realtime-added file
                      as soon as it's created (#38522),
                   2) not log "ERROR: Failed to get configuration for path"
                      for the orphaned file after the config is dropped,
                   3) still emit the orphan delete event via
                      handle_orphaned_delete on the next scheduled scan, and
                      actually persist it (not just log that it tried to).

    wazuh_min_version: 5.0.0

    tier: 0
    '''
    realtime_folder = Path(test_metadata['realtime_folder'])
    target_file = realtime_folder / test_metadata['test_file']
    target_file_pattern = re.escape(str(target_file))

    # Step 1: agent is up via daemons_handler. The baseline scan has
    # already visited both folders and promoted the seed files to sync=1
    # (start_monitoring blocks until the first sync finishes).
    #
    # Create the realtime-tracked file. inotify queues an "added" event; with
    # #38522 fixed, the row lands in fim.db with sync=1 right away instead of
    # being stuck at sync=0.
    file.write_file(str(target_file), 'evidence-36134')
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(EVENT_TYPE_ADDED),
        timeout=30,
    )

    # Assertion 1 (#38522 regression): the realtime insert queued the sync
    # flag update for target_file. Read before step 2 truncates the log.
    creation_log_text = Path(WAZUH_LOG_PATH).read_text()
    sync_queued_lines = [
        line for line in creation_log_text.splitlines()
        if re.search(SYNC_FLAG_QUEUED_PATTERN.format(path=target_file_pattern), line)
    ]
    assert sync_queued_lines, (
        f'Expected a "Added item to pending sync list" line with sync: 1 for '
        f'{target_file} right after its creation, got none. ossec.log tail:'
        f'\n{creation_log_text[-2000:]}'
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
    # decreased)" line — that signals the promote loop ran (it does even
    # with an empty docs_to_promote array: on the non-error path,
    # fim_db_get_documents_to_promote returns a valid, non-NULL cJSON array
    # regardless of how many sync=0 rows it found). If this never appears
    # the promote branch was short-circuited (e.g. no sync=1 rows) and the
    # test setup is wrong.
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(DOCUMENT_LIMIT_CHANGED_PATTERN),
        timeout=60,
    )

    # Give fim_initialize a beat to finish before we read the log.
    time.sleep(2)

    log_text = Path(WAZUH_LOG_PATH).read_text()

    # Assertion 2 (the #36134 regression itself): no ERROR for any orphaned
    # path under realtime_folder. This guards seed_file and target_file
    # alike — both are orphans once the directory is dropped, regardless of
    # whether either one is still an active docs_to_promote candidate at
    # this point.
    failed_lines = [
        line for line in log_text.splitlines()
        if 'ERROR: Failed to get configuration for path' in line
        and str(realtime_folder) in line
    ]
    assert not failed_lines, (
        f'Unexpected "Failed to get configuration" ERROR lines for '
        f'{realtime_folder}:\n' + '\n'.join(failed_lines)
    )

    # Assertion 3: the existing orphan-delete path still handles cleanup of
    # target_file on the first scheduled scan after restart, and actually
    # persists the stateful DELETE (not just logs that it tried to — the
    # "Generating delete event" line fires unconditionally, before
    # validate_and_persist_fim_event's sync gate is checked; #38522 was
    # exactly that gate silently dropping the event for a sync=0 row).
    FileMonitor(WAZUH_LOG_PATH).start(
        generate_callback(HANDLE_ORPHANED_DELETE_PATTERN),
        timeout=90,
    )

    time.sleep(2)
    delete_log_text = Path(WAZUH_LOG_PATH).read_text()

    all_lines = delete_log_text.splitlines()
    generating_delete_line_indices = [
        i for i, line in enumerate(all_lines)
        if re.search(HANDLE_ORPHANED_DELETE_PATTERN, line) and str(target_file) in line
    ]
    generating_delete_lines = [all_lines[i] for i in generating_delete_line_indices]
    assert generating_delete_lines, (
        f'Expected "Generating delete event for orphaned file" line for '
        f'{target_file}, got none. ossec.log tail:\n{delete_log_text[-2000:]}'
    )

    # The "Persisting FIM event" payload carries no event-type field, so a create and a
    # delete for the same path produce an identical-looking log line. target_file's original
    # CREATE (earlier in this same ossec.log, from _setup_orphan_test_folders) already left
    # one such line — searching the whole file would let that stale line satisfy this
    # assertion even if the DELETE itself was never persisted, exactly the #38522 bug this
    # test exists to catch. Anchor the search to lines from the orphan-delete detection
    # onward so only a persist for THIS delete can match.
    persisted_lines = [
        line for line in all_lines[generating_delete_line_indices[0]:]
        if re.search(PERSISTING_FIM_EVENT_PATTERN.format(path=target_file_pattern), line)
    ]
    assert persisted_lines, (
        f'The orphan delete for {target_file} was generated but never '
        f'persisted (no matching "Persisting FIM event" line) — this is '
        f'exactly the #38522 bug: the sync gate silently dropped the '
        f'stateful DELETE. ossec.log tail:\n{delete_log_text[-2000:]}'
    )
