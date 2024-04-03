'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. There is a feature to limit the
       number of events that the manager can process, in order to allow the correct functioning of the daemon. These
       tests validate that this feature works as expected.

components:
    - analysisd

suite: analysisd

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import pytest
import time
import re
from math import ceil
from copy import deepcopy

from pathlib import Path

from wazuh_testing.constants.paths.logs import ARCHIVES_LOG_PATH
from wazuh_testing.modules.analysisd import utils, configuration as analysisd_config
from wazuh_testing.modules.remoted import configuration as remoted_config
from wazuh_testing.scripts.syslog_simulator import DEFAULT_MESSAGE_SIZE
from wazuh_testing.tools import thread_executor
from wazuh_testing.tools.simulators import run_syslog_simulator
from wazuh_testing.utils import configuration, file

from . import CONFIGS_PATH, TEST_CASES_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
test_configs_path = Path(CONFIGS_PATH, 'event_processing_test_module', 'configuration_limitation.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'event_processing_test_module', 'cases_limitation.yaml')

test2_configs_path = Path(CONFIGS_PATH, 'event_processing_test_module', 'configuration_queue_events_after_limit.yaml')
test2_cases_path = Path(TEST_CASES_PATH, 'event_processing_test_module', 'cases_queue_events_after_limit.yaml')

test3_configs_path = Path(CONFIGS_PATH, 'event_processing_test_module', 'configuration_drop_events_queue_full.yaml')
test3_cases_path = Path(TEST_CASES_PATH, 'event_processing_test_module', 'cases_drop_events_queue_full.yaml')

test4_configs_path = Path(CONFIGS_PATH, 'event_processing_test_module', 'configuration_process_events_single.yaml')
test4_cases_path = Path(TEST_CASES_PATH, 'event_processing_test_module', 'cases_process_events_single.yaml')

test5_configs_path = Path(CONFIGS_PATH, 'event_processing_test_module', 'configuration_process_events_multi.yaml')
test5_cases_path = Path(TEST_CASES_PATH, 'event_processing_test_module', 'cases_process_events_multi.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(test_configs_path, test_configuration, test_metadata)

test2_configuration, test2_metadata, test2_cases_ids = configuration.get_test_cases_data(test2_cases_path)
test2_configuration = configuration.load_configuration_template(test2_configs_path, test2_configuration, test2_metadata)

test3_configuration, test3_metadata, test3_cases_ids = configuration.get_test_cases_data(test3_cases_path)
test3_configuration = configuration.load_configuration_template(test3_configs_path, test3_configuration, test3_metadata)

test4_configuration, test4_metadata, test4_cases_ids = configuration.get_test_cases_data(test4_cases_path)
test4_configuration = configuration.load_configuration_template(test4_configs_path, test4_configuration, test4_metadata)

test5_configuration, test5_metadata, test5_cases_ids = configuration.get_test_cases_data(test5_cases_path)
test5_configuration = configuration.load_configuration_template(test5_configs_path, test5_configuration, test5_metadata)

# Test internal options.
local_internal_options = {analysisd_config.ANALYSISD_STATE_INTERVAL: '1'}

t4_local_internal_options = {analysisd_config.ANALYSISD_STATE_INTERVAL: '1'}
t4_local_internal_options.update({analysisd_config.ANALYSISD_EVENT_THREADS: '1', analysisd_config.ANALYSISD_SYSCHECK_THREADS: '1',
                                  analysisd_config.ANALYSISD_SYSCOLLECTOR_THREADS: '1', analysisd_config.ANALYSISD_ROOTCHECK_THREADS: '1',
                                  analysisd_config.ANALYSISD_SCA_THREADS: '1', analysisd_config.ANALYSISD_HOSTINFO_THREADS: '1',
                                  analysisd_config.ANALYSISD_WINEVT_THREADS: '1', analysisd_config.ANALYSISD_RULE_MATCHING_THREADS: '1',
                                  analysisd_config.ANALYSISD_DBSYNC_THREADS: '1', remoted_config.REMOTED_WORKER_POOL: '1'})

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test variables.
SYSLOG_SIMULATOR_START_TIME = 2
QUEUE_EVENTS_SIZE = 16384


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_limitation(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                    configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check if after passing the event processing limit, the processing is stopped until the next timeframe.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Start the event simulator and check that the events are being received and analyzed.
            - Wait until the event limit is reached and check that the events are still being received but not
              processed.
            - Wait until the next analysis period (next timeframe) and check that events are still being
              processed, in this case the queued ones.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that events are received when expected.
        - Check that events are processed when expected.
        - Check that events are still received when expected.
        - Check that no events are processed due to blocking.
        - Check that events are still processed after blocking.

    input_description:
        - The `configuration_limitation` file provides the module configuration for this test.
        - The `cases_limitation` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                   'messages_number': test_metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()
    waited_simulator_time = 0

    # Wait until syslog simulator is started
    time.sleep(SYSLOG_SIMULATOR_START_TIME)

    # Get analysisd stats
    analysisd_state = utils.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])

    # Check that wazuh-manager is processing syslog events
    assert events_received > 0, '(0): No events are being received when it is expected'
    assert events_processed > 0, 'No events are being processed when it is expected'

    # Wait for the event non-processing phase to arrive (limit reached)
    waiting_limit_time = ceil((test_metadata['maximum'] * test_metadata['timeframe']) / test_metadata['eps']) + 1  # Offset 1s
    time.sleep(waiting_limit_time)
    waited_simulator_time += waiting_limit_time

    # Get analysisd stats in limitation stage
    analysisd_state = utils.get_analysisd_state()
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])
    expected_processed_events = test_metadata['maximum'] * test_metadata['timeframe']

    # Check that the wazuh-manager is receiving events but it is not processing them due to the limitation
    assert events_received > 0, '(1): No events are being received when it is expected'
    assert events_processed == expected_processed_events, f"Events are being processed when the limit has been " \
                                                          f"reached. {events_processed} != {expected_processed_events}"

    # Wait until the limited timeframe has elapsed
    time.sleep(test_metadata['timeframe'] + 1 - waited_simulator_time)  # Offset 1s

    # Get analysisd stats in limitation stage
    analysisd_state = utils.get_analysisd_state()
    events_processed = int(analysisd_state['events_processed'])

    # Check whether events continue to be processed after blocking
    assert events_processed > 0, 'Event processing has not been continued after blocking'

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test2_configuration, test2_metadata), ids=test2_cases_ids)
def test_queueing_events_after_limitation(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                          configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check if after stopping processing events (due to limit reached), the received events are stored in
        the events queue if it is not full.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check that the initial events queue usage rate is 0%.
            - Calculate when the limit of processed events is reached, waits a few seconds for events to be stored in
              the events queue and takes a sample of the usage to check that it is higher than 0%.
            - Wait a few seconds and takes a second sample again, to check that the events queue usage is higher than
              the first sample.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that the queue usage at startup is 0%.
        - Check that the queue usage grows after stopping processing events.
        - Check that the queue usage continues to grow after stopping processing events.

    input_description:
        - The `configuration_queue_events_after_limit` file provides the module configuration for this test.
        - The `cases_queue_events_after_limit` file provides the test cases.
    """
    # Get initial queue usage
    analysisd_state = utils.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])

    # Check that there are no events in the queue
    assert event_queue_usage == 0.0, 'The initial events queue is not at 0%'

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                   'messages_number': test_metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Wait for the event non-processing stage (limit reached)
    waiting_limit_time = ceil((test_metadata['maximum'] * test_metadata['timeframe']) / test_metadata['eps']) + \
        SYSLOG_SIMULATOR_START_TIME
    time.sleep(waiting_limit_time)

    # Get queue usage in limitation stage
    analysisd_state = utils.get_analysisd_state()
    event_queue_usage_sample_1 = float(analysisd_state['event_queue_usage'])

    # Check that received and unprocessed events are being queued
    assert event_queue_usage_sample_1 > 0.0, 'Events received after processing limitation are not being queued'

    # Wait a few more seconds before passing the timeframe
    waiting_time_sample_2 = ceil((test_metadata['timeframe'] - waiting_limit_time) / 2)
    time.sleep(waiting_time_sample_2)

    # Get queue usage in limitation stage
    analysisd_state = utils.get_analysisd_state()
    event_queue_usage_sample_2 = float(analysisd_state['event_queue_usage'])

    # Check that events received and not processed are still being queued
    assert event_queue_usage_sample_2 > event_queue_usage_sample_1, 'Events queue has not grown as expected during ' \
                                                                    'event limitation'
    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test3_configuration, test3_metadata), ids=test3_cases_ids)
def test_dropping_events_when_queue_is_full(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                            configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check that after the event analysis block, if the events queue is full, the events are dropped.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check that the initial queue usage rate is 0%.
            - Calculate when the event analysis blocking phase is expected and the queue is full, then it measures the
              use of the event queue to check that it is 100%, and that the received events are being dropped.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that the initial queue is at 0%.
        - Check that after the event analysis block and the queue is full, events are still being received.
        - Check that no events are processed when it is expected.
        - Check that the event queue usage is at 100% when it is expected.
        - Check that all events received are being dropped because the queue is full.

    input_description:
        - The `configuration_dropping_events_when_queue_is_full` file provides the module configuration for this test.
        - The `cases_dropping_events_when_queue_is_full` file provides the test cases.
    """
    # Get initial queue usage
    analysisd_state = utils.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])

    # Check that there are no events in the queue
    assert event_queue_usage == 0.0, 'The initial events queue is not at 0%'

    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                   'messages_number': test_metadata['messages_number']}

    # Run syslog simulator thread
    syslog_simulator_thread = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters})
    syslog_simulator_thread.start()

    # Calculate the non-processing stage (limit reached)
    waiting_limit_time = ceil((test_metadata['maximum'] * test_metadata['timeframe']) / test_metadata['eps']) + \
        SYSLOG_SIMULATOR_START_TIME

    # Calculate the stage when the events queue is full (offset 4 sec to check all received-dropped events)
    waiting_time_queue_is_full = waiting_limit_time + ((QUEUE_EVENTS_SIZE / DEFAULT_MESSAGE_SIZE) / test_metadata['eps']) + 4
    time.sleep(waiting_time_queue_is_full)

    # Get analysisd stats
    analysisd_state = utils.get_analysisd_state()
    event_queue_usage = float(analysisd_state['event_queue_usage'])
    events_dropped = float(analysisd_state['events_dropped'])
    events_received = int(analysisd_state['events_received'])
    events_processed = int(analysisd_state['events_processed'])
    expected_processed_events = test_metadata['maximum'] * test_metadata['timeframe']

    # Check that events are received, not processed and that they are dropped when the queue is full
    assert events_received > 0, ' No events are being received when it is expected'
    assert events_processed == expected_processed_events, 'Events are being processed when they are' \
                                                          ' not expected (due to the limit)'
    assert event_queue_usage == 1.0, 'The events queue is not full as expected'
    assert events_dropped > 10000, 'No events are being dropped even though the queue is full'

    # Wait until syslog simulator ends
    syslog_simulator_thread.join()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test4_configuration, test4_metadata), ids=test4_cases_ids)
@pytest.mark.parametrize('configure_local_internal_options', [t4_local_internal_options], indirect=True)
def test_event_processing_in_order_single_thread(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                                 configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check that events are processed in order according to the position within the queue, and
        that events that are being received during the blocking phase are being added to the end of the queue when
        using single-thread processing.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh event logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send a batch of identified events.
            - Wait a few seconds, then send another batch of identified events.
            - Wait until all events are processed.
            - Read the event log (archives.log) and check that the events have been processed in the expected order.
        - teardown:
            - Truncate wazuh event logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that all expected events have been stored in the archives.log.
        - Check that all events have been generated in the archives.log according to the expected order.

    input_description:
        - The `configuration_event_processing_in_order_single_thread` file provides the module configuration for this
          test.
        - The `cases_event_processing_in_order_single_thread` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    syslog_simulator_parameters_1 = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                     'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                     'messages_number': test_metadata['messages_number_1'], 'message': test_metadata['message'],
                                     'numbered_messages': test_metadata['numbered_messages']}

    # Run syslog simulator thread
    syslog_simulator_thread_1 = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters_1})
    syslog_simulator_thread_1.start()

    # Wait until the first processing interval has passed.
    waiting_time = test_metadata['timeframe']
    time.sleep(waiting_time)

    # Run syslog simulator to send new events when events sent previously still have to be processed
    # (they are in the queue)
    syslog_simulator_parameters_2 = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                     'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                     'messages_number': test_metadata['messages_number_2'], 'message': test_metadata['message'],
                                     'numbered_messages': test_metadata['messages_number_1'] + 1}
    syslog_simulator_thread_2 = thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': syslog_simulator_parameters_2})
    syslog_simulator_thread_2.start()

    # Wait until all events have been processed
    waiting_time = ((test_metadata['messages_number_1'] + test_metadata['messages_number_2']) /
                    (test_metadata['maximum'] * test_metadata['timeframe'])) * test_metadata['timeframe'] + SYSLOG_SIMULATOR_START_TIME
    time.sleep(waiting_time)

    # Read the events log data
    events_data = file.read_file(ARCHIVES_LOG_PATH).split('\n')
    expected_num_events = test_metadata['messages_number_1'] + test_metadata['messages_number_2']

    # Check that all events have been recorded in the log file
    assert len(events_data) >= expected_num_events, \
        f"Not all expected events were found in the archives.log. Found={len(events_data)}, " \
        f"expected>={expected_num_events}"

    # Get the IDs of event messages
    event_ids = [int(re.search(fr"{test_metadata['message']} - (\d+)", event).group(1)) for event in events_data
                 if bool(re.match(fr".*{test_metadata['message']} - (\d+)", event))]

    # Check that the event message IDs are in order
    assert all(event_ids[i] <= event_ids[i+1] for i in range(len(event_ids) - 1)), 'Events have not been processed ' \
                                                                                   'in the expected order'

    # Wait until syslog simulator ends
    syslog_simulator_thread_1.join()
    syslog_simulator_thread_2.join()


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test5_configuration, test5_metadata), ids=test5_cases_ids)
def test_event_processing_in_order_multi_thread(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                                                configure_local_internal_options, truncate_monitored_files, daemons_handler):
    """
    description: Check that events are processed in order according to the position within the queue, and
        that events that are being received during the blocking phase are being added to the end of the queue when
        using multi-thread processing.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh event logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Send a batch of identified events.
            - Wait a few seconds, then send another batch of identified events. This is repeated n times.
            - Wait until all events are processed.
            - Read the event log (archives.log) and check that the events have been processed in the expected order.
        - teardown:
            - Truncate wazuh event logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check that all expected events have been stored in the archives.log.
        - Check that all events have been generated in the archives.log according to the expected order.

    input_description:
        - The `configuration_event_processing_in_order_multi_thread` file provides the module configuration for this
          test.
        - The `cases_event_processing_in_order_multi_thread` file provides the test cases.
    """
    # Set syslog simulator parameters according to the use case data
    parameters = []
    syslog_simulator_threads = []
    syslog_simulator_parameters = {'address': test_metadata['address'], 'port': test_metadata['port'],
                                   'protocol': test_metadata['protocol'], 'eps': test_metadata['eps'],
                                   'messages_number': test_metadata['messages_number'], 'message': test_metadata['message_1']}
    # Create syslog simulator threads
    for index in range(test_metadata['num_batches']):
        parameters.append(deepcopy(syslog_simulator_parameters))
        parameters[index].update({'message': test_metadata[f"message_{index + 1}"]})
        syslog_simulator_threads.append(thread_executor.ThreadExecutor(run_syslog_simulator.syslog_simulator, {'parameters': parameters[index]}))

    # Start syslog simulator threads
    for thread in syslog_simulator_threads:
        thread.start()
        time.sleep(test_metadata['batch_sending_time'])

    # Wait until all events have been processed
    waiting_time_to_process_all_events = \
        ((test_metadata['messages_number'] * test_metadata['num_batches']) /
         (test_metadata['maximum'] * test_metadata['timeframe'])) * test_metadata['timeframe'] + SYSLOG_SIMULATOR_START_TIME

    waited_time_to_create_threads = test_metadata['batch_sending_time'] * test_metadata['num_batches']
    time.sleep(waiting_time_to_process_all_events - waited_time_to_create_threads)

    # Read the events log data
    events_data = file.read_file(ARCHIVES_LOG_PATH).split('\n')
    expected_num_events = test_metadata['batch_sending_time'] * test_metadata['num_batches']

    # Check that all events have been recorded in the log file
    assert len(events_data) >= expected_num_events, \
        f"Not all expected events were found in the archives.log. Found={len(events_data)}, " \
        f"expected>={expected_num_events}"

    # Get the IDs of event messages
    event_ids = [int(re.search(fr"{test_metadata['message_1']} - Group (\d+)", event).group(1)) for event in events_data
                 if bool(re.match(fr".*{test_metadata['message_1']} - Group (\d+)", event))]

    # Check that the event message IDs are in order
    assert all(event_ids[i] <= event_ids[i+1] for i in range(len(event_ids) - 1)), 'Events have not been processed ' \
                                                                                   'in the expected order'
    # Wait until all syslog simulator threads finish
    for thread in syslog_simulator_threads:
        thread.join()
