# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import botocore
import copy
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

import wodles.aws.tests.aws_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils
import aws_constants as test_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'services'))
import aws_service
import cloudwatchlogs

TEST_LOG_GROUP = 'test_log_group'
TEST_LOG_STREAM = 'test_stream'
TEST_START_TIME = 1640996200000
TEST_END_TIME = 1659355591835
TEST_TOKEN = 'f/12345678123456781234567812345678123456781234567812345678/s'

TEST_CLOUDWATCH_SCHEMA = "schema_cloudwatchlogs_test.sql"


@pytest.mark.parametrize('only_logs_after', [test_constants.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('aws_log_groups', [TEST_LOG_GROUP, None])
@pytest.mark.parametrize('remove_log_streams', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_aws_cloudwatchlogs_initializes_properly(mock_aws_service, mock_sts_client,
                                    remove_log_streams: bool, aws_log_groups: str or None,
                                    only_logs_after: str or None):
    """Test if the instances of AWSCloudWatchLogs are created properly.

    Parameters
    ----------
    aws_log_groups: str or None
        Log group names.
    only_logs_after: str or None
        Date after which obtain logs.
    remove_log_streams: bool
        Indicate if log streams should be removed after being fetched.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs,
                                        remove_log_streams=remove_log_streams,
                                        aws_log_groups=aws_log_groups,
                                        only_logs_after=only_logs_after)

    mock_aws_service.assert_called_once()
    assert instance.log_group_list == (
        [group for group in aws_log_groups.split(",") if group != ""] if aws_log_groups else [])
    assert instance.remove_log_streams == remove_log_streams
    assert instance.only_logs_after_millis == (int(datetime.strptime(only_logs_after, '%Y%m%d').replace(
        tzinfo=timezone.utc).timestamp() * 1000) if only_logs_after else None)
    assert instance.default_date_millis == int(instance.default_date.timestamp() * 1000)


@pytest.mark.parametrize('remove_log_streams', [True, False])
@pytest.mark.parametrize('only_logs_after', [test_constants.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('reparse', [True, False])
@patch('wazuh_integration.WazuhAWSDatabase.init_db')
@patch('wazuh_integration.WazuhAWSDatabase.close_db')
@patch('cloudwatchlogs.AWSCloudWatchLogs.purge_db')
@patch('cloudwatchlogs.AWSCloudWatchLogs.update_values')
@patch('cloudwatchlogs.AWSCloudWatchLogs.get_data_from_db')
@patch('cloudwatchlogs.AWSCloudWatchLogs.get_alerts_within_range')
@patch('cloudwatchlogs.AWSCloudWatchLogs.get_log_streams', return_value=[TEST_LOG_STREAM])
@patch('cloudwatchlogs.AWSCloudWatchLogs.remove_aws_log_stream')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_get_alerts(mock_debug, mock_sts_client, mock_remove_aws_log_stream, mock_get_log_streams,
                                       mock_get_alerts_within_range, mock_get_data_from_db,
                                       mock_update_values, mock_purge, mock_close, mock_init,
                                       reparse: bool, only_logs_after: str or None, remove_log_streams: bool):
    """Test 'get_alerts' method makes the expected calls in order to fetch the events and send them to Analysisd.

    Parameters
    ----------
    reparse: bool
        Whether to parse already parsed logs or not.
    only_logs_after: str or None
        Date after which obtain logs.
    remove_log_streams: bool
        Indicate if log streams should be removed after being fetched.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs, aws_log_groups=TEST_LOG_GROUP,
                                        reparse=reparse, remove_log_streams=remove_log_streams,
                                        only_logs_after=only_logs_after)

    data_from_db = {
        'token': TEST_TOKEN,
        'start_time': TEST_START_TIME,
        'end_time': TEST_END_TIME
    }

    mock_get_log_streams.return_value = [TEST_LOG_STREAM]
    mock_get_data_from_db.return_value = data_from_db

    instance.get_alerts()

    if reparse:
        mock_debug.assert_any_call('Reparse mode ON', 1)

    mock_init.assert_called_once()

    if instance.remove_log_streams:
        mock_remove_aws_log_stream.assert_called()

    mock_get_alerts_within_range.assert_called()

    mock_update_values.assert_called()
    mock_purge.assert_called()
    mock_close.assert_called_once()


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_remove_aws_log_stream(mock_debug, mock_sts_client):
    """Test 'remove_aws_log_stream' method makes the necessary calls in order to remove the specified log stream
    from AWS Cloudwatch Logs."""
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_delete_log_stream = instance.client.delete_log_stream

    instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)
    mock_debug.assert_any_call(
        'Removing log stream "{}" from log group "{}"'.format(TEST_LOG_GROUP, TEST_LOG_STREAM), 1)
    mock_delete_log_stream.assert_called_once_with(logGroupName=TEST_LOG_GROUP, logStreamName=TEST_LOG_STREAM)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_remove_aws_log_stream_handles_exceptions(mock_debug, mock_sts_client):
    """Test 'remove_aws_log_stream' method handles exceptions raised when trying
    to remove a log stream from a log group.
    This could be due to a botocore ClientError or another type of Exception.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_delete_log_stream = instance.client.delete_log_stream

    mock_delete_log_stream.side_effect = Exception
    instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)

    mock_debug.assert_any_call(
        'ERROR: Error trying to remove "{}" log stream from "{}" log group.'.format(TEST_LOG_STREAM, TEST_LOG_GROUP), 0)

    mock_delete_log_stream.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE}}, "name")
    with pytest.raises(SystemExit) as e:
        instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)
    assert e.value.code == wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE


@pytest.mark.parametrize('end_time', [None, TEST_END_TIME - 1])
@pytest.mark.parametrize('start_time', [None, TEST_START_TIME + 1])
@pytest.mark.parametrize('timestamp', [TEST_END_TIME, TEST_START_TIME])
@pytest.mark.parametrize('token', [None, TEST_TOKEN])
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_get_alerts_within_range(mock_debug, mock_sts_client, mock_send_msg,
                                                    token: str or None, timestamp: int,
                                                    start_time: int or None, end_time: int or None):
    """Test 'get_alerts_within_range' method makes the necessary calls in order
    to get the events from AWS CloudWatch Logs, send them to Analysisd and return the expected token and timestamps.


    Parameters
    ----------
    token: str
        Token to the next set of logs.
    timestamp: int
        Expected timestamp to be retrieved inside the get_log_events response.
    start_time : int or None
        The start of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
    end_time : int or None
        The end of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()

    mock_client_get_log_events = instance.client.get_log_events

    min_start_time = start_time
    max_end_time = end_time if end_time is not None else start_time

    expected_response_with_events = {
        'events': [
            {
                'timestamp': timestamp,
                'message': 'someMsg',
                'ingestionTime': 123
            },
        ],
        'nextForwardToken': token,
        'nextBackwardToken': 'string'
    }

    expected_response_without_events = copy.deepcopy(expected_response_with_events)
    expected_response_without_events['events'] = []
    expected_response_without_events['nextForwardToken'] = token

    if min_start_time is None:
        min_start_time = expected_response_with_events['events'][0]['timestamp']
    elif expected_response_with_events['events'][0]['timestamp'] < start_time:
        min_start_time = expected_response_with_events['events'][0]['timestamp']

    if max_end_time is None:
        max_end_time = expected_response_with_events['events'][0]['timestamp']
    elif expected_response_with_events['events'][0]['timestamp'] > max_end_time:
        max_end_time = expected_response_with_events['events'][0]['timestamp']

    expected_result = {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}

    mock_client_get_log_events.side_effect = [botocore.exceptions.EndpointConnectionError(endpoint_url='example.com'),
                                              expected_response_with_events, expected_response_without_events]

    assert expected_result == instance.get_alerts_within_range(TEST_LOG_GROUP, TEST_LOG_STREAM, token, start_time,
                                                               end_time)

    mock_send_msg.assert_any_call(expected_response_with_events['events'][0]['message'], dump_json=False)
    mock_debug.assert_any_call(f'WARNING: The "get_log_events" request was denied because the endpoint URL was not '
                               f'available. Attempting again.', 1)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
def test_aws_cloudwatchlogs_get_alerts_within_range_handles_exceptions_on_client_error(mock_sts_client):
    """Test 'get_alerts_within_range' method handles exceptions raised
    when trying to get log events from AWS CloudWatch Logs.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()

    mock_client_get_log_events = instance.client.get_log_events

    mock_client_get_log_events.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE}}, "name")
    with pytest.raises(SystemExit) as e:
        instance.get_alerts_within_range(TEST_LOG_GROUP, TEST_LOG_STREAM, 'token', TEST_START_TIME, TEST_END_TIME)
    assert e.value.code == wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
def test_aws_cloudwatchlogs_get_data_from_db(mock_sts_client, custom_database):
    """Test 'get_data_from_db' method retrieves the expected information from the DB.
    """
    utils.database_execute_script(custom_database, TEST_CLOUDWATCH_SCHEMA)

    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs, region=test_constants.TEST_REGION)

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    assert {'token': TEST_TOKEN,
            'start_time': TEST_START_TIME,
            'end_time': TEST_END_TIME} == instance.get_data_from_db(TEST_LOG_GROUP, TEST_LOG_STREAM)


@pytest.mark.parametrize('values', [None,
                                    {'token': TEST_TOKEN, 'start_time': TEST_START_TIME, 'end_time': TEST_END_TIME},
                                    {'token': TEST_TOKEN, 'start_time': None, 'end_time': None}
                                    ])
@pytest.mark.parametrize('result_after', [None,
                                          {'token': TEST_TOKEN, 'start_time': TEST_START_TIME + 1,
                                           'end_time': TEST_END_TIME + 1}])
@pytest.mark.parametrize('result_before', [None,
                                           {'token': TEST_TOKEN, 'start_time': TEST_START_TIME - 1,
                                            'end_time': TEST_END_TIME - 1}])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
def test_aws_cloudwatchlogs_update_values(mock_sts_client, result_before: dict or None, result_after: dict or None,
                                          values: dict or None):
    """Test 'update_values' method returns the expected dict with the results of previous executions.

    Parameters
    ----------
    result_before: dict or None
        A dict containing the token, start_time and end_time values to be updated.
    result_after: dict or None
        A dict containing the expected token, start_time and end_time values of a 'get_alerts_within_range' execution.
    values: dict or None
        A dict containing the expected token, start_time and end_time values of a 'get_alerts_within_range' execution.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    token = TEST_TOKEN if result_before or result_after else None
    start_time = None
    end_time = None

    if values or result_after or result_before:
        start_time = min(
            (value['start_time'] for value in [values, result_before, result_after] if value and value['start_time']),
            default=None)

        end_time = max(
            (value['end_time'] for value in [values, result_before, result_after] if value and value['end_time']),
            default=None)

        if values:
            if not values['start_time']:
                start_time = max(
                    (value['end_time'] for value in [values, result_before, result_after] if
                     value and value['end_time']),
                    default=None)
            if not values['end_time']:
                end_time = max(
                    (value['end_time'] for value in [values, result_before, result_after] if
                     value and value['end_time']),
                    default=None)

    result = {
        'token': token,
        'start_time': start_time,
        'end_time': end_time
    }

    assert result == instance.update_values(values, result_after, result_before)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_save_data_db(mock_debug, mock_sts_client, custom_database):
    """Test 'save_data_db' method inserts token, start_time and end_time values into the DB and updates them if
    already exist.
    """
    utils.database_execute_script(custom_database, TEST_CLOUDWATCH_SCHEMA)

    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs, region=test_constants.TEST_REGION)

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    instance.save_data_db(TEST_LOG_GROUP, TEST_LOG_STREAM,
                          {'token': TEST_TOKEN, 'start_time': TEST_START_TIME, 'end_time': TEST_END_TIME})

    assert utils.database_execute_query(instance.db_connector,
                                        instance.sql_cloudwatch_select.format(table_name=instance.db_table_name), {
                                            'aws_region': instance.region,
                                            'aws_log_group': TEST_LOG_GROUP,
                                            'aws_log_stream': TEST_LOG_STREAM})[2] == TEST_END_TIME

    instance.save_data_db(TEST_LOG_GROUP, TEST_LOG_STREAM,
                          {'token': TEST_TOKEN, 'start_time': TEST_START_TIME, 'end_time': TEST_END_TIME + 1})

    assert utils.database_execute_query(instance.db_connector,
                                        instance.sql_cloudwatch_select.format(table_name=instance.db_table_name), {
                                            'aws_region': instance.region,
                                            'aws_log_group': TEST_LOG_GROUP,
                                            'aws_log_stream': TEST_LOG_STREAM})[2] == TEST_END_TIME + 1

    mock_debug.assert_any_call("Some data already exists on DB for that key. Updating their values...", 2)


@pytest.mark.parametrize('describe_log_streams_response, expected_result_list',
                         [([{
                             'logStreams': [
                                 {
                                     'logStreamName': TEST_LOG_STREAM,
                                 },
                             ],
                             'nextToken': 'string'
                         }, {
                             'logStreams': [
                                 {
                                     'logStreamName': 'next_log_stream',
                                 },
                             ]
                         }], [TEST_LOG_STREAM, 'next_log_stream']),
                             ([{
                                 'logStreams': []
                             }], [])
                         ])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_get_log_streams(mock_debug, mock_sts_client,
                                            describe_log_streams_response, expected_result_list: list[str]):
    """Test 'get_log_streams' method retrieves the log streams from
    the response of describe_log_streams with the specified log group.

    Parameters
    ----------
    describe_log_streams_response: list[dict]
        List of the different responses that can be received.
    expected_result_list: list[str]
        Expected list of log streams to be returned by the method.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_describe_log_streams = instance.client.describe_log_streams

    mock_describe_log_streams.side_effect = describe_log_streams_response

    result_list = instance.get_log_streams(TEST_LOG_GROUP)

    if not result_list:
        mock_debug.assert_any_call('No log streams were found for log group "{}"'.format(TEST_LOG_GROUP), 1)

    assert expected_result_list == result_list


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_aws_cloudwatchlogs_get_log_streams_handles_exceptions(mock_debug, mock_sts_client):
    """Test 'get_log_streams' method handles exceptions raised when trying to fetch the log streams
    from the specified log group.
    This could be due to a botocore Error or another type of Exception.
    """
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_describe_log_streams = instance.client.describe_log_streams

    mock_describe_log_streams.side_effect = Exception
    instance.get_log_streams(TEST_LOG_GROUP)
    mock_debug.assert_any_call(
        '++++ The specified "{}" log group does not exist or insufficient privileges to access it.'.format(
            TEST_LOG_GROUP), 0)

    mock_describe_log_streams.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE}}, "name")
    with pytest.raises(SystemExit) as e:
        instance.get_log_streams(TEST_LOG_GROUP)
    assert e.value.code == wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.AWSCloudWatchLogs.get_log_streams', return_value=[])
def test_aws_cloudwatchlogs_purge_db(mock_get_log_streams, mock_sts_client, custom_database):
    """Test 'purge_db' method removes the records for log streams when they no longer exist on AWS CloudWatch Logs."""
    utils.database_execute_script(custom_database, TEST_CLOUDWATCH_SCHEMA)

    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs, region=test_constants.TEST_REGION)

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    instance.db_table_name = 'cloudwatch_logs'

    assert utils.database_execute_query(instance.db_connector,
                                        constants.SQL_COUNT_ROWS.format(table_name=instance.db_table_name)) == 1

    instance.purge_db(TEST_LOG_GROUP)

    assert utils.database_execute_query(instance.db_connector,
                                        constants.SQL_COUNT_ROWS.format(table_name=instance.db_table_name)) == 0
