import os
import sys
import botocore
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_service
import cloudwatchlogs

TEST_LOG_GROUP = 'test_log_group'
TEST_LOG_STREAM = 'test_stream'


@pytest.mark.parametrize('only_logs_after', [utils.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('aws_log_groups', [TEST_LOG_GROUP, None])
@pytest.mark.parametrize('remove_log_streams', [True, False])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('aws_service.AWSService.__init__', side_effect=aws_service.AWSService.__init__)
def test_AWSCloudWatchLogs__init__(mock_aws_service, mock_sts_client, remove_log_streams, aws_log_groups,
                                   only_logs_after):
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


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_alerts():
    pass


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_AWSCloudWatchLogs_remove_aws_log_stream(mock_debug, mock_sts_client):
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_delete_log_stream = instance.client.delete_log_stream

    instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)
    mock_debug.assert_any_call(
        'Removing log stream "{}" from log group "{}"'.format(TEST_LOG_GROUP, TEST_LOG_STREAM), 1)
    mock_delete_log_stream.assert_called_once_with(logGroupName=TEST_LOG_GROUP, logStreamName=TEST_LOG_STREAM)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('cloudwatchlogs.aws_tools.debug')
def test_AWSCloudWatchLogs_remove_aws_log_stream_ko(mock_debug, mock_sts_client):
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_delete_log_stream = instance.client.delete_log_stream

    mock_delete_log_stream.side_effect = Exception
    instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)
    mock_debug.assert_any_call(
        'Error trying to remove "{}" log stream from "{}" log group.'.format(TEST_LOG_STREAM, TEST_LOG_GROUP), 0)

    mock_delete_log_stream.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': utils.THROTTLING_ERROR_CODE}}, "name")
    with pytest.raises(SystemExit) as e:
        instance.remove_aws_log_stream(TEST_LOG_GROUP, TEST_LOG_STREAM)
    assert e.value.code == utils.THROTTLING_ERROR_CODE


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_alerts_within_range():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_get_data_from_db():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_update_values():
    pass


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_save_data_db():
    pass


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
def test_AWSCloudWatchLogs_get_log_streams(mock_debug, mock_sts_client, describe_log_streams_response,
                                           expected_result_list):
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
def test_AWSCloudWatchLogs_get_log_streams_ko(mock_debug, mock_sts_client):
    instance = utils.get_mocked_service(class_=cloudwatchlogs.AWSCloudWatchLogs)

    instance.client = MagicMock()
    mock_describe_log_streams = instance.client.describe_log_streams

    mock_describe_log_streams.side_effect = Exception
    instance.get_log_streams(TEST_LOG_GROUP)
    mock_debug.assert_any_call(
        '++++ The specified "{}" log group does not exist or insufficient privileges to access it.'.format(
            TEST_LOG_GROUP), 0)

    mock_describe_log_streams.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': utils.THROTTLING_ERROR_CODE}}, "name")
    with pytest.raises(SystemExit) as e:
        instance.get_log_streams(TEST_LOG_GROUP)
    assert e.value.code == utils.THROTTLING_ERROR_CODE


@pytest.mark.skip("Not implemented yet")
def test_AWSCloudWatchLogs_purge_db():
    pass
