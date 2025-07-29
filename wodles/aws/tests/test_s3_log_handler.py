# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import io
import re
from unittest.mock import patch, MagicMock, call
import pytest
import json
import datetime

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'subscribers'))
import s3_log_handler

SAMPLE_PARQUET_KEY = 'aws/source/region=region/accountId=accountID/eventHour=YYYYMMDDHH/file.gz.parquet'
SAMPLE_MESSAGE = {'bucket_path': utils.TEST_MESSAGE, 'log_path': SAMPLE_PARQUET_KEY}
SAMPLE_PARQUET_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}
SAMPLE_PARQUET_EVENT_WITH_DATETIME = {"timestamp": datetime.datetime(2024, 9, 18, 12, 0, 0),
                                       "event": "sample_event"}

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_path = os.path.join(test_data_path, 'log_files')


def test_method_raises_not_implemented():
    """Test that obtain_logs and process_file methods raise NotImplementedError."""
    handler = s3_log_handler.AWSS3LogHandler()
    with pytest.raises(NotImplementedError):
        handler.obtain_logs("test_bucket", "test_log_path")

    with pytest.raises(NotImplementedError):
        handler.process_file({"message": "test_message"})


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effet=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sl_subscriber_bucket_initializes_properly(mock_wazuh_integration, mock_client, mock_sts_client):
    """Test if the instances of AWSSLSubscriberBucket are created properly."""
    kwargs = utils.get_aws_s3_log_handler_parameters(iam_role_arn=utils.TEST_IAM_ROLE_ARN,
                                                     iam_role_duration=utils.TEST_IAM_ROLE_DURATION,
                                                     service_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                     sts_endpoint=utils.TEST_STS_ENDPOINT)

    integration = s3_log_handler.AWSSLSubscriberBucket(**kwargs)

    mock_wazuh_integration.assert_called_with(integration, access_key=None, secret_key=None,
                                              profile=None,
                                              service_name='s3',
                                              sts_endpoint=kwargs["sts_endpoint"],
                                              service_endpoint=kwargs["service_endpoint"],
                                              iam_role_arn=kwargs['iam_role_arn'],
                                              iam_role_duration=kwargs['iam_role_duration'],
                                              )


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sl_subscriber_bucket_obtain_logs(mock_wazuh_integration, mock_sts_client):
    """Test 'obtain_information_from_parquet' fetches parquets from a bucket and retrieves the expected list of
    events."""
    instance = utils.get_mocked_aws_sl_subscriber_bucket()
    mock_get_object = instance.client.get_object

    with patch('io.BytesIO', return_value=(os.path.join(logs_path, 'AWSSecurityLake', 'test_file.parquet'))):
        events = instance.obtain_logs(utils.TEST_BUCKET, SAMPLE_PARQUET_KEY)

    assert events == [json.dumps(SAMPLE_PARQUET_EVENT_1)]
    mock_get_object.assert_called_with(Bucket=utils.TEST_BUCKET, Key=SAMPLE_PARQUET_KEY)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sl_subscriber_bucket_obtain_logs_with_datetime(mock_wazuh_integration, mock_sts_client):
    """Test 'obtain_information_from_parquet' correctly processes events containing datetime objects."""
    instance = utils.get_mocked_aws_sl_subscriber_bucket()
    mock_get_object = instance.client.get_object

    with patch('pyarrow.parquet.ParquetFile', return_value=MagicMock()) as mock_parquet_file:
        mock_parquet_file.return_value.iter_batches.return_value = [MagicMock(to_pylist=lambda: [SAMPLE_PARQUET_EVENT_WITH_DATETIME])]
        with patch('io.BytesIO', return_value=b"fake parquet data"):
            events = instance.obtain_logs(utils.TEST_BUCKET, SAMPLE_PARQUET_KEY)

    assert events == [json.dumps(SAMPLE_PARQUET_EVENT_WITH_DATETIME, default=str)]
    mock_get_object.assert_called_with(Bucket=utils.TEST_BUCKET, Key=SAMPLE_PARQUET_KEY)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sl_subscriber_bucket_obtain_logs_handles_exception(mock_wazuh_integration,
                                                                                    mock_sts_client):
    """Test 'obtain_information_from_parquet' handles exceptions raised when failing to process a parquet file."""
    instance = utils.get_mocked_aws_sl_subscriber_bucket()

    instance.client.get_object.side_effect = Exception

    with pytest.raises(SystemExit) as e:
        instance.obtain_logs(utils.TEST_BUCKET, SAMPLE_PARQUET_KEY)
    assert e.value.code == utils.UNABLE_TO_FETCH_DELETE_FROM_QUEUE


@patch('s3_log_handler.AWSSLSubscriberBucket.obtain_logs')
@patch('wazuh_integration.WazuhIntegration.send_msg')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sl_subscriber_bucket_process_file(mock_wazuh_integration, mock_sts_client, mock_send, mock_obtain):
    """Test 'process_file' method sends the events inside the given message to AnalysisD."""
    instance = utils.get_mocked_aws_sl_subscriber_bucket()

    mock_obtain.return_value = SAMPLE_PARQUET_EVENT_1

    instance.process_file(SAMPLE_MESSAGE)

    mock_obtain.assert_called_once_with(bucket=SAMPLE_MESSAGE['bucket_path'],
                                        log_path=SAMPLE_MESSAGE['log_path'])
    mock_send.assert_called()


@pytest.mark.parametrize("content, is_csv",
                         [
                             ("Name, Age, City\nJohn, 30, New York", True),
                             ("Name1, Age, City\nJohn, 30, New York", False),
                             ("", True),
                         ])
def test_is_csv(content, is_csv):
    """Test the 'is_csv' function of AWSSubscriberBucket class."""
    valid_csv_file = io.StringIO(content)
    assert s3_log_handler.AWSSubscriberBucket.is_csv(valid_csv_file) == is_csv

@pytest.mark.parametrize("content, expected",
                         [
                             (['{"event1": "data1"}', '{"event2": "data2"}'],
                              [{'event1': 'data1'}, {'event2': 'data2'}])
                         ])
def test_process_jsonl(content, expected):
    """Test the '_process_jsonl' function of AWSSubscriberBucket class."""
    assert s3_log_handler.AWSSubscriberBucket._process_jsonl(content) == expected


def test_json_event_generator():
    """Test the _json_event_generator function of AWSSubscriberBucket class."""
    data = '{"event": "data1"}{"event": "data2"}'
    generator = s3_log_handler.AWSSubscriberBucket._json_event_generator(data)
    events = list(generator)
    assert events == [{"event": "data1"}, {"event": "data2"}]


@pytest.mark.parametrize("content, expected", [
    ({'example1': None, 'example2': 'some_value'}, {'example2': 'some_value'}),
    ({'example1': {'a': None, 'b': None}, 'example2': {'a': 1, 'b': None}},
     {'example1': {}, 'example2': {'a': 1}})
])
def test_protected_remove_none_fields(content, expected):
    """Test the '_remove_none_fields' function of AWSSubscriberBucket class."""
    s3_log_handler.AWSSubscriberBucket._remove_none_fields(content)
    assert content == expected


@pytest.mark.parametrize(
    "bucket_name, log_path, content, expected_logs",
    [
        (
            "test_bucket",
            "logs/sample.jsonl.gz",
            '{"event": "data1"}\n{"event": "data2"}\n',
            [{"event": "data1"}, {"event": "data2"}],
        ),
        (
            "test_bucket",
            "logs/sample.csv",
            "Name, Age, City\nJohn, 30, New York",
            [{"Age": "30", "City": "New York", "Name": "John", "source": "custom"}],
        ),
    ],
    ids=[
        "JSONL Sample Data",
        "CSV Sample Data",
    ],
)
def test_obtain_logs_processes_different_data_types(bucket_name, log_path, content, expected_logs):
    """Test the 'obtain_logs' function of AWSSubscriberBucket class."""
    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        with patch('s3_log_handler.AWSSubscriberBucket.decompress_file', return_value=io.StringIO(content)):
            formatted_logs = s3_log_handler.AWSSubscriberBucket().obtain_logs(bucket=bucket_name, log_path=log_path)

            assert formatted_logs == expected_logs
            assert formatted_logs is not None


@patch('s3_log_handler.aws_tools.debug')
def test_process_file_sends_expected_messages(mock_debug):
    """Test the 'process_file' function of AWSSubscriberBucket class."""
    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        processor = s3_log_handler.AWSSubscriberBucket()
        processor.discard_regex = re.compile('your_regex_pattern_here')
        processor.discard_field = 'your_discard_field_value'

        message_body = {'log_path': 'log.txt', 'bucket_path': 'bucket'}
        formatted_logs = [{'full_log': 'some log entry matching discard regex'}]

        processor.obtain_logs = MagicMock(return_value=formatted_logs)
        processor.event_should_be_skipped = MagicMock(return_value=False)
        processor.send_msg = MagicMock()

        formatted_logs_no_full_log = [{'other_field': 'some value'}]
        processor.obtain_logs.return_value = formatted_logs_no_full_log
        processor.process_file(message_body)

        expected_msg = {
            'integration': 'aws',
            'aws': {
                'log_info': {
                    'log_file': 'log.txt',
                    's3bucket': 'bucket'
                }
            }
        }
        expected_msg['aws'].update(formatted_logs_no_full_log[0]) 
        processor.send_msg.assert_called_once_with(expected_msg)

        log_with_match = {'full_log': 'some log entry matching discard regex'}
        formatted_logs_with_match = [log_with_match]

        processor.send_msg.reset_mock()
        processor.obtain_logs.return_value = formatted_logs_with_match
        processor.process_file(message_body)
        processor.send_msg.assert_called_once()


@patch('s3_log_handler.aws_tools.debug')
def test_process_file_sends_multiple_messages(mock_debug):
    """Test that 'process_file' sends one message per log event."""
    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        processor = s3_log_handler.AWSSubscriberBucket()
        processor.discard_regex = re.compile('your_regex_pattern_here')
        processor.discard_field = 'your_discard_field_value'

        message_body = {'log_path': 'log.txt', 'bucket_path': 'bucket'}
        logs = [{'event': 'event1'}, {'event': 'event2'}]
        processor.obtain_logs = MagicMock(return_value=logs)
        processor.event_should_be_skipped = MagicMock(return_value=False)
        processor.send_msg = MagicMock()

        processor.process_file(message_body)

        expected_calls = []
        for log in logs:
            expected_msg = {
                'integration': 'aws',
                'aws': {
                    'log_info': {
                        'log_file': 'log.txt',
                        's3bucket': 'bucket'
                    }
                }
            }
            expected_msg['aws'].update(log)
            expected_calls.append(call(expected_msg))

        processor.send_msg.assert_has_calls(expected_calls)
        assert processor.send_msg.call_count == 2


@pytest.mark.parametrize("content, expected_calls", [
    (['{"event1": "data1"}', '{"event2": "data2"}'], [call('{"event1": "data1"}', dump_json=False), call('{"event2": "data2"}', dump_json=False)])
])
def test_protected_process_jsonl(content, expected_calls):
    """Test the 'process_file' function of AWSSLSubscriberBucket class."""
    aws_ssl_subscriber_bucket = utils.get_mocked_aws_sl_subscriber_bucket()
    message_body = {'bucket_path': 'example-bucket', 'log_path': 'example-log.parquet'}
    mocked_obtain_logs = MagicMock(return_value=content)
    aws_ssl_subscriber_bucket.obtain_logs = mocked_obtain_logs

    with patch.object(aws_ssl_subscriber_bucket, 'send_msg') as mock_send_msg:
        aws_ssl_subscriber_bucket.process_file(message_body)

    mocked_obtain_logs.assert_called_once_with(bucket='example-bucket', log_path='example-log.parquet')
    mock_send_msg.assert_has_calls(expected_calls)


@pytest.mark.parametrize("details, event", [
    ({'actionName': 'Test action name', 'actionDescription': 'Test action description'},
     {'actionName': 'Test action name', 'actionDescription': 'Test action description',
      'extra_key': 'value'}),
    ({'actionName': 'Test action name', 'actionDescription': 'Test action description',
      'insightResults': [{'key': 'value'}], 'insightName': 'insightName', 'insightArn': 'insightArn'},
     {'actionName': 'Test action name', 'actionDescription': 'Test action description',
      'insightResults': [{'key': 'value'}], 'insightName': 'insightName', 'insightArn': 'insightArn',
      'extra_key': 'value'}),
    ({'findings': [{'key': 'value'}]},
     {'finding': {'key': 'value'}, 'extra_key': 'value'})
])
def test_sec_hub_protected_add_event_type_fields(details, event):
    """Test the 'add_event_type_fields' function of AWSSecurityHubSubscriberBucket class."""
    base_event = dict(extra_key="value")
    s3_log_handler.AWSSecurityHubSubscriberBucket._add_event_type_fields(details, base_event)
    assert base_event == event


@pytest.mark.parametrize(
    "content, expected_logs",
    [
        (
            '{"detail": {"data1": "value"}, "detail-type": "Security Hub Type"}'
            '{"detail": {"data2": "value"}, "detail-type": "Security Hub Type"}',
            [{"data1": "value", "source": "securityhub", "detail_type": "Security Hub Type"},
             {"data2": "value", "source": "securityhub", "detail_type": "Security Hub Type"}],
        ),
    ]
)
def test_obtain_logs_processes_security_hub_events(content, expected_logs):
    """Test the 'obtain_logs' method of AWSSecurityHubSubscriberBucket class."""
    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        with patch('s3_log_handler.AWSSubscriberBucket.decompress_file', return_value=io.StringIO(content)):
            with patch("s3_log_handler.AWSSecurityHubSubscriberBucket._add_event_type_fields",
                       side_effect=lambda event, base: base.update(event)):
                formatted_logs = s3_log_handler.AWSSecurityHubSubscriberBucket().obtain_logs(bucket=utils.TEST_BUCKET,
                                                                                             log_path=utils.TEST_LOG_KEY
                                                                                             )
                assert formatted_logs == expected_logs
                assert formatted_logs is not None


def test_sec_hub_obtain_logs_handles_exception():
    """Test 'obtain_logs' handles exceptions raised when failing to process JSON files."""
    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        with patch('s3_log_handler.AWSSubscriberBucket.decompress_file'):
            with patch('s3_log_handler.AWSSubscriberBucket._json_event_generator', side_effect=[json.JSONDecodeError
                                                                                                ('test', 'test', 1),
                                                                                                AttributeError]):
                with pytest.raises(SystemExit) as e:
                    s3_log_handler.AWSSecurityHubSubscriberBucket().obtain_logs(bucket=utils.TEST_BUCKET,
                                                                                log_path=utils.TEST_LOG_KEY)
                assert e.value.code == utils.PARSE_FILE_ERROR_CODE


@pytest.mark.parametrize("discard_log", [True, False])
@patch('s3_log_handler.aws_tools.debug')
def test_sec_hub_process_file_sends_expected_messages(mock_debug, discard_log):
    """Test 'process_file' method of AWSSecurityHubSubscriberBucket the class sends the events inside the given
    message to AnalysisD."""
    log_file = utils.TEST_LOG_KEY
    bucket_path = utils.TEST_BUCKET
    message_body = {"log_path": log_file, "bucket_path": bucket_path}

    formatted_logs = [{"field": "value"}]

    with patch('s3_log_handler.wazuh_integration.WazuhIntegration.__init__'):
        with patch('s3_log_handler.AWSSecurityHubSubscriberBucket.obtain_logs', return_value=formatted_logs):
            with patch('s3_log_handler.AWSSecurityHubSubscriberBucket.event_should_be_skipped',
                       return_value=discard_log):
                log_handler = s3_log_handler.AWSSecurityHubSubscriberBucket()

                log_handler.discard_regex = re.compile('discard_regex')
                log_handler.discard_field = 'discard_field'

                log_handler.send_msg = MagicMock()
                log_handler.process_file(message_body)
                mock_debug.assert_called()
                for log in formatted_logs:
                    if not discard_log:
                        expected_msg = {
                            'integration': 'aws',
                            'aws': {
                                'log_info': {
                                    'log_file': log_file,
                                    's3bucket': bucket_path
                                }
                            }
                        }
                        expected_msg['aws'].update(log)
                        log_handler.send_msg.assert_called_with(expected_msg)
