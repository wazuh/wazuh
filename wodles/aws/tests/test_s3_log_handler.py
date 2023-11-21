# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
import io
from unittest.mock import patch, MagicMock, call
import pytest
import json

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'subscribers'))
import s3_log_handler

SAMPLE_PARQUET_KEY = 'aws/source/region=region/accountId=accountID/eventHour=YYYYMMDDHH/file.gz.parquet'
SAMPLE_MESSAGE = {'bucket_path': utils.TEST_MESSAGE, 'log_path': SAMPLE_PARQUET_KEY}
SAMPLE_PARQUET_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
logs_path = os.path.join(test_data_path, 'log_files')


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


@pytest.mark.parametrize("content, expected", [
    ({'example1': None, 'example2': 'some_value'}, {'example2': 'some_value'}),
    ({'example1': {'a': None, 'b': None}, 'example2': {'a': 1, 'b': None}},
     {'example1': {}, 'example2': {'a': 1}})
])
def test_protected_remove_none_fields(content, expected):
    """Test the '_remove_none_fields' function of AWSSubscriberBucket class."""
    s3_log_handler.AWSSubscriberBucket._remove_none_fields(content)
    assert content == expected

@pytest.mark.parametrize("content, expected_calls", [
    (['{"event1": "data1"}', '{"event2": "data2"}'], [call('{"event1": "data1"}', dump_json=False), call('{"event2": "data2"}', dump_json=False)])
])
def test_protected_process_jsonl(content, expected_calls):
    """Test the 'process_file' function of AWSSubscriberBucket class."""
    aws_ssl_subscriber_bucket = utils.get_mocked_aws_sl_subscriber_bucket()
    message_body = {'bucket_path': 'example-bucket', 'log_path': 'example-log.parquet'}
    mocked_obtain_logs = MagicMock(return_value=content)
    aws_ssl_subscriber_bucket.obtain_logs = mocked_obtain_logs

    with patch.object(aws_ssl_subscriber_bucket, 'send_msg') as mock_send_msg:
        aws_ssl_subscriber_bucket.process_file(message_body)

    mocked_obtain_logs.assert_called_once_with(bucket='example-bucket', log_path='example-log.parquet')
    mock_send_msg.assert_has_calls(expected_calls)
