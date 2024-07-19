# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
import sys
import botocore
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import vpcflow

VPC_SCHEMA_COUNT = 8

DAYS_DELTA = 10

TEST_VPCFLOW_SCHEMA = "schema_vpcflow_test.sql"
TEST_EMPTY_TABLE_SCHEMA = "schema_empty_vpc_table.sql"

TEST_FLOW_LOG_ID = 'fl-1234'
TEST_TABLE_NAME = 'vpcflow'
TEST_LOG_KEY = 'vpc/AWSLogs/123456789/vpcflowlogs/us-east-1/2019/04/15/123456789_vpcflowlogs_us-east-1_' \
               'fl-1234_20190415T0945Z_c23ab7.log.gz'
TEST_DATE = "2023/01/01"

SQL_GET_DATE_LAST_LOG_PROCESSED = """SELECT created_date FROM {table_name} ORDER BY log_key DESC LIMIT 1;"""
SQL_GET_ROW = "SELECT bucket_path, aws_account_id, aws_region, flow_log_id, log_key, created_date FROM {table_name};"
SQL_FIND_LAST_KEY_PROCESSED = """SELECT log_key FROM {table_name} ORDER BY log_key DESC LIMIT 1;"""


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_aws_vpc_flow_bucket_initializes_properly(mock_logs_bucket):
    """Test if the instances of AWSVPCFlowBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)
    assert instance.service == 'vpcflowlogs'

    mock_logs_bucket.assert_called_once()


def test_aws_vpc_flow_bucket_load_information_from_file():
    """Test 'load_information_from_file' method returns the expected information."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)

    data = '2 123456789123 eni-12345678912345678 0.0.0.0 0.0.0.0 3500 52000 6 39 4698 1622505433 1622505730 ACCEPT OK'

    expected_result = [{
        'version': '2', 'account_id': '123456789123',
        'interface_id': 'eni-12345678912345678',
        'srcaddr': '0.0.0.0', 'dstaddr': '0.0.0.0',
        'srcport': '3500', 'dstport': '52000',
        'protocol': '6', 'packets': '39',
        'bytes': '4698', 'start': '1622505433',
        'end': '1622505730', 'action': 'ACCEPT', 'log_status': 'OK'
    }]
    expected_result[0].update({'source': 'vpc'})
    expected_result[0]["start"] = datetime.utcfromtimestamp(int(expected_result[0]["start"])).strftime(
        '%Y-%m-%dT%H:%M:%SZ')
    expected_result[0]["end"] = datetime.utcfromtimestamp(int(expected_result[0]["end"])).strftime('%Y-%m-%dT%H:%M:%SZ')

    with patch('aws_bucket.AWSBucket.decompress_file', mock_open(read_data=data)):
        assert instance.load_information_from_file(utils.TEST_LOG_KEY) == list(expected_result)


@pytest.mark.parametrize('profile', [None, utils.TEST_AWS_PROFILE])
def test_aws_vpc_flow_bucket_get_ec2_client(profile: str or None):
    """Test 'get_ec2_client' method instantiates a boto3.Session object with the proper arguments.

    Parameters
    ----------
    profile: str or None
        AWS profile.
    """
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)
    region = utils.TEST_REGION

    conn_args = {'region_name': region}

    if profile is not None:
        conn_args['profile_name'] = profile

    with patch('boto3.Session') as mock_session:
        instance.connection_config = MagicMock()
        instance.get_ec2_client(region, profile)
        mock_session.assert_called_once_with(**conn_args)


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_aws_vpc_flow_bucket_get_ec2_client_handles_exceptions_on_ec2_client_error(mock_logs_bucket):
    """Test 'get_ec2_client' method handles exceptions raised when trying to get the EC2 client."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)

    with patch('boto3.Session'), \
            pytest.raises(SystemExit) as e:
        instance.get_ec2_client(utils.TEST_REGION, utils.TEST_AWS_PROFILE)
    assert e.value.code == utils.INVALID_CREDENTIALS_ERROR_CODE


@patch('vpcflow.AWSVPCFlowBucket.get_ec2_client')
def test_aws_vpc_flow_bucket_get_flow_logs_ids(mock_get_ec2_client):
    """Test 'get_flow_logs_ids' method returns the expected flow log ids from the client's response."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)

    ec2_client = mock_get_ec2_client.return_value
    ec2_client.describe_flow_logs.return_value = {
        'FlowLogs': [
            {
                'FlowLogId': 'Id1',
                'OtherFields': 'fields'
            },
            {
                'FlowLogId': 'Id2',
                'OtherFields': 'fields'
            },
            {
                'FlowLogId': 'Id3',
                'OtherFields': 'fields'
            },
        ],
        'NextToken': 'string'
    }

    assert ['Id1', 'Id2', 'Id3'] == instance.get_flow_logs_ids(utils.TEST_REGION, utils.TEST_AWS_PROFILE)


@pytest.mark.parametrize('log_file, account_id, region, expected_result', [
    (TEST_LOG_KEY, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    ("", utils.TEST_ACCOUNT_ID, utils.TEST_REGION, False),
    (TEST_LOG_KEY, "", utils.TEST_REGION, False),
])
def test_aws_vpc_flow_bucket_already_processed(custom_database,
                                               log_file: str, account_id: str,
                                               region: str, expected_result: bool):
    """Test 'already_processed' method correctly determines if a log file has been processed.

    Parameters
    ----------
    log_file: str
        Complete path of the downloaded file.
    account_id: str
        AWS account ID.
    region: str
        Region of service.
    expected_result: bool
        Expected result from the method's execution.
    """
    utils.database_execute_script(custom_database, TEST_VPCFLOW_SCHEMA)

    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket, bucket=utils.TEST_BUCKET)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME
    instance.aws_account_id = utils.TEST_ACCOUNT_ID

    assert instance.already_processed(downloaded_file=log_file, aws_account_id=account_id,
                                      aws_region=region, flow_log_id=TEST_FLOW_LOG_ID) == expected_result


@pytest.mark.parametrize('account_id', [[utils.TEST_ACCOUNT_ID], None])
@pytest.mark.parametrize('regions', [[utils.TEST_REGION], None])
@patch('aws_bucket.AWSLogsBucket.iter_files_in_bucket')
@patch('vpcflow.AWSVPCFlowBucket.get_flow_logs_ids', return_value=['Id1'])
@patch('vpcflow.AWSVPCFlowBucket.db_maintenance')
@patch('aws_bucket.AWSBucket.find_account_ids', return_value=[utils.TEST_ACCOUNT_ID])
@patch('aws_bucket.AWSBucket.find_regions', side_effect=[[utils.TEST_REGION], None])
def test_aws_vpc_flow_bucket_iter_regions_and_accounts(mock_find_regions, mock_accounts,
                                                       mock_maintenance, mock_get_flow_logs_ids,
                                                       mock_iter_files_in_bucket,
                                                       regions: list[str] or None, account_id: list[str] or None):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files.

    Parameters
    ----------
    regions: list[str] or None
        List of regions.
    account_id: list[str] or None
        List of account IDs.
    """
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket)

    instance.profile_name = utils.TEST_AWS_PROFILE

    instance.iter_regions_and_accounts(account_id, regions)

    if not account_id:
        mock_accounts.assert_called_once()
        account_id = instance.find_account_ids()
    for aws_account_id in account_id:
        if not regions:
            mock_find_regions.assert_called_with(aws_account_id)
            regions = instance.find_regions(aws_account_id)
            if not regions:
                continue
        for aws_region in regions:
            mock_get_flow_logs_ids.assert_called_with(
                aws_region, aws_account_id, profile_name=instance.profile_name
            )
            flow_logs_ids = instance.get_flow_logs_ids(aws_region, profile_name=instance.profile_name)
            for flow_log_id in flow_logs_ids:
                mock_iter_files_in_bucket.assert_called_with(aws_account_id, aws_region, flow_log_id=flow_log_id)
                mock_maintenance.assert_called_with(aws_account_id, aws_region, flow_log_id)


@pytest.mark.parametrize('flow_log_id', [TEST_FLOW_LOG_ID, "other-id"])
@pytest.mark.parametrize('region', [utils.TEST_REGION, "invalid_region"])
def test_aws_vpc_flow_bucket_db_count_region(custom_database, region: str, flow_log_id: str):
    """Test 'db_count_region' method returns the number of rows in DB for a region.

    Parameters
    ----------
    region: str
        AWS region that may or not be in DB.
    flow_log_id: str
        Flow log ID.
    """
    utils.database_execute_script(custom_database, TEST_VPCFLOW_SCHEMA)
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket, bucket=utils.TEST_BUCKET)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME

    expected_count = VPC_SCHEMA_COUNT if region == utils.TEST_REGION and flow_log_id == TEST_FLOW_LOG_ID else 0
    assert instance.db_count_region(utils.TEST_ACCOUNT_ID, region, flow_log_id) == expected_count


@pytest.mark.parametrize('expected_db_count', [VPC_SCHEMA_COUNT, 0])
def test_aws_vpc_flow_bucket_db_maintenance(custom_database, expected_db_count: int):
    """Test 'db_maintenance' function deletes rows from a table until the count is equal to 'retain_db_records'."""
    utils.database_execute_script(custom_database, TEST_VPCFLOW_SCHEMA)
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket, bucket=utils.TEST_BUCKET)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME
    instance.retain_db_records = expected_db_count

    assert utils.database_execute_query(instance.db_connector, utils.SQL_COUNT_ROWS.format(
        table_name=instance.db_table_name)) == VPC_SCHEMA_COUNT

    with patch('aws_bucket.AWSBucket.db_count_region', return_value=VPC_SCHEMA_COUNT):
        instance.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                                flow_log_id=TEST_FLOW_LOG_ID)

    assert utils.database_execute_query(instance.db_connector, utils.SQL_COUNT_ROWS.format(
        table_name=instance.db_table_name)) == expected_db_count


def test_aws_vpc_flow_bucket_mark_complete(custom_database):
    """Test 'mark_complete' method inserts non-processed logs into the DB."""
    utils.database_execute_script(custom_database, TEST_EMPTY_TABLE_SCHEMA)

    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket, bucket=utils.TEST_BUCKET)

    instance.reparse = True
    with patch('vpcflow.AWSVPCFlowBucket.already_processed', return_value=True), \
            patch('aws_bucket.aws_tools.debug') as mock_debug:
        instance.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                               log_file={'Key': TEST_LOG_KEY}, flow_log_id=TEST_FLOW_LOG_ID)
        mock_debug.assert_called_once_with(f'+++ File already marked complete, but reparse flag set: {TEST_LOG_KEY}', 2)

    instance.reparse = False

    log_file = {'Key': TEST_LOG_KEY}

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME

    assert utils.database_execute_query(instance.db_connector,
                                        utils.SQL_COUNT_ROWS.format(table_name=instance.db_table_name)) == 0

    instance.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                           log_file=log_file, flow_log_id=TEST_FLOW_LOG_ID)

    assert utils.database_execute_query(instance.db_connector,
                                        utils.SQL_COUNT_ROWS.format(table_name=instance.db_table_name)) == 1

    row = utils.database_execute_query(instance.db_connector, SQL_GET_ROW.format(table_name=instance.db_table_name))
    assert row[0] == f"{utils.TEST_BUCKET}/"
    assert row[1] == utils.TEST_ACCOUNT_ID
    assert row[2] == utils.TEST_REGION
    assert row[3] == TEST_FLOW_LOG_ID
    assert row[4] == TEST_LOG_KEY
    assert row[5] == instance.get_creation_date(log_file)


@patch('aws_bucket.aws_tools.debug')
def test_aws_vpc_flow_bucket_mark_complete_handles_exceptions_on_query_error(mock_debug, custom_database):
    """Test 'mark_complete' handles exceptions raised when trying to execute a query to the DB."""
    instance = utils.get_mocked_bucket(class_=vpcflow.AWSVPCFlowBucket, reparse=False)

    instance.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception
    instance.db_cursor = mocked_cursor

    instance.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                           log_file={'Key': TEST_LOG_KEY}, flow_log_id=TEST_FLOW_LOG_ID)

    mock_debug.assert_any_call(f"+++ Error marking log {TEST_LOG_KEY} as completed: ", 2)
