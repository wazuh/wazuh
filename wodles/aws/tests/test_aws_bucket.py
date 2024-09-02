# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import os
import sys
import zipfile
import re
import csv
from datetime import datetime
from unittest.mock import MagicMock, patch, mock_open

import botocore
import pytest

import wodles.aws.tests.aws_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils
import aws_constants as test_constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration
import constants

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
from cloudtrail import AWSCloudTrailBucket
from config import AWSConfigBucket

TEST_CLOUDTRAIL_SCHEMA = "schema_cloudtrail_test.sql"
TEST_CUSTOM_SCHEMA = "schema_custom_test.sql"
TEST_EMPTY_TABLE_SCHEMA = "schema_empty_table.sql"

CLOUDTRAIL_SCHEMA_COUNT = 8
CUSTOM_SCHEMA_COUNT = 8

SQL_GET_ROW = "SELECT bucket_path, aws_account_id, aws_region, log_key, created_date FROM {table_name};"
SQL_COUNT_TABLES = """SELECT count(*) FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"""
SQL_SELECT_TABLES = """SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"""
SQL_FIND_LAST_KEY_PROCESSED = """SELECT log_key FROM {table_name} ORDER BY log_key DESC LIMIT 1;"""

SAMPLE_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}
SAMPLE_EVENT_2 = {'key1': 'value1', 'key2': None}

test_constants.LIST_OBJECT_V2_NO_PREFIXES['Contents'][0]['Key'] = test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1


@pytest.mark.parametrize('only_logs_after', [None, "20220101"])
@patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version')
@patch('wazuh_integration.sqlite3.connect')
@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.utils.find_wazuh_path', return_value=test_constants.TEST_WAZUH_PATH)
@patch('wazuh_integration.utils.get_wazuh_version')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_bucket_initializes_properly(mock_wazuh_integration, mock_version, mock_path, mock_client, mock_connect,
                                         mock_metadata,
                                         only_logs_after: str or None):
    """Test if the instances of AWSBucket are created properly."""
    kwargs = utils.get_aws_bucket_parameters(db_table_name=test_constants.TEST_TABLE_NAME, bucket=test_constants.TEST_BUCKET,
                                             profile=test_constants.TEST_AWS_PROFILE, iam_role_arn=test_constants.TEST_IAM_ROLE_ARN,
                                             account_alias=test_constants.TEST_ACCOUNT_ALIAS, prefix=test_constants.TEST_PREFIX,
                                             suffix=test_constants.TEST_SUFFIX, aws_organization_id=test_constants.TEST_ORGANIZATION_ID,
                                             region=test_constants.TEST_REGION, discard_field=test_constants.TEST_DISCARD_FIELD,
                                             discard_regex=test_constants.TEST_DISCARD_REGEX,
                                             sts_endpoint=test_constants.TEST_STS_ENDPOINT,
                                             service_endpoint=test_constants.TEST_SERVICE_ENDPOINT,
                                             iam_role_duration=test_constants.TEST_IAM_ROLE_DURATION, delete_file=True,
                                             skip_on_error=True, reparse=True, only_logs_after=only_logs_after)
    integration = aws_bucket.AWSBucket(**kwargs)
    mock_wazuh_integration.assert_called_with(integration, service_name="s3",
                                              profile=kwargs["profile"], iam_role_arn=kwargs["iam_role_arn"],
                                              region=kwargs["region"], discard_field=kwargs["discard_field"],
                                              discard_regex=kwargs["discard_regex"],
                                              sts_endpoint=kwargs["sts_endpoint"],
                                              service_endpoint=kwargs["service_endpoint"],
                                              iam_role_duration=kwargs["iam_role_duration"], external_id=None,
                                              skip_on_error=kwargs["skip_on_error"])

    assert integration.retain_db_records == constants.MAX_AWS_BUCKET_RECORD_RETENTION
    assert integration.reparse == kwargs["reparse"]
    assert integration.only_logs_after == datetime.strptime(only_logs_after, constants.AWS_BUCKET_DB_DATE_FORMAT) \
        if only_logs_after else integration.only_logs_after is None
    assert integration.skip_on_error == kwargs["skip_on_error"]
    assert integration.account_alias == kwargs["account_alias"]
    assert integration.prefix == kwargs["prefix"]
    assert integration.suffix == kwargs["suffix"]
    assert integration.delete_file == kwargs["delete_file"]
    assert integration.bucket == kwargs["bucket"]
    assert integration.bucket_path == f'{kwargs["bucket"]}/{kwargs["prefix"]}'
    assert integration.aws_organization_id == kwargs["aws_organization_id"]
    assert not integration.check_prefix


@pytest.mark.parametrize('log_file, account_id, region, expected_result', [
    (test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, test_constants.TEST_ACCOUNT_ID,
     test_constants.TEST_REGION, True),
    (test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_2, test_constants.TEST_ACCOUNT_ID,
     test_constants.TEST_REGION, True),
    ("", test_constants.TEST_ACCOUNT_ID, test_constants.TEST_REGION, False),
    (test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, test_constants.TEST_ACCOUNT_ID, "", False),
    (test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, "", test_constants.TEST_REGION, False),
])
def test_aws_bucket_already_processed(custom_database,
                                      log_file: str, account_id: str, region: str, expected_result: bool):
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
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)

    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, region=region)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = 'cloudtrail'

    assert bucket.already_processed(downloaded_file=log_file, aws_account_id=account_id,
                                    aws_region=region) == expected_result


def test_aws_bucket_get_creation_date_raises_exception():
    """Test 'get_creation_date' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_creation_date(test_constants.TEST_LOG_KEY)


def test_aws_bucket_mark_complete(custom_database):
    """Test 'mark_complete' method inserts non-processed logs into the DB."""
    utils.database_execute_script(custom_database, TEST_EMPTY_TABLE_SCHEMA)

    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = test_constants.TEST_TABLE_NAME

    assert utils.database_execute_query(bucket.db_connector,
                                        constants.SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 0

    with patch('aws_bucket.AWSBucket.get_creation_date', return_value=test_constants.TEST_CREATION_DATE):
        bucket.mark_complete(aws_account_id=test_constants.TEST_ACCOUNT_ID, aws_region=test_constants.TEST_REGION,
                             log_file={'Key': test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1})

    assert utils.database_execute_query(bucket.db_connector,
                                        constants.SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 1

    row = utils.database_execute_query(bucket.db_connector, SQL_GET_ROW.format(table_name=bucket.db_table_name))
    assert row[0] == f"{test_constants.TEST_BUCKET}/"
    assert row[1] == test_constants.TEST_ACCOUNT_ID
    assert row[2] == test_constants.TEST_REGION
    assert row[3] == test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1
    assert row[4] == test_constants.TEST_CREATION_DATE


@patch('aws_bucket.aws_tools.debug')
def test_aws_bucket_mark_complete_handles_exceptions_when_db_query_fails(mock_debug, custom_database):
    """Test 'mark_complete' handles exceptions raised when trying to execute a query to the DB."""
    bucket = utils.get_mocked_aws_bucket()

    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception
    bucket.db_cursor = mocked_cursor

    bucket.mark_complete(aws_account_id=test_constants.TEST_ACCOUNT_ID, aws_region=test_constants.TEST_REGION,
                         log_file={'Key': test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1})

    mock_debug.assert_called_with(f'+++ Error marking log {test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1} as completed: ', 2)


@pytest.mark.parametrize('region', [test_constants.TEST_REGION, "invalid_region"])
def test_aws_bucket_db_count_region(custom_database, region):
    """Test 'db_count_region' method counts the number of rows in DB for a region"""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = test_constants.TEST_TABLE_NAME

    expected_count = CLOUDTRAIL_SCHEMA_COUNT if region == test_constants.TEST_REGION else 0
    assert bucket.db_count_region(test_constants.TEST_ACCOUNT_ID, region) == expected_count


@pytest.mark.parametrize('expected_db_count', [CLOUDTRAIL_SCHEMA_COUNT, 0])
def test_aws_bucket_db_maintenance(custom_database, expected_db_count):
    """Test 'db_maintenance' method deletes rows from a table until the count is equal to 'retain_db_records'."""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = test_constants.TEST_TABLE_NAME
    bucket.retain_db_records = expected_db_count

    assert utils.database_execute_query(bucket.db_connector, constants.SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == CLOUDTRAIL_SCHEMA_COUNT

    with patch('aws_bucket.AWSBucket.db_count_region', return_value=CLOUDTRAIL_SCHEMA_COUNT):
        bucket.db_maintenance(aws_account_id=test_constants.TEST_ACCOUNT_ID, aws_region=test_constants.TEST_REGION)

    assert utils.database_execute_query(bucket.db_connector, constants.SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == expected_db_count


@patch('builtins.print')
def test_aws_bucket_db_maintenance_handles_exceptions_when_db_fails(mock_print, custom_database):
    """Test 'db_maintenance' method handles exceptions raised when fails to make the DB maintenance."""
    bucket = utils.get_mocked_aws_bucket()

    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception

    bucket.db_maintenance(aws_account_id=test_constants.TEST_ACCOUNT_ID, aws_region=test_constants.TEST_REGION)

    mock_print.assert_called_once()


def test_aws_bucket_marker_custom_date():
    """Test 'marker_custom_date' method returns a valid AWS bucket marker when using a custom date."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.date_format = '%Y-%m-%d'

    test_date = datetime.now()
    full_prefix = f"{test_constants.TEST_ACCOUNT_ID}/{test_constants.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_custom_date(aws_region=test_constants.TEST_REGION, aws_account_id=test_constants.TEST_ACCOUNT_ID,
                                           date=test_date)
    assert marker == f"{full_prefix}{test_date.strftime(bucket.date_format)}"


def test_aws_bucket_marker_only_logs_after():
    """Test 'marker_only_logs_after' method returns a valid marker using only_log_after."""
    test_only_logs_after = test_constants.TEST_ONLY_LOGS_AFTER
    bucket = utils.get_mocked_aws_bucket(only_logs_after=test_only_logs_after)
    bucket.date_format = '%Y-%m-%d'

    full_prefix = f"{test_constants.TEST_ACCOUNT_ID}/{test_constants.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_only_logs_after(aws_region=test_constants.TEST_REGION, aws_account_id=test_constants.TEST_ACCOUNT_ID)
    assert marker == f"{full_prefix}{test_only_logs_after[0:4]}-{test_only_logs_after[4:6]}-{test_only_logs_after[6:8]}"


@pytest.mark.parametrize('event', [SAMPLE_EVENT_1, SAMPLE_EVENT_2, None])
def test_aws_bucket_get_alert_msg(event):
    """Test 'get_alert_msg' method returns messages with the valid format."""
    bucket = utils.get_mocked_aws_bucket(account_alias=test_constants.TEST_ACCOUNT_ALIAS)
    expected_error_message = "error message"
    expected_msg = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
    expected_msg['aws']['log_info'].update({
        'aws_account_alias': bucket.account_alias,
        'log_file': test_constants.TEST_LOG_KEY,
        's3bucket': bucket.bucket
    })
    if event:
        # Remove 'None' values from the event before updating the message
        expected_msg['aws'].update({k: v for k, v in event.items() if v is not None})
    else:
        expected_msg['error_msg'] = expected_error_message
    assert bucket.get_alert_msg(test_constants.TEST_ACCOUNT_ID,
                                test_constants.TEST_LOG_KEY, event,
                                error_msg=expected_error_message) == expected_msg


def test_aws_bucket_get_full_prefix():
    """Test 'get_full_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_full_prefix(test_constants.TEST_ACCOUNT_ID,
                               test_constants.TEST_REGION)


def test_aws_bucket_get_base_prefix():
    """Test 'get_base_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_base_prefix()


def test_aws_bucket_get_service_prefix():
    """Test 'get_service_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_service_prefix(test_constants.TEST_ACCOUNT_ID)


@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=test_constants.TEST_PREFIX)
def test_aws_bucket_find_account_ids(mock_prefix):
    """Test 'find_account_ids' method returns a valid account_ids list."""
    object_list = {'CommonPrefixes': [{'Prefix': f'AWSLogs/{test_constants.TEST_ACCOUNT_ID}/'},
                                      {'Prefix': f'AWSLogs/prefix/{test_constants.TEST_ACCOUNT_ID}/'}]}
    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, prefix=test_constants.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_account_ids()
    bucket.client.list_objects_v2.assert_called_with(Bucket=test_constants.TEST_BUCKET, Prefix=test_constants.TEST_PREFIX, Delimiter='/')
    assert accounts == [test_constants.TEST_ACCOUNT_ID for _ in object_list['CommonPrefixes']]


@pytest.mark.parametrize('error_code, exit_code', [
    (constants.THROTTLING_EXCEPTION_ERROR_NAME, wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE),
    ('OtherClientException', wodles.aws.tests.aws_constants.UNKNOWN_ERROR_CODE)
])
@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=test_constants.TEST_PREFIX)
def test_aws_bucket_find_account_ids_handles_exceptions_on_client_error(mock_prefix, error_code: str, exit_code: int):
    """Test 'find_account_ids' method handles client errors as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, prefix=test_constants.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}}, "name")

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == exit_code


@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=test_constants.TEST_PREFIX)
@patch('aws_bucket.aws_tools.get_script_arguments')
def test_aws_bucket_find_account_ids_handles_exceptions_on_key_error(mock_prefix, mock_script_arguments):
    """Test 'find_account_ids' method handles KeyError as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, prefix=test_constants.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = KeyError

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == wodles.aws.tests.aws_constants.INVALID_PREFIX_ERROR_CODE


@pytest.mark.parametrize('object_list', [test_constants.LIST_OBJECT_V2,
                                         test_constants.LIST_OBJECT_V2_NO_PREFIXES])
@patch('aws_bucket.AWSBucket.get_service_prefix', return_value=test_constants.TEST_PREFIX)
def test_aws_bucket_find_regions(mock_prefix, object_list: dict):
    """Test 'find_regions' method returns a valid region list."""

    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, prefix=test_constants.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_regions(test_constants.TEST_ACCOUNT_ID)
    bucket.client.list_objects_v2.assert_called_with(Bucket=test_constants.TEST_BUCKET, Prefix=test_constants.TEST_PREFIX, Delimiter='/')
    if object_list.get('CommonPrefixes'):
        assert accounts == [test_constants.TEST_REGION for _ in object_list['CommonPrefixes']]
    else:
        assert len(accounts) == 0


@pytest.mark.parametrize('error_code, exit_code', [
    (constants.THROTTLING_EXCEPTION_ERROR_NAME, wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE),
    ('OtherClientException', wodles.aws.tests.aws_constants.UNKNOWN_ERROR_CODE)
])
@patch('aws_bucket.AWSBucket.get_service_prefix', return_value=test_constants.TEST_PREFIX)
def test_aws_bucket_find_regions_handles_exceptions_on_client_error(mock_prefix, error_code: str, exit_code: int):
    """Test 'find_regions' method handles client errors as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, prefix=test_constants.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}}, "name")

    with pytest.raises(SystemExit) as e:
        bucket.find_regions(test_constants.TEST_ACCOUNT_ID)
    assert e.value.code == exit_code


@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('only_logs_after', [test_constants.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('iterating', [True, False])
@pytest.mark.parametrize('custom_delimiter', ['', '-'])
@pytest.mark.parametrize('region', [test_constants.TEST_REGION, 'region_for_empty_db'])
@patch('aws_bucket.AWSBucket.get_full_prefix', return_value=test_constants.TEST_FULL_PREFIX)
def test_aws_bucket_build_s3_filter_args(mock_get_full_prefix, custom_database,
                                         region: str, custom_delimiter: str, iterating: bool,
                                         only_logs_after: str or None, reparse: bool):
    """Test 'build_s3_filter_args' method returns the expected filter arguments for the list_objects_v2 call.

    Parameters
    ----------
    region: str
        Region name.
    custom_delimiter: str
        Custom delimiter expected in the key.
    iterating: bool
        Whether the call to the method is being made inside a loop due to a truncated response.
    only_logs_after: str or None
        Date after which obtain logs.
    reparse: bool
        Whether to parse already parsed logs or not.
    """
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)

    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, reparse=reparse, only_logs_after=only_logs_after)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = test_constants.TEST_TABLE_NAME

    expected_filter_args = {
        'Bucket': bucket.bucket,
        'MaxKeys': 1000,
        'Prefix': mock_get_full_prefix(test_constants.TEST_ACCOUNT_ID,
                                       test_constants.TEST_REGION)
    }

    aws_account_id = test_constants.TEST_ACCOUNT_ID
    aws_region = region

    if bucket.reparse:
        if only_logs_after:
            filter_marker = bucket.marker_only_logs_after(aws_region, aws_account_id)
        else:
            filter_marker = bucket.marker_custom_date(aws_region, aws_account_id, bucket.default_date)
    else:
        filter_marker = utils.database_execute_query(bucket.db_connector, SQL_FIND_LAST_KEY_PROCESSED.format(
            table_name=bucket.db_table_name))

    if aws_region == 'region_for_empty_db':
        filter_marker = bucket.marker_only_logs_after(aws_region, aws_account_id) if bucket.only_logs_after \
            else bucket.marker_custom_date(aws_region, aws_account_id, bucket.default_date)

    if not iterating:
        expected_filter_args['StartAfter'] = filter_marker
        if only_logs_after:
            only_logs_marker = bucket.marker_only_logs_after(aws_region, aws_account_id)
            expected_filter_args['StartAfter'] = only_logs_marker if only_logs_marker > filter_marker else filter_marker

        if custom_delimiter:
            prefix_len = len(expected_filter_args['Prefix'])
            expected_filter_args['StartAfter'] = expected_filter_args['StartAfter'][:prefix_len] + \
                                                 expected_filter_args['StartAfter'][prefix_len:]. \
                                                     replace('/', custom_delimiter)

    assert expected_filter_args == bucket.build_s3_filter_args(aws_account_id, aws_region, iterating,
                                                               custom_delimiter)


def test_aws_bucket_reformat_msg():
    """Test 'reformat_msg' method applies the expected format to a given event."""
    bucket = utils.get_mocked_aws_bucket()
    event = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update(
        {
            'sourceIPAddress': '255.255.255.255',
            'tags': ['tag1', 'tag2'],
            'additional_field': ['element']
        }
    )

    formatted_event = bucket.reformat_msg(event)

    assert isinstance(formatted_event['aws']['tags'], dict)
    assert not isinstance(formatted_event['aws']['additional_field'], list)
    assert formatted_event['aws']['source_ip_address'] == '255.255.255.255'
    assert formatted_event['aws']['tags'] == {'value': ['tag1', 'tag2']}


def test_aws_bucket_load_information_from_file():
    """Test 'load_information_from_file' method properly raise a NotImplementedError exception
    when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.load_information_from_file(test_constants.TEST_LOG_KEY)


@pytest.mark.parametrize('expected_result', [SAMPLE_EVENT_1, SAMPLE_EVENT_2])
@patch('aws_bucket.AWSBucket.load_information_from_file')
def test_aws_bucket_get_log_file(mock_load_from_file, expected_result):
    """Test 'get_log_file' method returns the expected event from a log file"""
    bucket = utils.get_mocked_aws_bucket()
    mock_load_from_file.return_value = expected_result
    assert expected_result == bucket.get_log_file(test_constants.TEST_ACCOUNT_ID,
                                                  test_constants.TEST_LOG_KEY)
    mock_load_from_file.assert_called_with(log_key=test_constants.TEST_LOG_KEY)


@pytest.mark.parametrize('exception, error_message, exit_code', [
    (TypeError, f'Failed to decompress file {test_constants.TEST_LOG_KEY}: TypeError()',
     wodles.aws.tests.aws_constants.DECOMPRESS_FILE_ERROR_CODE),
    (zipfile.BadZipfile, f'Failed to decompress file {test_constants.TEST_LOG_KEY}: BadZipFile()',
     wodles.aws.tests.aws_constants.DECOMPRESS_FILE_ERROR_CODE),
    (zipfile.LargeZipFile, f'Failed to decompress file {test_constants.TEST_LOG_KEY}: LargeZipFile()',
     wodles.aws.tests.aws_constants.DECOMPRESS_FILE_ERROR_CODE),
    (IOError, f'Failed to decompress file {test_constants.TEST_LOG_KEY}: OSError()',
     wodles.aws.tests.aws_constants.DECOMPRESS_FILE_ERROR_CODE),
    (ValueError, f'Failed to parse file {test_constants.TEST_LOG_KEY}: ValueError()',
     wodles.aws.tests.aws_constants.PARSE_FILE_ERROR_CODE),
    (csv.Error, f'Failed to parse file {test_constants.TEST_LOG_KEY}: Error()',
     wodles.aws.tests.aws_constants.PARSE_FILE_ERROR_CODE),
    (Exception, f'Unknown error reading/parsing file {test_constants.TEST_LOG_KEY}: Exception()',
     wodles.aws.tests.aws_constants.UNKNOWN_ERROR_CODE)
])
@pytest.mark.parametrize('skip_on_error', [True, False])
@patch('aws_bucket.AWSBucket.load_information_from_file')
def test_aws_bucket_get_log_file_handles_exceptions_when_information_cannot_be_loaded(mock_load_from_file,
                                                                                      skip_on_error: bool,
                                                                                      exception: Exception,
                                                                                      error_message: str,
                                                                                      exit_code: int):
    """Test 'get_log_file' method handles exceptions raised according to their type.

    Parameters
    ----------
    skip_on_error: bool
        Whether to send the error to Wazuh or exit with an error code.
    exception: Exception
        Exception that might be raised.
    error_message: str
        Expected error message.
    exit_code: int
        Expected exit code.
    """
    bucket = utils.get_mocked_aws_bucket(skip_on_error=skip_on_error)
    mock_load_from_file.side_effect = exception
    if bucket.skip_on_error:
        with patch('aws_bucket.AWSBucket.send_msg') as mock_send_msg, \
                patch('aws_bucket.aws_tools.debug') as mock_debug, \
                patch('aws_bucket.AWSBucket.get_alert_msg', return_value='error_msg') as mock_get_alert_msg:
            debug_message_example = "++ {}; skipping...".format(error_message)

            bucket.get_log_file(test_constants.TEST_ACCOUNT_ID,
                                test_constants.TEST_LOG_KEY)
            mock_debug.assert_called_with(debug_message_example, 1)
            mock_get_alert_msg.assert_called_once_with(test_constants.TEST_ACCOUNT_ID,
                                                       test_constants.TEST_LOG_KEY, None, error_message)
            mock_send_msg.assert_called_once_with(mock_get_alert_msg())

            mock_send_msg.side_effect = Exception
            bucket.get_log_file(test_constants.TEST_ACCOUNT_ID,
                                test_constants.TEST_LOG_KEY)
            mock_debug.assert_called_with("++ Failed to send message to Wazuh", 1)

    else:
        with pytest.raises(SystemExit) as e:
            bucket.get_log_file(test_constants.TEST_ACCOUNT_ID,
                                test_constants.TEST_LOG_KEY)
        assert e.value.code == exit_code


@patch('aws_bucket.AWSBucket.iter_regions_and_accounts')
@patch('aws_bucket.AWSBucket.init_db')
def test_aws_bucket_iter_bucket(mock_init, mock_iter):
    """Test 'iter_bucket' method calls the appropriate functions."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = MagicMock()
    bucket.db_cursor = MagicMock()
    bucket.iter_bucket(test_constants.TEST_ACCOUNT_ID, test_constants.TEST_REGION)

    mock_init.assert_called_once()
    mock_iter.assert_called_with(test_constants.TEST_ACCOUNT_ID,
                                 test_constants.TEST_REGION)
    bucket.db_connector.commit.assert_called_once()
    bucket.db_cursor.execute.assert_called_with(bucket.sql_db_optimize)
    bucket.db_connector.close.assert_called_once()


@pytest.mark.parametrize('account_id', [[test_constants.TEST_ACCOUNT_ID], None])
@pytest.mark.parametrize('regions', [[test_constants.TEST_REGION], None])
@patch('aws_bucket.AWSBucket.find_account_ids', return_value=[test_constants.TEST_ACCOUNT_ID])
@patch('aws_bucket.AWSBucket.find_regions', side_effect=[[test_constants.TEST_REGION], None])
@patch('aws_bucket.AWSBucket.iter_files_in_bucket')
@patch('aws_bucket.AWSBucket.db_maintenance')
def test_aws_bucket_iter_regions_and_accounts(mock_db_maintenance, mock_iter_files, mock_find_regions, mock_accounts,
                                              regions: list[str], account_id: list[str]):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files."""
    bucket = utils.get_mocked_aws_bucket()

    bucket.iter_regions_and_accounts(account_id, regions)

    if not account_id:
        mock_accounts.assert_called_once()
        account_id = bucket.find_account_ids()
    for aws_account_id in account_id:
        if not regions:
            mock_find_regions.assert_called_with(aws_account_id)
            regions = bucket.find_regions(aws_account_id)
            if not regions:
                continue
        for region in regions:
            mock_iter_files.assert_called_with(aws_account_id, region)
            mock_db_maintenance.assert_called_with(aws_account_id=aws_account_id, aws_region=region)


@patch('aws_bucket.AWSBucket.send_msg')
@patch('aws_bucket.AWSBucket.reformat_msg', return_value=SAMPLE_EVENT_1)
def test_aws_bucket_send_event(mock_reformat, mock_send):
    """Test 'send_event' method makes the necessary calls in order to send an event to Analysisd."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.send_event(SAMPLE_EVENT_1)
    mock_reformat.assert_called_with(SAMPLE_EVENT_1)
    mock_send.assert_called_with(SAMPLE_EVENT_1)


@pytest.mark.parametrize('discard_field', [None, 'eventVersion'])
@pytest.mark.parametrize('discard_regex', [None, '^ver.ion$'])
@patch('aws_bucket.AWSBucket.get_alert_msg')
@patch('aws_bucket.AWSBucket.send_event')
@patch('aws_bucket.aws_tools.debug')
def test_aws_bucket_iter_events(mock_debug, mock_send_event, mock_get_alert,
                                discard_regex: str or None, discard_field: str or None):
    """Test 'iter_events' method process a list of events and discards them in case they contain the discard values.

    Parameters
    ----------
    discard_regex: str or None
        REGEX value to determine whether an event should be skipped.
    discard_field: str or None
        Name of the event field to apply the regex value on.
    """
    bucket = utils.get_mocked_aws_bucket(discard_field=discard_field, discard_regex=discard_regex)
    event_list = [
        {'eventVersion': 'version', 'userIdentity': {'type': 'someType'}, 'eventTime': 'someTime', 'eventName': 'name',
         'source': 'cloudtrail'}]

    bucket.iter_events(event_list, test_constants.TEST_LOG_KEY,
                       test_constants.TEST_ACCOUNT_ID)
    for event in event_list:
        if bucket.discard_field and discard_regex:
            mock_debug.assert_any_call(
                f'+++ The "{bucket.discard_regex.pattern}" regex found a match in the "{bucket.discard_field}" '
                f'field. The event will be skipped.', 2)
            continue
        mock_get_alert.assert_called_with(test_constants.TEST_ACCOUNT_ID,
                                          test_constants.TEST_LOG_KEY, event)
        mock_send_event.assert_called()


@pytest.mark.parametrize('object_list',
                         [test_constants.LIST_OBJECT_V2,
                          test_constants.LIST_OBJECT_V2_NO_PREFIXES,
                          test_constants.LIST_OBJECT_V2_TRUNCATED])
@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('check_prefix', [True, False])
@pytest.mark.parametrize('delete_file', [True, False])
@patch('aws_bucket.aws_tools.debug')
@patch('aws_bucket.AWSBucket.build_s3_filter_args')
def test_aws_bucket_iter_files_in_bucket(mock_build_filter, mock_debug,
                                         delete_file: bool, check_prefix: bool, reparse: bool, object_list: dict):
    """Test 'iter_files_in_bucket' method makes the necessary method calls
    in order to process the logs inside the bucket.

    Parameters
    ----------
    delete_file: bool
        Whether to remove the file from the bucket or not.
    check_prefix: bool
        Whether to check the key prefix or not.
    reparse: bool
        Whether to parse already parsed logs or not.
    object_list: dict
        Objects to be returned by list_objects_v2.
    """
    bucket = utils.get_mocked_aws_bucket(bucket=test_constants.TEST_BUCKET, delete_file=delete_file, reparse=reparse,
                                         prefix=test_constants.TEST_PREFIX)

    mock_build_filter.return_value = {
        'Bucket': bucket.bucket,
        'MaxKeys': 1000,
        'Prefix': test_constants.TEST_PREFIX
    }

    bucket.client.list_objects_v2.return_value = object_list
    bucket.check_prefix = check_prefix

    aws_account_id = test_constants.TEST_ACCOUNT_ID
    aws_region = test_constants.TEST_REGION

    with patch('aws_bucket.AWSBucket.already_processed', return_value=True) as mock_already_processed, \
            patch('aws_bucket.AWSBucket.get_log_file') as mock_get_log_file, \
            patch('aws_bucket.AWSBucket.iter_events') as mock_iter_events, \
            patch('aws_bucket.AWSBucket.mark_complete') as mock_mark_complete, \
            patch('aws_bucket.AWSBucket.get_full_prefix', return_value=test_constants.TEST_FULL_PREFIX):

        if 'IsTruncated' in object_list and object_list['IsTruncated']:
            bucket.client.list_objects_v2.side_effect = [object_list,
                                                         test_constants.LIST_OBJECT_V2_NO_PREFIXES]

        bucket.iter_files_in_bucket(aws_account_id, aws_region)

        if bucket.reparse:
            mock_debug.assert_any_call('++ Reparse mode enabled', 2)

        mock_build_filter.assert_any_call(aws_account_id, aws_region)
        bucket.client.list_objects_v2.assert_called_with(**mock_build_filter(aws_account_id, aws_region))

        if 'Contents' not in object_list:
            mock_debug.assert_any_call(f"+++ No logs to process in bucket: {aws_account_id}/{aws_region}",
                                       1)
        else:
            for bucket_file in object_list['Contents']:
                if not bucket_file['Key']:
                    continue

                if bucket_file['Key'][-1] == '/':
                    continue

                if bucket.check_prefix:
                    date_match = bucket.date_regex.search(bucket_file['Key'])
                    match_start = date_match.span()[0] if date_match else None

                    if not bucket._same_prefix(match_start, aws_account_id, aws_region):
                        mock_debug.assert_any_call(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                        continue

                mock_already_processed.assert_called_with(bucket_file['Key'], aws_account_id, aws_region)
                if bucket.reparse:
                    mock_debug.assert_any_call(
                        f"++ File previously processed, but reparse flag set: {bucket_file['Key']}",
                        1)
                else:
                    mock_debug.assert_any_call(f"++ Skipping previously processed file: {bucket_file['Key']}", 1)
                    continue

                mock_debug.assert_any_call(f"++ Found new log: {bucket_file['Key']}", 2)
                mock_get_log_file.assert_called_with(aws_account_id, bucket_file['Key'])
                mock_iter_events.assert_called()

                if bucket.delete_file:
                    mock_debug.assert_any_call(f"+++ Remove file from S3 Bucket:{bucket_file['Key']}", 2)

                mock_mark_complete.assert_called_with(aws_account_id, aws_region, bucket_file)

            if object_list['IsTruncated']:
                mock_build_filter.assert_any_call(aws_account_id, aws_region, True)


@pytest.mark.parametrize('error_code, exit_code', [
    (constants.THROTTLING_EXCEPTION_ERROR_NAME, wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE),
    ('OtherClientException', wodles.aws.tests.aws_constants.UNKNOWN_ERROR_CODE),
])
def test_aws_bucket_iter_files_in_bucket_handles_exceptions_on_error(error_code, exit_code):
    """Test 'iter_files_in_bucket' method handles exceptions raised when trying to fetch objects from AWS
    or by an unexpected cause and exits with the expected exit code.
    """
    bucket = utils.get_mocked_aws_bucket()
    bucket.client = MagicMock()

    with patch('aws_bucket.AWSBucket.build_s3_filter_args') as mock_build_filter:
        with pytest.raises(SystemExit) as e:
            bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}},
                                                                                        "name")
            bucket.iter_files_in_bucket(test_constants.TEST_ACCOUNT_ID,
                                        test_constants.TEST_REGION)
        assert e.value.code == exit_code

        with pytest.raises(SystemExit) as e:
            mock_build_filter.side_effect = Exception
            bucket.iter_files_in_bucket(test_constants.TEST_ACCOUNT_ID,
                                        test_constants.TEST_REGION)
        assert e.value.code == wodles.aws.tests.aws_constants.UNEXPECTED_ERROR_WORKING_WITH_S3


def test_aws_bucket_check_bucket():
    """Test 'check_bucket' method makes the necessary method calls in order to verify that the bucket is not empty."""
    page = {'CommonPrefixes': 'list of Prefix'}
    bucket = utils.get_mocked_aws_bucket()
    bucket.client = MagicMock()

    paginator = MagicMock()
    bucket.client.get_paginator.return_value = paginator
    paginator.paginate = MagicMock(return_value=[page])
    bucket.check_bucket()

    bucket.client.get_paginator.assert_called_once()
    paginator.paginate.assert_called_with(Bucket=bucket.bucket, Prefix=bucket.prefix, Delimiter='/')


def test_aws_bucket_check_bucket_exits_when_empty():
    """Test 'check_bucket' method exits with the expected error code when the bucket is empty."""
    page = {'OtherKey': ''}
    bucket = utils.get_mocked_aws_bucket()
    bucket.client = MagicMock()

    paginator = MagicMock()
    bucket.client.get_paginator.return_value = paginator
    paginator.paginate = MagicMock(return_value=[page])

    with pytest.raises(SystemExit) as e:
        bucket.check_bucket()
    paginator.paginate.assert_called_with(Bucket=bucket.bucket, Prefix=bucket.prefix, Delimiter='/')
    assert e.value.code == 14


@pytest.mark.parametrize('error_code, exit_code', [
    (constants.THROTTLING_EXCEPTION_ERROR_NAME, wodles.aws.tests.aws_constants.THROTTLING_ERROR_CODE),
    (constants.INVALID_CREDENTIALS_ERROR_NAME, wodles.aws.tests.aws_constants.INVALID_CREDENTIALS_ERROR_CODE),
    (constants.INVALID_REQUEST_TIME_ERROR_NAME, wodles.aws.tests.aws_constants.INVALID_REQUEST_TIME_ERROR_CODE),
    ("OtherClientError", wodles.aws.tests.aws_constants.UNKNOWN_ERROR_CODE)
])
def test_aws_bucket_check_bucket_handles_exceptions_on_client_error(error_code: str, exit_code: int):
    """Test 'check_bucket' method handles the different botocore client exceptions and exits with the expected code
    when an exception is raised accessing to AWS.

    Parameters
    ----------
    error_code: str
        Expected error message.
    exit_code: int
        Expected exit code.
    """
    bucket = utils.get_mocked_aws_bucket()
    bucket.client = MagicMock()

    with pytest.raises(SystemExit) as e:
        bucket.client.get_paginator.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}},
                                                                                  "name")
        bucket.check_bucket()
    assert e.value.code == exit_code


def test_aws_bucket_check_bucket_handles_exceptions_on_endpoint_error():
    """Test 'check_bucket' method handles botocore endpoint exceptions and exits with the expected code
    when an exception is raised connecting to AWS."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.client = MagicMock()

    with pytest.raises(SystemExit) as e:
        bucket.client.get_paginator.side_effect = botocore.exceptions.EndpointConnectionError(
            endpoint_url='endpoint.aws.com')
        bucket.check_bucket()
    assert e.value.code == wodles.aws.tests.aws_constants.INVALID_ENDPOINT_ERROR_CODE


@pytest.mark.parametrize('prefix', [test_constants.TEST_PREFIX, None])
@pytest.mark.parametrize('suffix', [test_constants.TEST_SUFFIX, None])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_aws_logs_bucket_initializes_properly(mock_bucket, mock_wazuh_aws_database, prefix, suffix):
    """Test if the instances of AWSLogsBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, bucket=test_constants.TEST_BUCKET,
                                       prefix=prefix, suffix=suffix)
    mock_bucket.assert_called_once()
    assert instance.bucket_path == f"{test_constants.TEST_BUCKET}/{prefix}{suffix}"


@pytest.mark.parametrize('organization_id', [test_constants.TEST_ORGANIZATION_ID, None])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_logs_bucket_get_base_prefix(mock_wazuh_aws_database, organization_id):
    """Test 'get_base_prefix' returns the expected prefix with the format
    <prefix>/AWSLogs/<suffix>/<organization_id>/.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, aws_organization_id=organization_id,
                                       prefix=f'{test_constants.TEST_PREFIX}/', suffix=f'{test_constants.TEST_SUFFIX}/')
    expected_base_prefix = os.path.join(test_constants.TEST_PREFIX, 'AWSLogs',
                                        test_constants.TEST_SUFFIX,
                                        (organization_id if organization_id else ""), '')
    assert instance.get_base_prefix() == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSLogsBucket.get_base_prefix', return_value='base_prefix/')
def test_aws_logs_bucket_get_service_prefix(mock_base_prefix, mock_wazuh_aws_database):
    """Test 'get_service_prefix' method returns the expected prefix with the format
    <base_prefix>/<account_id>/<service>.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    instance.service = test_constants.TEST_SERVICE_NAME
    expected_base_prefix = os.path.join('base_prefix', test_constants.TEST_ACCOUNT_ID,
                                        test_constants.TEST_SERVICE_NAME, '')
    assert instance.get_service_prefix(test_constants.TEST_ACCOUNT_ID) == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSLogsBucket.get_service_prefix', return_value='service_prefix/')
def test_aws_logs_bucket_get_full_prefix(mock_service_prefix, mock_wazuh_aws_database):
    """Test 'get_full_prefix' method returns the expected prefix with the format <service_prefix>/<region>."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, region=test_constants.TEST_REGION)
    expected_base_prefix = os.path.join('service_prefix', test_constants.TEST_REGION, '')
    assert instance.get_full_prefix(test_constants.TEST_ACCOUNT_ID,
                                    test_constants.TEST_REGION) == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_logs_bucket_get_creation_date(mock_wazuh_aws_database):
    """Test 'get_creation_date' method returns the expected date from a log filename."""
    log_file = {'Key': test_constants.TEST_LOG_FULL_PATH_CLOUDTRAIL_1}
    expected_result = 20190401
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    assert instance.get_creation_date(log_file) == expected_result


def test_aws_logs_bucket_get_alert_msg():
    """Test 'get_alert_msg' method returns messages with the valid format."""
    bucket = utils.get_mocked_aws_bucket()

    with patch('wazuh_integration.WazuhAWSDatabase.__init__'):
        instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
        aws_account_id = test_constants.TEST_ACCOUNT_ID
        expected_msg = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
        expected_error_message = "error message"

        expected_alert_msg = bucket.get_alert_msg(aws_account_id, test_constants.TEST_LOG_KEY, expected_msg,
                                                  error_msg=expected_error_message)
        expected_alert_msg['aws']['aws_account_id'] = aws_account_id

        assert expected_alert_msg == instance.get_alert_msg(aws_account_id, test_constants.TEST_LOG_KEY, expected_msg,
                                                            expected_error_message)


@pytest.mark.parametrize('class_, json_file_content, result', [
    (AWSCloudTrailBucket, {"field_to_load": "example"}, None),
    (AWSCloudTrailBucket, {"Records": [{"example_key": "example_value"}]},
     [{"example_key": "example_value", 'source': 'cloudtrail'}]),
    (AWSConfigBucket, {"configurationItems": [{"example_key": "example_value"}]},
     [{"example_key": "example_value", 'source': 'config'}])])
@patch('json.load')
@patch('aws_bucket.AWSBucket.decompress_file')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_logs_bucket_load_information_from_file(mock_wazuh_aws_database, mock_decompress, mock_json_load,
                                                    class_: AWSCloudTrailBucket or AWSConfigBucket,
                                                    json_file_content: dict, result: list[dict] or None):
    """Test 'load_information_from_file' method returns the expected information.

    Parameters
    ----------
    class_: AWSCloudTrailBucket or AWSConfigBucket
        Subclasses of AWSLogsBucket which determine the field to load from the file.
    json_file_content: dict
        File content.
    result: list[dict] or None
        Expected information to be fetched from the file.
    """
    instance = utils.get_mocked_bucket(class_=class_)

    mock_json_load.return_value = json_file_content

    assert result == instance.load_information_from_file(test_constants.TEST_LOG_KEY)
    mock_decompress.assert_called_once_with(instance.bucket, log_key=test_constants.TEST_LOG_KEY)


@pytest.mark.parametrize('profile', [test_constants.TEST_AWS_PROFILE, None])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_aws_custom_bucket_initializes_properly(mock_bucket, mock_wazuh_aws_database, mock_sts, profile):
    """Test if the instances of AWSCustomBucket are created properly."""

    mock_client = MagicMock()
    mock_sts.return_value = mock_client

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket,
                                       profile=profile)
    mock_bucket.assert_called_once()

    assert instance.retain_db_records == constants.MAX_AWS_BUCKET_RECORD_RETENTION
    mock_sts.assert_called_with(profile=profile)
    mock_client.get_caller_identity.assert_called_once()
    assert instance.macie_location_pattern == re.compile(r'"lat":(-?0+\d+\.\d+),"lon":(-?0+\d+\.\d+)')
    assert instance.check_prefix


@pytest.mark.parametrize('data, result', [
    ('{"source": "aws.custombucket", "detail": {"schemaVersion": "2.0"}}',
     [{"source": "custombucket", "schemaVersion": "2.0"}]),
    ('version account_id\nversion account_id', [{"source": "vpc", "version": "version", "account_id": "account_id"}])
])
@patch('csv.DictReader', return_value=[{"version": "version", "account_id": "account_id"}])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_load_information_from_file(mock_wazuh_aws_database, mock_sts, mock_reader,
                                                      data: str, result: list[dict]):
    """Test 'load_information_from_file' method returns the expected information.

    Parameters
    ----------
    data: str
        File content.
    result: list[dict]
        Expected information to be fetched from the file.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    with patch('aws_bucket.AWSBucket.decompress_file', mock_open(read_data=data)):
        assert result == instance.load_information_from_file(test_constants.TEST_LOG_KEY)


@pytest.mark.parametrize('log_file, expected_date', [
    ({'Key': 'AWSLogs/166157441623/elasticloadbalancing/us-west-1/2021/12/21/166157441623_elasticloadbalancing'},
     20211221),
    ({'Key': 'AWSLogs/875611522134/elasticloadbalancing/us-west-1/2020/01/03/166157441623_elasticloadbalancing'},
     20200103),
    ({'Key': '981837383623/iplogs/2020-09-20/2020-09-20-00-00-moyl.csv.gz'}, 20200920),
    ({'Key': '836629801214/iplogs/2021-01-18/2021-01-18-00-00-zxsb.csv.gz'}, 20210118),
    ({'Key': '2020/09/30/13/firehose_guardduty-1-2020-09-30-13-17-05-532e184c-1hfba.zip'}, 20200930),
    ({'Key': '2020/10/15/03/firehose_guardduty-1-2020-10-15-03-22-01-ea728dd1-763a4.zip'}, 20201015),
    ({'Key': 'AWSLogs/567970947422/GuardDuty/us-east-1/2022/10/21/ec7b0b8c-5ec8-32ec-8e77-c738515b4f6f.jsonl.gz'},
     20221021),
    ({'Key': '2021/03/18/aws-waf-logs-delivery-stream-1-2021-03-18-10-32-48-77baca34f-efad-4f14-45bd7871'},
     20210318),
    ({'Key': '2021/09/06/aws-waf-logs-delivery-stream-1-2021-09-06-21-02-18-8ba031bbd-babf-4c6a-83ba282c'},
     20210906),
    ({'Key': '2021-11-12-09-11-26-B9F9F891E8D0EB13'}, 20211112),
    ({'Key': '20-03-02-21-02-43-A8269E82CA8BDD21', 'LastModified': datetime.strptime('2021/01/23', '%Y/%m/%d')},
     20210123)
])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_get_creation_date(mock_wazuh_aws_database, mock_sts, log_file: dict, expected_date: int):
    """Test AWSCustomBucket's get_creation_date method.

    Parameters
    ----------
    log_file : dict
        The log file introduced.
    expected_date : int
        The date that the method should return.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    assert instance.get_creation_date(log_file) == expected_date


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_get_full_prefix(mock_wazuh_aws_database, mock_sts):
    """Test 'get_full_prefix' method returns the expected prefix."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket, prefix=test_constants.TEST_PREFIX)

    assert instance.get_full_prefix(test_constants.TEST_ACCOUNT_ID,
                                    test_constants.TEST_REGION) == test_constants.TEST_PREFIX


@pytest.mark.parametrize('event_field, event_field_name', [('count', ''), ('other_field', 'event_field_value')])
@pytest.mark.parametrize('source', ['macie', 'custom'])
@pytest.mark.parametrize('macie_field', ['Bucket', 'DLP risk', 'IP', 'Location', 'Object',
                                         'Owner', 'Themes', 'Timestamps', 'recipientAccountId'])
def test_aws_custom_bucket_reformat_msg(macie_field: str, source: str, event_field: str, event_field_name: str):
    """Test 'reformat_msg' method applies the expected format to a given event depending on the event field.

    Parameters
    ----------
    macie_field: str
        Fields present in AWS Macie logs.
    source: str
        Field that determines from which AWS Service the log comes from.
    event_field: str
        Field that may or may not be present in the event.
    event_field_name: str
        Field that may or may not be present in the event.
    """
    event = copy.deepcopy(constants.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update(
        {
            'source': source,
            'trigger': 'test_value',
            'service': {
                'additionalInfo': {
                    'unusual': 'unusual_value'
                }
            }
        }
    )
    if event['aws']['source'] == 'macie':
        event['aws'].update(
            {
                'trigger': 'test_value',
                'summary': {
                    macie_field: {
                        'test_key': 'value'
                    },
                    'Events': {
                        'event_name': {
                            event_field: {
                                event_field_name: 'value'
                            }
                        }
                    }
                }
            }
        )

    with patch('wazuh_integration.WazuhIntegration.get_sts_client'), \
            patch('wazuh_integration.WazuhAWSDatabase.__init__'), \
            patch('aws_bucket.AWSBucket.reformat_msg') as mock_reformat:
        instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

        instance.reformat_msg(event)
        mock_reformat.assert_called_once_with(instance, event)
        assert event['aws']['service']['additionalInfo']['unusual'] == {'value': 'unusual_value'}

        if source == 'macie':
            assert 'trigger' not in event['aws']
            assert event['aws']['summary'][macie_field] == ['test_key']
            assert event['aws']['summary']['Events']['event_name'] == {event_field: [event_field_name]}


@patch('aws_bucket.AWSBucket.iter_files_in_bucket')
@patch('aws_bucket.AWSCustomBucket.db_maintenance')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_iter_regions_and_accounts(mock_wazuh_aws_database, mock_sts, mock_maintenance,
                                                     mock_iter_files_bucket):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    instance.iter_regions_and_accounts(test_constants.TEST_ACCOUNT_ID,
                                       test_constants.TEST_REGION)

    mock_maintenance.assert_called_once()
    mock_iter_files_bucket.assert_called_once()


@pytest.mark.parametrize('log_file, account_id, region, expected_result', [
    (test_constants.TEST_LOG_FULL_PATH_CUSTOM_1, test_constants.TEST_ACCOUNT_ID,
     test_constants.TEST_REGION, True),
    (test_constants.TEST_LOG_FULL_PATH_CUSTOM_2, test_constants.TEST_ACCOUNT_ID,
     test_constants.TEST_REGION, True),
    ("", test_constants.TEST_ACCOUNT_ID, test_constants.TEST_REGION, False),
    (test_constants.TEST_LOG_FULL_PATH_CUSTOM_1, test_constants.TEST_ACCOUNT_ID, "", True),
    (test_constants.TEST_LOG_FULL_PATH_CUSTOM_1, "", test_constants.TEST_REGION, False),
])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_already_processed(mock_wazuh_aws_database, mock_sts,
                                             custom_database, log_file: str, account_id: str, region: str,
                                             expected_result):
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
    utils.database_execute_script(custom_database, TEST_CUSTOM_SCHEMA)

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket, bucket=test_constants.TEST_BUCKET, region=region)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = 'custom'
    instance.aws_account_id = account_id

    assert instance.already_processed(downloaded_file=log_file, aws_account_id=account_id,
                                      aws_region=region) == expected_result


def test_aws_custom_bucket_mark_complete():
    """Test 'mark_complete' method inserts non-processed logs into the DB."""
    test_log_file = 'log_file'

    bucket = utils.get_mocked_aws_bucket()

    with patch('wazuh_integration.WazuhIntegration.get_sts_client'), \
            patch('wazuh_integration.WazuhAWSDatabase.__init__'), \
            patch('aws_bucket.AWSBucket.mark_complete'):
        instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)
        instance.aws_account_id = test_constants.TEST_ACCOUNT_ID

        instance.mark_complete(test_constants.TEST_ACCOUNT_ID,
                               test_constants.TEST_REGION, test_log_file)
        bucket.mark_complete.assert_called_once_with(instance, instance.aws_account_id,
                                                     test_constants.TEST_REGION,
                                                     test_log_file)


@pytest.mark.parametrize('aws_account_id', [test_constants.TEST_ACCOUNT_ID, None])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_db_count_custom(mock_wazuh_aws_database, mock_sts, custom_database,
                                           aws_account_id: str or None):
    """Test 'db_count_region' method returns the number of rows in DB for an AWS account id.

    Parameters
    ----------
    aws_account_id: str or None
        AWS account ID.
    """
    utils.database_execute_script(custom_database, TEST_CUSTOM_SCHEMA)

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = "custom"
    instance.aws_account_id = test_constants.TEST_ACCOUNT_ID

    expected_count = CUSTOM_SCHEMA_COUNT
    assert instance.db_count_custom(aws_account_id) == expected_count


@pytest.mark.parametrize('expected_db_count', [CUSTOM_SCHEMA_COUNT, 0])
@pytest.mark.parametrize('aws_account_id', [test_constants.TEST_ACCOUNT_ID, None])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_db_maintenance(mock_wazuh_aws_database, mock_sts, aws_account_id, expected_db_count,
                                          custom_database):
    """Test 'db_maintenance' method deletes rows from a table until the count is equal to 'retain_db_records'."""
    utils.database_execute_script(custom_database, TEST_CUSTOM_SCHEMA)

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = "custom"
    instance.retain_db_records = expected_db_count
    instance.aws_account_id = test_constants.TEST_ACCOUNT_ID

    assert utils.database_execute_query(instance.db_connector, constants.SQL_COUNT_ROWS.format(
        table_name=instance.db_table_name)) == CUSTOM_SCHEMA_COUNT

    with patch('aws_bucket.AWSCustomBucket.db_count_custom', return_value=CUSTOM_SCHEMA_COUNT):
        instance.db_maintenance(aws_account_id=aws_account_id)

    assert utils.database_execute_query(instance.db_connector, constants.SQL_COUNT_ROWS.format(
        table_name=instance.db_table_name)) == expected_db_count


@patch('builtins.print')
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_db_maintenance_handles_exceptions(mock_wazuh_aws_database, mock_sts, mock_print,
                                                             custom_database):
    """Test 'db_maintenance' handles exceptions raised when trying to execute a query to the DB."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    instance.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception

    instance.db_maintenance(aws_account_id=test_constants.TEST_ACCOUNT_ID)

    mock_print.assert_called_once()
