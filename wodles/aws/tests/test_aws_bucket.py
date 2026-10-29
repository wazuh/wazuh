# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import gzip
import os
import sqlite3
import sys
import time
import zipfile
import re
import csv
from datetime import date, datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, mock_open

import botocore
import pytest
import zlib

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
from cloudtrail import AWSCloudTrailBucket
from config import AWSConfigBucket
from guardduty import AWSGuardDutyBucket
from load_balancers import AWSALBBucket
from server_access import AWSServerAccess
from umbrella import CiscoUmbrella
from vpcflow import AWSVPCFlowBucket
from waf import AWSWAFBucket

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

utils.LIST_OBJECT_V2_NO_PREFIXES['Contents'][0]['Key'] = utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1


@pytest.mark.parametrize('only_logs_after', [None, "20220101"])
@patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version')
@patch('wazuh_integration.sqlite3.connect')
@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH)
@patch('wazuh_integration.utils.get_wazuh_version')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_bucket_initializes_properly(mock_wazuh_integration, mock_version, mock_path, mock_client, mock_connect,
                                         mock_metadata,
                                         only_logs_after: str or None):
    """Test if the instances of AWSBucket are created properly."""
    kwargs = utils.get_aws_bucket_parameters(db_table_name=utils.TEST_TABLE_NAME, bucket=utils.TEST_BUCKET,
                                             profile=utils.TEST_AWS_PROFILE, access_key=utils.TEST_ACCESS_KEY,
                                             secret_key=utils.TEST_SECRET_KEY, iam_role_arn=utils.TEST_IAM_ROLE_ARN,
                                             account_alias=utils.TEST_ACCOUNT_ALIAS, prefix=utils.TEST_PREFIX,
                                             suffix=utils.TEST_SUFFIX, aws_organization_id=utils.TEST_ORGANIZATION_ID,
                                             region=utils.TEST_REGION, discard_field=utils.TEST_DISCARD_FIELD,
                                             discard_regex=utils.TEST_DISCARD_REGEX,
                                             sts_endpoint=utils.TEST_STS_ENDPOINT,
                                             service_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                             iam_role_duration=utils.TEST_IAM_ROLE_DURATION, delete_file=True,
                                             skip_on_error=True, reparse=True, only_logs_after=only_logs_after)
    integration = aws_bucket.AWSBucket(**kwargs)
    mock_wazuh_integration.assert_called_with(integration, service_name="s3",
                                              access_key=kwargs["access_key"], secret_key=kwargs["secret_key"],
                                              profile=kwargs["profile"], iam_role_arn=kwargs["iam_role_arn"],
                                              region=kwargs["region"], discard_field=kwargs["discard_field"],
                                              discard_regex=kwargs["discard_regex"],
                                              sts_endpoint=kwargs["sts_endpoint"],
                                              service_endpoint=kwargs["service_endpoint"],
                                              iam_role_duration=kwargs["iam_role_duration"], external_id=None,
                                              skip_on_error=kwargs["skip_on_error"])

    assert integration.retain_db_records == aws_bucket.MAX_RECORD_RETENTION
    assert integration.reparse == kwargs["reparse"]
    assert integration.only_logs_after == datetime.strptime(only_logs_after, aws_bucket.DB_DATE_FORMAT) \
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
    (utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    (utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_2, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    ("", utils.TEST_ACCOUNT_ID, utils.TEST_REGION, False),
    (utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, utils.TEST_ACCOUNT_ID, "", False),
    (utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1, "", utils.TEST_REGION, False),
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

    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, region=region)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = 'cloudtrail'

    assert bucket.already_processed(downloaded_file=log_file, aws_account_id=account_id,
                                    aws_region=region) == expected_result


def test_aws_bucket_get_creation_date_raises_exception():
    """Test 'get_creation_date' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_creation_date(utils.TEST_LOG_KEY)


def test_aws_bucket_mark_complete(custom_database):
    """Test 'mark_complete' method inserts non-processed logs into the DB."""
    utils.database_execute_script(custom_database, TEST_EMPTY_TABLE_SCHEMA)

    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    assert utils.database_execute_query(bucket.db_connector,
                                        utils.SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 0

    with patch('aws_bucket.AWSBucket.get_creation_date', return_value=utils.TEST_CREATION_DATE):
        bucket.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                             log_file={'Key': utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1})

    assert utils.database_execute_query(bucket.db_connector,
                                        utils.SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 1

    row = utils.database_execute_query(bucket.db_connector, SQL_GET_ROW.format(table_name=bucket.db_table_name))
    assert row[0] == f"{utils.TEST_BUCKET}/"
    assert row[1] == utils.TEST_ACCOUNT_ID
    assert row[2] == utils.TEST_REGION
    assert row[3] == utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1
    assert row[4] == utils.TEST_CREATION_DATE


@patch('aws_bucket.aws_tools.debug')
def test_aws_bucket_mark_complete_handles_exceptions_when_db_query_fails(mock_debug, custom_database):
    """Test 'mark_complete' handles exceptions raised when trying to execute a query to the DB."""
    bucket = utils.get_mocked_aws_bucket()

    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception
    bucket.db_cursor = mocked_cursor

    bucket.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                         log_file={'Key': utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1})

    mock_debug.assert_called_with(f'+++ Error marking log {utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1} as completed: ', 2)


@pytest.mark.parametrize("prefix", ["", "archive/2024/01/01/"])
@pytest.mark.parametrize("marker_suffix, expected_called",[
        ("2026/01/30/00/test.json.gz", True),
        ("no-date-here/test.json.gz", False),
    ])
def test_aws_bucket_rewind_marker_to_day_folder(marker_suffix, expected_called, prefix):
    """Test 'rewind_marker_to_day_folder' rewinds the marker to the day folder (YYYY/MM/DD) when applicable,
    ignoring any date in the configured prefix."""
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET)

    bucket.date_regex = re.compile(r"(\d{4}/\d{2}/\d{2})")
    full_prefix = f"{prefix}AWSLogs/{utils.TEST_ACCOUNT_ID}/CloudTrail/{utils.TEST_REGION}/"
    marker = f"{full_prefix}{marker_suffix}"

    with patch('aws_bucket.AWSBucket.marker_custom_date', return_value="rewound-marker") as mock_marker_custom_date, \
            patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        result = bucket.rewind_marker_to_day_folder(
            marker=marker,
            aws_account_id=utils.TEST_ACCOUNT_ID,
            aws_region=utils.TEST_REGION
        )

    if expected_called:
        assert result == "rewound-marker"
        mock_marker_custom_date.assert_called_once()
        args, _ = mock_marker_custom_date.call_args
        assert args[0] == utils.TEST_REGION
        assert args[1] == utils.TEST_ACCOUNT_ID
        assert isinstance(args[2], datetime)
        assert args[2].strftime('%Y/%m/%d') == "2026/01/29"
    else:
        assert result == marker
        mock_marker_custom_date.assert_not_called()


@pytest.mark.parametrize('region', [utils.TEST_REGION, "invalid_region"])
def test_aws_bucket_db_count_region(custom_database, region):
    """Test 'db_count_region' method counts the number of rows in DB for a region"""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    expected_count = CLOUDTRAIL_SCHEMA_COUNT if region == utils.TEST_REGION else 0
    assert bucket.db_count_region(utils.TEST_ACCOUNT_ID, region) == expected_count


@pytest.mark.parametrize('expected_db_count', [CLOUDTRAIL_SCHEMA_COUNT, 0])
def test_aws_bucket_db_maintenance(custom_database, expected_db_count):
    """Test 'db_maintenance' method deletes rows from a table until the count is equal to 'retain_db_records'."""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME
    bucket.retain_db_records = expected_db_count

    assert utils.database_execute_query(bucket.db_connector, utils.SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == CLOUDTRAIL_SCHEMA_COUNT

    bucket.rewinds_marker = False
    with patch('aws_bucket.AWSBucket.db_count_region', return_value=CLOUDTRAIL_SCHEMA_COUNT):
        bucket.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)

    assert utils.database_execute_query(bucket.db_connector, utils.SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == expected_db_count


@pytest.mark.parametrize('retain_db_records, expected_deleted_days', [
    (0, ['2019/03/29', '2019/03/30']),
    (CLOUDTRAIL_SCHEMA_COUNT + 1, ['2019/03/29', '2019/03/30']),
    (CLOUDTRAIL_SCHEMA_COUNT + 3, []),
])
def test_aws_bucket_db_maintenance_keeps_late_arrival_window(custom_database, retain_db_records,
                                                             expected_deleted_days):
    """Test 'db_maintenance' method keeps the rows inside the rewound marker window for the late arrival tables,
    as the next fetch would list those files again."""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME
    bucket.retain_db_records = retain_db_records

    # Every row of the schema is from 2019/04/01, so the window starts at 2019/03/31
    full_prefix = 'AWSLogs/123456789/CloudTrail/us-east-1/'
    old_keys = {day: f'{full_prefix}{day}/123456789_CloudTrail-us-east-1_{day.replace("/", "")}T0000Z_aaaa.json.gz'
                for day in ['2019/03/29', '2019/03/30', '2019/03/31']}
    for key in old_keys.values():
        bucket.db_cursor.execute(bucket.sql_mark_complete.format(table_name=bucket.db_table_name), {
            'bucket_path': bucket.bucket_path, 'aws_account_id': utils.TEST_ACCOUNT_ID,
            'aws_region': utils.TEST_REGION, 'log_key': key, 'created_date': ''})

    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        bucket.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)

    remaining_keys = {row[0] for row in bucket.db_cursor.execute(f'SELECT log_key FROM {bucket.db_table_name}')}
    assert len(remaining_keys) == CLOUDTRAIL_SCHEMA_COUNT + len(old_keys) - len(expected_deleted_days)
    for day, key in old_keys.items():
        assert (key not in remaining_keys) == (day in expected_deleted_days)


@patch('aws_tools.get_script_arguments')
def test_aws_bucket_db_maintenance_then_build_s3_filter_args_keeps_late_arrival_window(mock_get_script_arguments,
                                                                                     custom_database):
    """Test the marker of the fetch after 'db_maintenance' still starts at the day before the last key processed, so
    a late file of that day sorting before every key processed of the day is listed."""
    mock_get_script_arguments.return_value.type = 'cloudtrail'
    bucket = utils.get_mocked_bucket(class_=AWSCloudTrailBucket, bucket=utils.TEST_BUCKET)
    bucket.db_connector = custom_database
    bucket.db_cursor = custom_database.cursor()
    bucket.db_cursor.execute(bucket.sql_create_table.format(table_name=bucket.db_table_name))

    full_prefix = bucket.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    for day in ['2019/03/30', '2019/03/31', '2019/04/01']:
        for index in range(bucket.retain_db_records // 2):
            bucket.mark_complete(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, {
                'Key': f'{full_prefix}{day}/{utils.TEST_ACCOUNT_ID}_CloudTrail_{utils.TEST_REGION}_'
                       f'{day.replace("/", "")}T0000Z_b{index:04d}.json.gz'})

    bucket.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)
    filter_args = bucket.build_s3_filter_args(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

    assert bucket.db_count_region(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) < bucket.retain_db_records // 2 * 3
    assert filter_args['StartAfter'] == f'{full_prefix}2019/03/31'
    late_key = f'{full_prefix}2019/03/31/{utils.TEST_ACCOUNT_ID}_CloudTrail_{utils.TEST_REGION}_20190331T0000Z_a.json.gz'
    assert late_key > filter_args['StartAfter']


def test_aws_bucket_db_maintenance_keeps_rows_of_other_prefixes(custom_database):
    """Test 'db_maintenance' only deletes the rows of its own full prefix, so an account trail and an organization
    trail of the same bucket, account and region do not delete each other's window."""
    account_trail = utils.get_mocked_bucket(class_=AWSCloudTrailBucket, bucket=utils.TEST_BUCKET)
    organization_trail = utils.get_mocked_bucket(class_=AWSCloudTrailBucket, bucket=utils.TEST_BUCKET,
                                                 aws_organization_id='o-abc')
    for bucket in (account_trail, organization_trail):
        bucket.db_connector = custom_database
        bucket.db_cursor = custom_database.cursor()
        bucket.retain_db_records = 0
    custom_database.execute(account_trail.sql_create_table.format(table_name=account_trail.db_table_name))

    for bucket in (account_trail, organization_trail):
        full_prefix = bucket.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
        for day in ['2019/03/30', '2019/04/01']:
            bucket.mark_complete(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, {
                'Key': f'{full_prefix}{day}/{utils.TEST_ACCOUNT_ID}_CloudTrail_{utils.TEST_REGION}_'
                       f'{day.replace("/", "")}T0000Z_a.json.gz'})

    organization_trail.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)

    remaining_keys = [row[0] for row in custom_database.execute('SELECT log_key FROM cloudtrail ORDER BY log_key')]
    account_prefix = account_trail.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    organization_prefix = organization_trail.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    assert len([key for key in remaining_keys if key.startswith(account_prefix)]) == 2
    assert [key for key in remaining_keys if key.startswith(organization_prefix)] == \
        [f'{organization_prefix}2019/04/01/{utils.TEST_ACCOUNT_ID}_CloudTrail_{utils.TEST_REGION}_20190401T0000Z_a.json.gz']


@patch('builtins.print')
def test_aws_bucket_db_maintenance_handles_exceptions_when_db_fails(mock_print, custom_database):
    """Test 'db_maintenance' method handles exceptions raised when fails to make the DB maintenance."""
    bucket = utils.get_mocked_aws_bucket()

    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = Exception

    bucket.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)

    mock_print.assert_called_once()


def test_aws_bucket_marker_custom_date():
    """Test 'marker_custom_date' method returns a valid AWS bucket marker when using a custom date."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.date_format = '%Y-%m-%d'

    test_date = datetime.now()
    full_prefix = f"{utils.TEST_ACCOUNT_ID}/{utils.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_custom_date(aws_region=utils.TEST_REGION, aws_account_id=utils.TEST_ACCOUNT_ID,
                                           date=test_date)
    assert marker == f"{full_prefix}{test_date.strftime(bucket.date_format)}"


def test_aws_bucket_marker_only_logs_after():
    """Test 'marker_only_logs_after' method returns a valid marker using only_log_after."""
    test_only_logs_after = utils.TEST_ONLY_LOGS_AFTER
    bucket = utils.get_mocked_aws_bucket(only_logs_after=test_only_logs_after)
    bucket.date_format = '%Y-%m-%d'

    full_prefix = f"{utils.TEST_ACCOUNT_ID}/{utils.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_only_logs_after(aws_region=utils.TEST_REGION, aws_account_id=utils.TEST_ACCOUNT_ID)
    assert marker == f"{full_prefix}{test_only_logs_after[0:4]}-{test_only_logs_after[4:6]}-{test_only_logs_after[6:8]}"


@pytest.mark.parametrize('event', [SAMPLE_EVENT_1, SAMPLE_EVENT_2, None])
def test_aws_bucket_get_alert_msg(event):
    """Test 'get_alert_msg' method returns messages with the valid format."""
    bucket = utils.get_mocked_aws_bucket(account_alias=utils.TEST_ACCOUNT_ALIAS)
    expected_error_message = "error message"
    expected_msg = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    expected_msg['aws']['log_info'].update({
        'aws_account_alias': bucket.account_alias,
        'log_file': utils.TEST_LOG_KEY,
        's3bucket': bucket.bucket
    })
    if event:
        # Remove 'None' values from the event before updating the message
        expected_msg['aws'].update({k: v for k, v in event.items() if v is not None})
    else:
        expected_msg['error_msg'] = expected_error_message
    assert bucket.get_alert_msg(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY, event,
                                error_msg=expected_error_message) == expected_msg


def test_aws_bucket_get_full_prefix():
    """Test 'get_full_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)


def test_aws_bucket_get_base_prefix():
    """Test 'get_base_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_base_prefix()


def test_aws_bucket_get_service_prefix():
    """Test 'get_service_prefix' method properly raise a NotImplementedError exception when being directly called."""
    bucket = utils.get_mocked_aws_bucket()

    with pytest.raises(NotImplementedError):
        bucket.get_service_prefix(utils.TEST_ACCOUNT_ID)


@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
def test_aws_bucket_find_account_ids(mock_prefix):
    """Test 'find_account_ids' method returns a valid account_ids list."""
    object_list = {'CommonPrefixes': [{'Prefix': f'AWSLogs/{utils.TEST_ACCOUNT_ID}/'},
                                      {'Prefix': f'AWSLogs/prefix/{utils.TEST_ACCOUNT_ID}/'}]}
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_account_ids()
    bucket.client.list_objects_v2.assert_called_with(Bucket=utils.TEST_BUCKET, Prefix=utils.TEST_PREFIX, Delimiter='/')
    assert accounts == [utils.TEST_ACCOUNT_ID for _ in object_list['CommonPrefixes']]


@pytest.mark.parametrize('error_code, exit_code', [
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, utils.THROTTLING_ERROR_CODE),
    ('OtherClientException', utils.UNKNOWN_ERROR_CODE)
])
@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
def test_aws_bucket_find_account_ids_handles_exceptions_on_client_error(mock_prefix, error_code: str, exit_code: int):
    """Test 'find_account_ids' method handles client errors as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}}, "name")

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == exit_code


@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
@patch('aws_bucket.aws_tools.get_script_arguments')
def test_aws_bucket_find_account_ids_handles_exceptions_on_key_error(mock_prefix, mock_script_arguments):
    """Test 'find_account_ids' method handles KeyError as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = KeyError

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == utils.INVALID_PREFIX_ERROR_CODE


@pytest.mark.parametrize('object_list', [utils.LIST_OBJECT_V2, utils.LIST_OBJECT_V2_NO_PREFIXES])
@patch('aws_bucket.AWSBucket.get_service_prefix', return_value=utils.TEST_PREFIX)
def test_aws_bucket_find_regions(mock_prefix, object_list: dict):
    """Test 'find_regions' method returns a valid region list."""

    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_regions(utils.TEST_ACCOUNT_ID)
    bucket.client.list_objects_v2.assert_called_with(Bucket=utils.TEST_BUCKET, Prefix=utils.TEST_PREFIX, Delimiter='/')
    if object_list.get('CommonPrefixes'):
        assert accounts == [utils.TEST_REGION for _ in object_list['CommonPrefixes']]
    else:
        assert len(accounts) == 0


@pytest.mark.parametrize('error_code, exit_code', [
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, utils.THROTTLING_ERROR_CODE),
    ('OtherClientException', utils.UNKNOWN_ERROR_CODE)
])
@patch('aws_bucket.AWSBucket.get_service_prefix', return_value=utils.TEST_PREFIX)
def test_aws_bucket_find_regions_handles_exceptions_on_client_error(mock_prefix, error_code: str, exit_code: int):
    """Test 'find_regions' method handles client errors as expected."""
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError({'Error': {'Code': error_code}}, "name")

    with pytest.raises(SystemExit) as e:
        bucket.find_regions(utils.TEST_ACCOUNT_ID)
    assert e.value.code == exit_code


@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('only_logs_after', [utils.TEST_ONLY_LOGS_AFTER, None])
@pytest.mark.parametrize('iterating', [True, False])
@pytest.mark.parametrize('custom_delimiter', ['', '-'])
@pytest.mark.parametrize('region', [utils.TEST_REGION, 'region_for_empty_db'])
@pytest.mark.parametrize('config_type', ['config', 'other'])
@patch('aws_bucket.AWSBucket.get_full_prefix', return_value=utils.TEST_FULL_PREFIX)
@patch('aws_tools.get_script_arguments')
def test_aws_bucket_build_s3_filter_args(mock_get_script_arguments, mock_get_full_prefix, custom_database,
                                         region: str, custom_delimiter: str, iterating: bool,
                                         only_logs_after: str or None, reparse: bool, config_type: str):
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
    config_type: str
        Type of configuration to test for.
    """
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)

    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, reparse=reparse, only_logs_after=only_logs_after)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    expected_filter_args = {
        'Bucket': bucket.bucket,
        'MaxKeys': 1000,
        'Prefix': mock_get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    }

    aws_account_id = utils.TEST_ACCOUNT_ID
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

    if (not bucket.reparse
            and bucket.rewinds_marker
            and aws_region != 'region_for_empty_db'):
        filter_marker = bucket.rewind_marker_to_day_folder(filter_marker, aws_account_id, aws_region)

    mock_get_script_arguments.return_value.type = config_type

    if not iterating:
        if config_type == 'config':
            filter_marker = re.match(r'(.*?/\d{4}/)', filter_marker).group(1)
            expected_filter_args['StartAfter'] = filter_marker
            
            assert expected_filter_args == bucket.build_s3_filter_args(aws_account_id, aws_region, iterating,
                                                                custom_delimiter)
        else:
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
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
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
        bucket.load_information_from_file(utils.TEST_LOG_KEY)


@pytest.mark.parametrize('expected_result', [SAMPLE_EVENT_1, SAMPLE_EVENT_2])
@patch('aws_bucket.AWSBucket.load_information_from_file')
def test_aws_bucket_get_log_file(mock_load_from_file, expected_result):
    """Test 'get_log_file' method returns the expected event from a log file"""
    bucket = utils.get_mocked_aws_bucket()
    mock_load_from_file.return_value = expected_result
    assert expected_result == bucket.get_log_file(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY)
    mock_load_from_file.assert_called_with(log_key=utils.TEST_LOG_KEY)


@pytest.mark.parametrize('exception, error_message, exit_code', [
    (TypeError, f'Failed to decompress file {utils.TEST_LOG_KEY}: TypeError()', utils.DECOMPRESS_FILE_ERROR_CODE),
    (zipfile.BadZipfile, f'Failed to decompress file {utils.TEST_LOG_KEY}: BadZipFile()',
     utils.DECOMPRESS_FILE_ERROR_CODE),
    (zipfile.LargeZipFile, f'Failed to decompress file {utils.TEST_LOG_KEY}: LargeZipFile()',
     utils.DECOMPRESS_FILE_ERROR_CODE),
    (IOError, f'Failed to decompress file {utils.TEST_LOG_KEY}: OSError()', utils.DECOMPRESS_FILE_ERROR_CODE),
    (ValueError, f'Failed to parse file {utils.TEST_LOG_KEY}: ValueError()', utils.PARSE_FILE_ERROR_CODE),
    (csv.Error, f'Failed to parse file {utils.TEST_LOG_KEY}: Error()', utils.PARSE_FILE_ERROR_CODE),
    (Exception, f'Unknown error reading/parsing file {utils.TEST_LOG_KEY}: Exception()', utils.UNKNOWN_ERROR_CODE)
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

            bucket.get_log_file(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY)
            mock_debug.assert_called_with(debug_message_example, 1)
            mock_get_alert_msg.assert_called_once_with(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY, None, error_message)
            mock_send_msg.assert_called_once_with(mock_get_alert_msg())

            mock_send_msg.side_effect = Exception
            bucket.get_log_file(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY)
            mock_debug.assert_called_with("++ Failed to send message to Wazuh", 1)

    else:
        with pytest.raises(SystemExit) as e:
            bucket.get_log_file(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY)
        assert e.value.code == exit_code


@patch('aws_bucket.AWSBucket.iter_regions_and_accounts')
@patch('aws_bucket.AWSBucket.init_db')
def test_aws_bucket_iter_bucket(mock_init, mock_iter):
    """Test 'iter_bucket' method calls the appropriate functions."""
    bucket = utils.get_mocked_aws_bucket()
    bucket.db_connector = MagicMock()
    bucket.db_cursor = MagicMock()
    bucket.iter_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

    mock_init.assert_called_once()
    mock_iter.assert_called_with(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    bucket.db_connector.commit.assert_called_once()
    bucket.db_cursor.execute.assert_called_with(bucket.sql_db_optimize)
    bucket.db_connector.close.assert_called_once()


@pytest.mark.parametrize('account_id', [[utils.TEST_ACCOUNT_ID], None])
@pytest.mark.parametrize('regions', [[utils.TEST_REGION], None])
@patch('aws_bucket.AWSBucket.find_account_ids', return_value=[utils.TEST_ACCOUNT_ID])
@patch('aws_bucket.AWSBucket.find_regions', side_effect=[[utils.TEST_REGION], None])
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

    bucket.iter_events(event_list, utils.TEST_LOG_KEY, utils.TEST_ACCOUNT_ID)
    for event in event_list:
        if bucket.discard_field and discard_regex:
            mock_debug.assert_any_call(
                f'+++ The "{bucket.discard_regex.pattern}" regex found a match in the "{bucket.discard_field}" '
                f'field. The event will be skipped.', 2)
            continue
        mock_get_alert.assert_called_with(utils.TEST_ACCOUNT_ID, utils.TEST_LOG_KEY, event)
        mock_send_event.assert_called()


@pytest.mark.parametrize('object_list',
                         [utils.LIST_OBJECT_V2, utils.LIST_OBJECT_V2_NO_PREFIXES, utils.LIST_OBJECT_V2_TRUNCATED])
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
    bucket = utils.get_mocked_aws_bucket(bucket=utils.TEST_BUCKET, delete_file=delete_file, reparse=reparse,
                                         prefix=utils.TEST_PREFIX)

    mock_build_filter.return_value = {
        'Bucket': bucket.bucket,
        'MaxKeys': 1000,
        'Prefix': utils.TEST_PREFIX
    }

    bucket.client.list_objects_v2.return_value = object_list
    bucket.check_prefix = check_prefix

    aws_account_id = utils.TEST_ACCOUNT_ID
    aws_region = utils.TEST_REGION

    with patch('aws_bucket.AWSBucket.already_processed', return_value=True) as mock_already_processed, \
            patch('aws_bucket.AWSBucket.get_log_file') as mock_get_log_file, \
            patch('aws_bucket.AWSBucket.iter_events') as mock_iter_events, \
            patch('aws_bucket.AWSBucket.mark_complete') as mock_mark_complete, \
            patch('aws_bucket.AWSBucket.get_full_prefix', return_value=utils.TEST_FULL_PREFIX):

        if 'IsTruncated' in object_list and object_list['IsTruncated']:
            bucket.client.list_objects_v2.side_effect = [object_list, utils.LIST_OBJECT_V2_NO_PREFIXES]

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

                if not bucket.is_valid_marker(bucket_file['Key'], aws_account_id, aws_region,
                                              bucket_file['LastModified']):
                    mock_debug.assert_any_call(f"+++ WARNING: Skipping file without a valid date after the prefix or "
                                               f"dated after it was written: {bucket_file['Key']}", 1)
                    continue

                mock_already_processed.assert_called_with(bucket_file['Key'], aws_account_id, aws_region)
                if bucket.reparse:
                    mock_debug.assert_any_call(
                        f"++ File previously processed, but reparse flag set: {bucket_file['Key']}",
                        1)
                else:
                    mock_debug.assert_any_call(f"++ Skipping previously processed file: {bucket_file['Key']}", 2)
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
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, utils.THROTTLING_ERROR_CODE),
    ('OtherClientException', utils.UNKNOWN_ERROR_CODE),
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
            bucket.iter_files_in_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
        assert e.value.code == exit_code

        with pytest.raises(SystemExit) as e:
            mock_build_filter.side_effect = Exception
            bucket.iter_files_in_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
        assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3


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
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, utils.THROTTLING_ERROR_CODE),
    (aws_bucket.INVALID_CREDENTIALS_ERROR_CODE, utils.INVALID_CREDENTIALS_ERROR_CODE),
    (aws_bucket.INVALID_REQUEST_TIME_ERROR_CODE, utils.INVALID_REQUEST_TIME_ERROR_CODE),
    ("OtherClientError", utils.UNKNOWN_ERROR_CODE)
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
    assert e.value.code == utils.INVALID_ENDPOINT_ERROR_CODE


@pytest.mark.parametrize('prefix', [utils.TEST_PREFIX, None])
@pytest.mark.parametrize('suffix', [utils.TEST_SUFFIX, None])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_aws_logs_bucket_initializes_properly(mock_bucket, mock_wazuh_aws_database, prefix, suffix):
    """Test if the instances of AWSLogsBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, bucket=utils.TEST_BUCKET,
                                       prefix=prefix, suffix=suffix)
    mock_bucket.assert_called_once()
    assert instance.bucket_path == f"{utils.TEST_BUCKET}/{prefix}{suffix}"


@pytest.mark.parametrize('organization_id', [utils.TEST_ORGANIZATION_ID, None])
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_logs_bucket_get_base_prefix(mock_wazuh_aws_database, organization_id):
    """Test 'get_base_prefix' returns the expected prefix with the format
    <prefix>/AWSLogs/<suffix>/<organization_id>/.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, aws_organization_id=organization_id,
                                       prefix=f'{utils.TEST_PREFIX}/', suffix=f'{utils.TEST_SUFFIX}/')
    expected_base_prefix = os.path.join(utils.TEST_PREFIX, 'AWSLogs', utils.TEST_SUFFIX,
                                        (organization_id if organization_id else ""), '')
    assert instance.get_base_prefix() == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSLogsBucket.get_base_prefix', return_value='base_prefix/')
def test_aws_logs_bucket_get_service_prefix(mock_base_prefix, mock_wazuh_aws_database):
    """Test 'get_service_prefix' method returns the expected prefix with the format
    <base_prefix>/<account_id>/<service>.
    """
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    instance.service = utils.TEST_SERVICE_NAME
    expected_base_prefix = os.path.join('base_prefix', utils.TEST_ACCOUNT_ID, utils.TEST_SERVICE_NAME, '')
    assert instance.get_service_prefix(utils.TEST_ACCOUNT_ID) == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSLogsBucket.get_service_prefix', return_value='service_prefix/')
def test_aws_logs_bucket_get_full_prefix(mock_service_prefix, mock_wazuh_aws_database):
    """Test 'get_full_prefix' method returns the expected prefix with the format <service_prefix>/<region>."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, region=utils.TEST_REGION)
    expected_base_prefix = os.path.join('service_prefix', utils.TEST_REGION, '')
    assert instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == expected_base_prefix


@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_logs_bucket_get_creation_date(mock_wazuh_aws_database):
    """Test 'get_creation_date' method returns the expected date from a log filename."""
    log_file = {'Key': utils.TEST_LOG_FULL_PATH_CLOUDTRAIL_1}
    expected_result = 20190401
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    assert instance.get_creation_date(log_file) == expected_result


def test_aws_logs_bucket_get_alert_msg():
    """Test 'get_alert_msg' method returns messages with the valid format."""
    bucket = utils.get_mocked_aws_bucket()

    with patch('wazuh_integration.WazuhAWSDatabase.__init__'):
        instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
        aws_account_id = utils.TEST_ACCOUNT_ID
        expected_msg = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
        expected_error_message = "error message"

        expected_alert_msg = bucket.get_alert_msg(aws_account_id, utils.TEST_LOG_KEY, expected_msg,
                                                  error_msg=expected_error_message)
        expected_alert_msg['aws']['aws_account_id'] = aws_account_id

        assert expected_alert_msg == instance.get_alert_msg(aws_account_id, utils.TEST_LOG_KEY, expected_msg,
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

    assert result == instance.load_information_from_file(utils.TEST_LOG_KEY)
    mock_decompress.assert_called_once_with(instance.bucket, log_key=utils.TEST_LOG_KEY)


@pytest.mark.parametrize('profile', [utils.TEST_AWS_PROFILE, None])
@pytest.mark.parametrize('secret_key', [utils.TEST_SECRET_KEY, None])
@pytest.mark.parametrize('access_key', [utils.TEST_ACCESS_KEY, None])
@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_aws_custom_bucket_initializes_properly(mock_bucket, mock_wazuh_aws_database, mock_sts, access_key, secret_key,
                                                profile):
    """Test if the instances of AWSCustomBucket are created properly."""

    mock_client = MagicMock()
    mock_sts.return_value = mock_client

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket,
                                       profile=profile,
                                       secret_key=secret_key,
                                       access_key=access_key)
    mock_bucket.assert_called_once()

    assert instance.retain_db_records == aws_bucket.MAX_RECORD_RETENTION
    mock_sts.assert_called_with(access_key, secret_key, profile=profile)
    mock_client.get_caller_identity.assert_called_once()
    assert instance.macie_location_pattern == re.compile(r'"lat":(-?0\d+\.\d+),"lon":(-?0\d+\.\d+)')
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
        assert result == instance.load_information_from_file(utils.TEST_LOG_KEY)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_load_information_from_file_macie_recovery_unchanged(mock_wazuh_aws_database, mock_sts):
    """Test 'load_information_from_file' keeps its existing (buggy) Macie lat/lon recovery
    behavior unchanged after the performance fix: re.sub() in the recovery branch is still a
    global substitution, so a second finding with its OWN different malformed lat/lon still ends
    up with the FIRST finding's corrected value. The fix is scoped to performance only (tracking
    a position instead of re-slicing data every iteration); this is a regression guard proving
    that refactor did not also change this pre-existing, separately-tracked behavior.
    """
    data = ('{"source":"aws.macie","detail":{"id":"finding-1","lat":0010.0,"lon":0020.0}}'
            '{"source":"aws.macie","detail":{"id":"finding-2","lat":0099.9,"lon":0088.8}}')
    expected = [
        {"id": "finding-1", "lat": 10.0, "lon": 20.0, "source": "macie"},
        {"id": "finding-2", "lat": 10.0, "lon": 20.0, "source": "macie"},  # inherits finding-1's values
    ]
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    with patch('aws_bucket.AWSBucket.decompress_file', mock_open(read_data=data)):
        assert expected == instance.load_information_from_file(utils.TEST_LOG_KEY)


@patch('wazuh_integration.WazuhIntegration.get_sts_client')
@patch('wazuh_integration.WazuhAWSDatabase.__init__')
def test_aws_custom_bucket_load_information_from_file_is_not_quadratic(mock_wazuh_aws_database, mock_sts):
    """Test 'load_information_from_file' processes a large number of concatenated JSON objects in
    time roughly proportional to the file size, not to its square. The pre-fix
    `data = data[json_index:]` pattern took ~0.75s for this exact input; the fix takes ~0.04s --
    0.3s is a decisive, non-flaky threshold between the two.
    """
    n_objects = 6000
    pad = "x" * 800
    obj = f'{{"source":"aws.custombucket","detail":{{"note":"{pad}","lat":5.5,"lon":6.6}}}}'
    data = obj * n_objects
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket)

    with patch('aws_bucket.AWSBucket.decompress_file', mock_open(read_data=data)):
        start = time.perf_counter()
        result = instance.load_information_from_file(utils.TEST_LOG_KEY)
        elapsed = time.perf_counter() - start

    assert len(result) == n_objects
    assert elapsed < 0.3, f"took {elapsed:.3f}s -- quadratic rescan likely reintroduced"


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
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket, prefix=utils.TEST_PREFIX)

    assert instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == utils.TEST_PREFIX


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
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
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

    instance.iter_regions_and_accounts(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

    mock_maintenance.assert_called_once()
    mock_iter_files_bucket.assert_called_once()


@pytest.mark.parametrize('log_file, account_id, region, expected_result', [
    (utils.TEST_LOG_FULL_PATH_CUSTOM_1, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    (utils.TEST_LOG_FULL_PATH_CUSTOM_2, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    ("", utils.TEST_ACCOUNT_ID, utils.TEST_REGION, False),
    (utils.TEST_LOG_FULL_PATH_CUSTOM_1, utils.TEST_ACCOUNT_ID, "", True),
    (utils.TEST_LOG_FULL_PATH_CUSTOM_1, "", utils.TEST_REGION, False),
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

    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSCustomBucket, bucket=utils.TEST_BUCKET, region=region)
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
        instance.aws_account_id = utils.TEST_ACCOUNT_ID

        instance.mark_complete(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, test_log_file)
        bucket.mark_complete.assert_called_once_with(instance, instance.aws_account_id, utils.TEST_REGION,
                                                     test_log_file)


@pytest.mark.parametrize('aws_account_id', [utils.TEST_ACCOUNT_ID, None])
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
    instance.aws_account_id = utils.TEST_ACCOUNT_ID

    expected_count = CUSTOM_SCHEMA_COUNT
    assert instance.db_count_custom(aws_account_id) == expected_count


@pytest.mark.parametrize('expected_db_count', [CUSTOM_SCHEMA_COUNT, 0])
@pytest.mark.parametrize('aws_account_id', [utils.TEST_ACCOUNT_ID, None])
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
    instance.aws_account_id = utils.TEST_ACCOUNT_ID

    assert utils.database_execute_query(instance.db_connector, utils.SQL_COUNT_ROWS.format(
        table_name=instance.db_table_name)) == CUSTOM_SCHEMA_COUNT

    with patch('aws_bucket.AWSCustomBucket.db_count_custom', return_value=CUSTOM_SCHEMA_COUNT):
        instance.db_maintenance(aws_account_id=aws_account_id)

    assert utils.database_execute_query(instance.db_connector, utils.SQL_COUNT_ROWS.format(
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

    instance.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID)

    mock_print.assert_called_once()


class FakeS3Bucket:
    """Objects of a bucket, listed as S3 does: in UTF-8 binary order of their key and after 'StartAfter'."""

    def __init__(self):
        self.objects = {}

    def put(self, key: str, day: date):
        self.objects[key] = datetime(day.year, day.month, day.day, 12, tzinfo=timezone.utc)

    def list_objects_v2(self, Prefix='', StartAfter='', MaxKeys=1000, ContinuationToken=None, **kwargs):
        keys = sorted(key for key in self.objects if key.startswith(Prefix) and key > (ContinuationToken or StartAfter))
        response = {'IsTruncated': len(keys) > MaxKeys}
        if keys:
            response['Contents'] = [{'Key': key, 'LastModified': self.objects[key]} for key in keys[:MaxKeys]]
        if response['IsTruncated']:
            response['NextContinuationToken'] = keys[MaxKeys - 1]
        return response


A, R, FLOW_LOG_ID = utils.TEST_ACCOUNT_ID, utils.TEST_REGION, 'fl-1234'
# Bucket type, its parameters and the key of a log file of a day, as the AWS service or Firehose writes them
BUCKET_LAYOUTS = [
    pytest.param(AWSCloudTrailBucket, {}, lambda d, n: f'AWSLogs/{A}/CloudTrail/{R}/{d:%Y/%m/%d}/'
                 f'{A}_CloudTrail_{R}_{d:%Y%m%d}T0000Z_{n}.json.gz', id='cloudtrail'),
    pytest.param(AWSConfigBucket, {}, lambda d, n: f'AWSLogs/{A}/Config/{R}/{d.year}/{d.month}/{d.day}/ConfigHistory/'
                 f'{A}_Config_{R}_ConfigHistory_AWS::EC2::Instance_{d:%Y%m%d}T0000Z_{d:%Y%m%d}T0000Z_{n}.json.gz',
                 id='config'),
    pytest.param(AWSVPCFlowBucket, {}, lambda d, n: f'AWSLogs/{A}/vpcflowlogs/{R}/{d:%Y/%m/%d}/'
                 f'{A}_vpcflowlogs_{R}_{FLOW_LOG_ID}_{d:%Y%m%d}T0000Z_{n}.log.gz', id='vpcflow'),
    pytest.param(AWSALBBucket, {}, lambda d, n: f'AWSLogs/{A}/elasticloadbalancing/{R}/{d:%Y/%m/%d}/'
                 f'{A}_elasticloadbalancing_{R}_app.lb_{d:%Y%m%d}T0000Z_10.0.0.1_{n}.log.gz', id='alb'),
    pytest.param(AWSGuardDutyBucket, {'native': True},
                 lambda d, n: f'AWSLogs/{A}/GuardDuty/{R}/{d:%Y/%m/%d}/{n}.jsonl.gz', id='guardduty'),
    pytest.param(AWSGuardDutyBucket, {'native': False, 'prefix': 'firehose/'},
                 lambda d, n: f'firehose/{d:%Y/%m/%d}/00/firehose-1-{d:%Y-%m-%d}-00-00-00-{n}', id='guardduty-kinesis'),
    # The module does not set the table of the custom type, which is then 'custom'
    pytest.param(aws_bucket.AWSCustomBucket, {'prefix': 'custom/', 'db_table_name': None},
                 lambda d, n: f'custom/{d:%Y/%m/%d}/00/firehose-1-{d:%Y-%m-%d}-00-00-00-{n}', id='custom'),
    pytest.param(AWSWAFBucket, {'prefix': 'waf/'},
                 lambda d, n: f'waf/{d:%Y/%m/%d}/00/firehose-1-{d:%Y-%m-%d}-00-00-00-{n}', id='waf'),
    pytest.param(CiscoUmbrella, {'prefix': 'dnslogs/'},
                 lambda d, n: f'dnslogs/{d:%Y-%m-%d}/{d:%Y-%m-%d}-00-00-{n}.csv.gz', id='cisco_umbrella'),
    pytest.param(AWSServerAccess, {'prefix': 'access/'},
                 lambda d, n: f'access/{d:%Y-%m-%d}-00-00-00-{n}', id='server_access'),
]


def get_layout_bucket(class_, parameters: dict, database, only_logs_after: date):
    """Return a bucket of the given type with an empty database and the fake S3 bucket as client."""
    parameters = dict(parameters)
    native = parameters.pop('native', None)
    with patch('wazuh_integration.WazuhIntegration.get_sts_client'), \
            patch('guardduty.AWSGuardDutyBucket.check_guardduty_type', return_value=native):
        bucket = utils.get_mocked_bucket(class_=class_, only_logs_after=f'{only_logs_after:%Y%m%d}', **parameters)
    bucket.aws_account_id = A
    bucket.db_connector = database
    bucket.db_cursor = database.cursor()
    bucket.db_cursor.execute(bucket.sql_create_table.format(table_name=bucket.db_table_name))
    bucket.client = FakeS3Bucket()
    return bucket


def get_layout_iter_kwargs(bucket) -> dict:
    return {'flow_log_id': FLOW_LOG_ID} if isinstance(bucket, AWSVPCFlowBucket) else {}


def fetch_layout_bucket(bucket, regions=(R,)) -> list:
    """Run a fetch of the bucket as the module does and return the keys of the files it processed."""
    processed = []
    with patch('aws_tools.get_script_arguments') as mock_arguments, \
            patch.object(bucket, 'get_log_file', side_effect=lambda account, key: processed.append(key) or []), \
            patch.object(bucket, 'iter_events'), \
            patch('vpcflow.AWSVPCFlowBucket.get_flow_logs_ids', return_value=[FLOW_LOG_ID]):
        mock_arguments.return_value.type = bucket.db_table_name
        bucket.iter_regions_and_accounts([A], list(regions))
    return processed


# Days of the logs of the tests of planted keys. A key of September with a single digit month sorts after them
PLANTED_DAY_1, PLANTED_DAY_2 = date(2025, 10, 26), date(2025, 10, 27)
PLANTED_KINDS = ['future', 'invalid', 'single_digit', 'other_separator', 'no_date']


def get_planted_key(bucket, key_of_day, kind: str) -> str:
    """Return a key a writer of the bucket could choose to sort after the logs."""
    planted = key_of_day(date(9999, 12, 31), 'zzzz')
    if kind == 'future':
        return planted
    full_prefix = bucket.get_full_prefix(A, R)
    rest = planted[len(full_prefix):]
    match = bucket.key_date_regex.match(rest)
    separator = rest[4]
    if kind == 'invalid':
        return f'{full_prefix}2026{separator}99{separator}99{rest[match.end():]}'
    if kind == 'single_digit':
        return f'{full_prefix}{PLANTED_DAY_1.year}{separator}9{separator}9{rest[match.end():]}'
    if kind == 'other_separator':
        other = '/' if separator == '-' else '-'
        return f'{full_prefix}{PLANTED_DAY_1.strftime(f"%Y{other}%m{other}%d")}{rest[match.end():]}'
    # Without date, but with the name of a log so it can be marked as processed
    return f'{full_prefix}zzzz/{os.path.basename(planted)}'


@pytest.mark.parametrize('kind', PLANTED_KINDS)
@pytest.mark.parametrize('class_, parameters, key_of_day', BUCKET_LAYOUTS)
def test_aws_bucket_planted_key_does_not_become_the_marker(custom_database, class_, parameters, key_of_day, kind):
    """Test a key sorting after the logs written to the bucket, such as a far future day folder, is not processed, so
    it does not become the marker and the logs written after it are still processed."""
    if class_ is AWSConfigBucket and kind == 'single_digit':
        pytest.skip('AWS Config writes the month and day with a single digit')
    day_1, day_2 = PLANTED_DAY_1, PLANTED_DAY_2
    bucket = get_layout_bucket(class_, parameters, custom_database, day_1 - timedelta(days=10))

    bucket.client.put(key_of_day(day_1, 'a'), day_1)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_1, 'a')]

    planted = get_planted_key(bucket, key_of_day, kind)
    bucket.client.put(planted, day_1)
    bucket.client.put(key_of_day(day_1, 'b'), day_1)
    bucket.client.put(key_of_day(day_2, 'a'), day_2)
    with patch('aws_bucket.aws_tools.debug') as mock_debug:
        assert fetch_layout_bucket(bucket) == [key_of_day(day_1, 'b'), key_of_day(day_2, 'a')]
    # A key sorting before the logs, such as one with a dash in a bucket type of slashes, is not listed at all
    assert call_skipped(mock_debug, planted) or is_skipped_before(bucket, kind) or planted < key_of_day(day_1, 'a')

    bucket.client.put(key_of_day(day_2, 'b'), day_2)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_2, 'b')]


def is_skipped_before(bucket, kind: str) -> bool:
    """Whether a planted key is skipped before checking if it can be the marker: without a date of two digit month and
    day, by the prefix check of the bucket types that have it, and without a valid date, by the date filter of AWS
    Config with only_logs_after."""
    return (kind in ('no_date', 'single_digit', 'other_separator') and bucket.check_prefix) or \
        (kind != 'future' and isinstance(bucket, AWSConfigBucket))


def call_skipped(mock_debug, key: str) -> bool:
    return any(c.args == (f'+++ WARNING: Skipping file without a valid date after the prefix or dated after it was '
                          f'written: {key}', 1) for c in mock_debug.call_args_list)


@pytest.mark.parametrize('kind', PLANTED_KINDS)
@pytest.mark.parametrize('class_, parameters, key_of_day', BUCKET_LAYOUTS)
def test_aws_bucket_marker_skips_planted_key_processed_by_older_versions(custom_database, class_, parameters,
                                                                         key_of_day, kind):
    """Test the marker is the greatest key processed that is a valid one, so a key sorting after the logs that an
    older version processed does not keep the next fetches from processing the logs written after it, and that key is
    removed from the database."""
    if class_ is AWSConfigBucket and kind == 'single_digit':
        pytest.skip('AWS Config writes the month and day with a single digit')
    day_1, day_2 = PLANTED_DAY_1, PLANTED_DAY_2
    bucket = get_layout_bucket(class_, parameters, custom_database, day_1 - timedelta(days=10))
    planted = get_planted_key(bucket, key_of_day, kind)
    for key in (key_of_day(day_1, 'a'), planted):
        bucket.mark_complete(A, R, {'Key': key, 'LastModified': bucket.default_date},
                             **get_layout_iter_kwargs(bucket))
    assert utils.database_execute_query(custom_database, utils.SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == 2

    bucket.client.put(key_of_day(day_1, 'a'), day_1)
    bucket.client.put(key_of_day(day_2, 'a'), day_2)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_2, 'a')]
    # Only the keys sorting after the marker are removed, the others cannot be the marker and the retention deletes them
    remaining = {row[0] for row in custom_database.execute(f'SELECT log_key FROM {bucket.db_table_name}')}
    assert remaining == {key_of_day(day_1, 'a'), key_of_day(day_2, 'a')} | \
        ({planted} if planted < key_of_day(day_1, 'a') else set())


@pytest.mark.parametrize('class_, parameters, key_columns', [
    (AWSCloudTrailBucket, {}, 'bucket_path=? AND aws_account_id=? AND aws_region=? AND log_key=?'),
    (AWSVPCFlowBucket, {}, 'bucket_path=? AND aws_account_id=? AND aws_region=? AND flow_log_id=? AND log_key=?'),
    (aws_bucket.AWSCustomBucket, {'prefix': 'custom/', 'db_table_name': None},
     'bucket_path=? AND aws_account_id=? AND log_key=?'),
])
def test_aws_bucket_delete_processed_key_uses_the_primary_key(custom_database, class_, parameters, key_columns):
    """Test the deletion of a processed key searches it with every column of the primary key of its table."""
    bucket = get_layout_bucket(class_, parameters, custom_database, PLANTED_DAY_1)
    plan = custom_database.execute(
        f'EXPLAIN QUERY PLAN {bucket.sql_delete_processed_key.format(table_name=bucket.db_table_name)}', {
            'bucket_path': 'b', 'aws_account_id': A, 'aws_region': R, 'flow_log_id': FLOW_LOG_ID, 'log_key': 'k'
        }).fetchall()
    assert f'({key_columns})' in plan[0][-1]


def test_aws_bucket_get_last_key_processed_allows_the_clock_skew_of_the_manager(custom_database):
    """Test a key dated the next day, written by S3 after 10:00 UTC and processed when the clock of the manager was
    up to 15 minutes behind, is still the marker and is not removed."""
    bucket = get_layout_bucket(aws_bucket.AWSCustomBucket, {'prefix': 'custom/', 'db_table_name': None},
                               custom_database, PLANTED_DAY_1)
    key = 'custom/2025/10/28/00/file'
    custom_database.execute(bucket.sql_mark_complete.replace("DATETIME('now')", ':processed_date').format(
        table_name=bucket.db_table_name), {'bucket_path': bucket.bucket_path, 'aws_account_id': A, 'log_key': key,
                                           'processed_date': '2025-10-27 09:50:00', 'created_date': 20251028})

    assert bucket.get_last_key_processed(A, R, 'custom/%') == key
    assert bucket.get_written_date('2025-10-27 09:50:00') == datetime(2025, 10, 27, 10, 5)


def test_aws_bucket_get_last_key_processed_keeps_keys_of_other_prefixes(custom_database):
    """Test 'get_last_key_processed' only removes the keys of the full prefix that cannot be the marker, not the ones
    of other prefixes that the pattern of the query matches."""
    bucket = get_layout_bucket(aws_bucket.AWSCustomBucket, {'prefix': 'my_logs/'}, custom_database,
                               PLANTED_DAY_1 - timedelta(days=10))
    keys = ['my_logs/2025/10/26/a', 'myXlogs/zzzz/b', 'my_logs/zzzz/c']
    for key in keys:
        bucket.mark_complete(A, R, {'Key': key, 'LastModified': bucket.default_date})

    assert bucket.get_last_key_processed(A, R, 'my_logs/%') == 'my_logs/2025/10/26/a'
    remaining = {row[0] for row in custom_database.execute(f'SELECT log_key FROM {bucket.db_table_name}')}
    assert remaining == {'my_logs/2025/10/26/a', 'myXlogs/zzzz/b'}


@pytest.mark.parametrize('days_ahead', [0, 1])
@pytest.mark.parametrize('class_, parameters, key_of_day', BUCKET_LAYOUTS)
def test_aws_bucket_logs_sorting_before_a_valid_planted_key_are_processed(custom_database, class_, parameters,
                                                                         key_of_day, days_ahead):
    """Test a key dated the day it is written, or the next one in UTC+14, sorting after the logs of that day is
    processed, and the logs of the day written after it, which sort before it, are processed by the next fetch, as
    the marker goes back to the day before its date."""
    day_1, day_2 = PLANTED_DAY_1, PLANTED_DAY_2
    bucket = get_layout_bucket(class_, parameters, custom_database, day_1 - timedelta(days=10))
    bucket.client.put(key_of_day(day_1, 'a'), day_1)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_1, 'a')]

    # Written at 12:00 UTC, so the next day is still valid in UTC+14
    planted = key_of_day(day_2 + timedelta(days=days_ahead), 'zzzz')
    bucket.client.put(planted, day_2)
    bucket.client.put(key_of_day(day_2, 'a'), day_2)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_2, 'a'), planted]

    bucket.client.put(key_of_day(day_2, 'b'), day_2)
    assert fetch_layout_bucket(bucket) == [key_of_day(day_2, 'b')]


@pytest.mark.parametrize('class_, parameters, key_of_day', BUCKET_LAYOUTS)
def test_aws_bucket_db_maintenance_keeps_the_window_of_the_marker(custom_database, class_, parameters, key_of_day):
    """Test the database maintenance keeps every key of the window of the rewound marker, even beyond the retention,
    so the next fetch, which lists them again, does not process them twice, and deletes the keys before it."""
    if class_ is AWSConfigBucket:
        pytest.skip('AWS Config lists the whole year folder and its marker is not rewound')
    day_0, day_1, day_2 = PLANTED_DAY_1 - timedelta(days=1), PLANTED_DAY_1, PLANTED_DAY_2
    bucket = get_layout_bucket(class_, parameters, custom_database, day_0 - timedelta(days=10))
    bucket.retain_db_records = 2
    keys = [key_of_day(day, name) for day in (day_0, day_1, day_2) for name in 'abc']
    for key in keys:
        bucket.client.put(key, day_2)
    assert fetch_layout_bucket(bucket) == keys
    assert fetch_layout_bucket(bucket) == []

    remaining = {row[0] for row in custom_database.execute(f'SELECT log_key FROM {bucket.db_table_name}')}
    assert remaining == set(keys[3:])


@pytest.mark.parametrize('class_, parameters, key_of_day', BUCKET_LAYOUTS)
def test_aws_bucket_marker_is_the_day_before_the_last_key(custom_database, class_, parameters, key_of_day):
    """Test the marker of the next fetch is the day before the date of the last key processed, in the date format of
    each bucket type, or its year folder for AWS Config."""
    day_1, day_2 = PLANTED_DAY_1, PLANTED_DAY_2
    bucket = get_layout_bucket(class_, parameters, custom_database, day_1 - timedelta(days=10))
    bucket.client.put(key_of_day(day_2, 'a'), day_2)
    fetch_layout_bucket(bucket)

    with patch('aws_tools.get_script_arguments') as mock_arguments:
        mock_arguments.return_value.type = bucket.db_table_name
        start_after = bucket.build_s3_filter_args(A, R, **get_layout_iter_kwargs(bucket))['StartAfter']

    full_prefix = bucket.get_full_prefix(A, R)
    if class_ is AWSConfigBucket:
        assert start_after == f'{full_prefix}{day_2.year}/'
    else:
        assert start_after == f'{full_prefix}{day_1.strftime(bucket.date_format)}'


def test_aws_bucket_marker_is_a_key_of_the_region_fetched(custom_database):
    """Test the marker of a region is a key of that region for GuardDuty, whose database query does not filter by
    region, so the keys of another region, real or planted, do not keep its logs from being processed."""
    today = datetime.now(timezone.utc).date()
    day_1, day_2 = today - timedelta(days=2), today - timedelta(days=1)
    bucket = get_layout_bucket(AWSGuardDutyBucket, {'native': True}, custom_database, today - timedelta(days=10))

    def key_of_day(region, day, name):
        return f'AWSLogs/{A}/GuardDuty/{region}/{day:%Y/%m/%d}/{name}.jsonl.gz'

    for region in ('us-east-1', 'us-west-2'):
        bucket.client.put(key_of_day(region, day_1, 'a'), day_1)
    assert fetch_layout_bucket(bucket, ('us-east-1', 'us-west-2')) == \
        [key_of_day('us-east-1', day_1, 'a'), key_of_day('us-west-2', day_1, 'a')]

    bucket.client.put(key_of_day('us-east-1', day_2, 'a'), day_2)
    assert fetch_layout_bucket(bucket, ('us-east-1', 'us-west-2')) == [key_of_day('us-east-1', day_2, 'a')]


def test_aws_bucket_db_maintenance_keeps_the_keys_of_each_region(custom_database):
    """Test the database maintenance of GuardDuty keeps the last keys of each region, as the marker of a region is one
    of its keys and the table has no region column, so no region whose keys sort first loses all of them and processes
    its files again."""
    today = datetime.now(timezone.utc).date()
    bucket = get_layout_bucket(AWSGuardDutyBucket, {'native': True}, custom_database, today - timedelta(days=10))
    bucket.retain_db_records = 2
    regions = ('ap-south-1', 'us-east-1', 'us-west-2')

    def key_of_day(region, day, name):
        return f'AWSLogs/{A}/GuardDuty/{region}/{day:%Y/%m/%d}/{name}.jsonl.gz'

    keys = [key_of_day(region, today - timedelta(days=offset), 'a') for region in regions for offset in (3, 2, 1)]
    for key in keys:
        bucket.client.put(key, today - timedelta(days=1))
    assert fetch_layout_bucket(bucket, regions) == keys
    assert fetch_layout_bucket(bucket, regions) == []

    bucket.client.put(key_of_day('ap-south-1', today - timedelta(days=1), 'b'), today - timedelta(days=1))
    assert fetch_layout_bucket(bucket, regions) == [key_of_day('ap-south-1', today - timedelta(days=1), 'b')]


@pytest.mark.parametrize('class_', [AWSCloudTrailBucket, AWSALBBucket])
def test_aws_bucket_db_maintenance_window_skips_planted_key(custom_database, class_):
    """Test the window that the database maintenance keeps for the late arrival types starts at the day before the
    greatest valid key processed, not at the one of a planted key sorting after it."""
    key_of_day = next(p.values[2] for p in BUCKET_LAYOUTS if p.values[0] is class_)
    today = datetime.now(timezone.utc).date()
    bucket = get_layout_bucket(class_, {}, custom_database, today - timedelta(days=10))
    bucket.retain_db_records = 0
    days = [today - timedelta(days=offset) for offset in (3, 2, 1)]
    for key in [key_of_day(day, 'a') for day in days] + [key_of_day(date(9999, 12, 31), 'zzzz')]:
        bucket.mark_complete(A, R, {'Key': key})

    bucket.db_maintenance(aws_account_id=A, aws_region=R)

    remaining = {row[0] for row in custom_database.execute(f'SELECT log_key FROM {bucket.db_table_name}')}
    assert key_of_day(days[0], 'a') not in remaining
    assert {key_of_day(days[1], 'a'), key_of_day(days[2], 'a')} <= remaining


@pytest.mark.parametrize('key_suffix, expected_date', [
    ('2026/10/28/00/firehose-1', date(2026, 10, 28)),
    ('2026/1/6/ConfigHistory/file', None),
    ('2026/9/09/file', None),
    ('2026-10-28/2026-10-28-00-00-abcd.csv.gz', None),
    ('9999/12/31/file', date(9999, 12, 31)),
    ('2026/99/99/file', None),
    ('2026/02/30/file', None),
    ('2026/10/280/file', None),
    ('zzzz/2026/10/28/file', None),
    ('', None),
])
def test_aws_bucket_get_key_date(key_suffix, expected_date):
    """Test 'get_key_date' returns the date right after the full prefix of a key, if it is a valid one."""
    bucket = utils.get_mocked_aws_bucket()
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value='archive/2024/01/01/'):
        assert bucket.get_key_date(f'archive/2024/01/01/{key_suffix}', A, R) == expected_date
        assert bucket.get_key_date(f'other/{key_suffix}', A, R) is None


@pytest.mark.parametrize('class_, parameters', [
    (CiscoUmbrella, {'prefix': 'dnslogs/'}),
    (AWSServerAccess, {'prefix': 'access/'}),
])
@pytest.mark.parametrize('key_suffix, expected_date', [
    ('2026-10-28/2026-10-28-00-00-abcd.csv.gz', date(2026, 10, 28)),
    ('2026-10-28-12-00-00-F123456789012345', date(2026, 10, 28)),
    ('2026/10/28/x.csv.gz', None),
    ('2026-10-9/x.csv.gz', None),
])
def test_aws_bucket_get_key_date_with_dashes(custom_database, class_, parameters, key_suffix, expected_date):
    """Test 'get_key_date' of Cisco Umbrella and Server Access takes the date with the dashes they write, as a key
    with slashes would sort after all of their logs."""
    bucket = get_layout_bucket(class_, parameters, custom_database, PLANTED_DAY_1)
    assert bucket.get_key_date(f'{parameters["prefix"]}{key_suffix}', A, R) == expected_date


@pytest.mark.parametrize('key_suffix, expected_date', [
    ('2026/1/6/ConfigHistory/file', date(2026, 1, 6)),
    ('2026/10/28/ConfigHistory/file', date(2026, 10, 28)),
    ('2026/1/60/ConfigHistory/file', None),
])
def test_aws_config_bucket_get_key_date(key_suffix, expected_date):
    """Test 'get_key_date' of AWS Config takes the month and day with one or two digits, as AWS Config writes them."""
    bucket = utils.get_mocked_bucket(class_=AWSConfigBucket)
    assert bucket.get_key_date(f'{bucket.get_full_prefix(A, R)}{key_suffix}', A, R) == expected_date


@pytest.mark.parametrize('key_date, written_date, expected', [
    ('2026/10/27', datetime(2026, 10, 28, 9, tzinfo=timezone.utc), True),
    ('2026/10/28', datetime(2026, 10, 28, 0, tzinfo=timezone.utc), True),
    ('2026/10/29', datetime(2026, 10, 28, 10, tzinfo=timezone.utc), True),
    ('2026/10/29', datetime(2026, 10, 28, 9, 59, 59, tzinfo=timezone.utc), False),
    ('2026/10/29', datetime(2026, 10, 28, 10), True),
    ('2026/10/30', datetime(2026, 10, 28, 23, 59, tzinfo=timezone.utc), False),
    ('9999/12/31', datetime(2026, 10, 28, tzinfo=timezone.utc), False),
])
def test_aws_bucket_is_valid_marker(key_date, written_date, expected):
    """Test 'is_valid_marker' accepts a key dated up to the date that it was written on in the time zone furthest
    ahead of UTC, UTC+14."""
    bucket = utils.get_mocked_aws_bucket()
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value='custom/'):
        assert bucket.is_valid_marker(f'custom/{key_date}/00/file', A, R, written_date) == expected
        assert not bucket.is_valid_marker('custom/zzzz/00/file', A, R, written_date)
