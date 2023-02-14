import pytest
import os
import sys
import copy
from unittest.mock import patch, MagicMock
import re
from datetime import datetime, timedelta

import botocore

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket
import config

TEST_CONFIG_SCHEMA = "schema_config_test.sql"
TEST_TABLE_NAME = 'config'

TEST_DATE = '2023/1/1'
DAYS_DELTA = 10

SQL_FIND_LAST_LOG_PROCESSED = """SELECT created_date FROM {table_name} ORDER BY created_date DESC LIMIT 1;"""
SQL_FIND_LAST_KEY_PROCESSED = """SELECT log_key FROM {table_name} ORDER BY log_key DESC LIMIT 1;"""

utils.LIST_OBJECT_V2_NO_PREFIXES['Contents'][0]['Key'] = utils.TEST_LOG_FULL_PATH_CONFIG_1


@patch('aws_bucket.AWSLogsBucket.__init__')
def test_aws_config_bucket__init__(mock_logs_bucket):
    """Test if the instances of AWSConfigBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    mock_logs_bucket.assert_called_once()
    assert instance.service == "Config"
    assert instance.field_to_load == "configurationItems"
    assert instance._leading_zero_regex == re.compile(r'/(0)(?P<num>\d)')
    assert instance._extract_date_regex == re.compile(r'\d{4}/\d{1,2}/\d{1,2}')


def test_aws_config_bucket_get_days_since_today():
    """Test 'get_days_since_today' returns the expected number of days since today."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    test_date = "20220630"

    date = datetime.strptime(test_date, "%Y%m%d")
    delta = datetime.utcnow() - date + timedelta(days=1)

    assert instance.get_days_since_today(test_date) == delta.days


@patch('config.AWSConfigBucket.get_date_last_log')
@patch('config.AWSConfigBucket.get_days_since_today', return_value=DAYS_DELTA)
def test_aws_config_bucket_get_date_list(mock_days_since_today, mock_date_last_log):
    """Test 'get_date_list' returns the expected list of dates for a given delta of days."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    date_list_time = [datetime.utcnow() - timedelta(days=x) for x in range(0, DAYS_DELTA)]

    assert instance.get_date_list(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == [datetime.strftime(date, "%Y/%-m/%-d")
                                                                                for date in reversed(date_list_time)]


@pytest.mark.parametrize('only_logs_after', [None, utils.TEST_ONLY_LOGS_AFTER])
@pytest.mark.parametrize('reparse', [True, False])
def test_aws_config_bucket_get_date_last_log(custom_database, reparse: bool, only_logs_after: str or None):
    """Test 'get_date_last_log' method returns the expected last log date, checking the DB
    or getting it from the instance's attributes (only_logs_after) if the DB is empty.

    Parameters
    ----------
    reparse: bool
        Whether to parse already parsed logs or not.
    only_logs_after: str or None
        Date after which obtain logs.
    """
    utils.database_execute_script(custom_database, TEST_CONFIG_SCHEMA)

    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, bucket=utils.TEST_BUCKET, reparse=reparse,
                                       only_logs_after=only_logs_after)

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME

    if instance.reparse:
        last_date_processed = instance.only_logs_after.strftime('%Y%m%d') if instance.only_logs_after else \
            instance.default_date.strftime('%Y%m%d')
    else:
        query_date_last_log = utils.database_execute_query(instance.db_connector, SQL_FIND_LAST_LOG_PROCESSED.format(
            table_name=instance.db_table_name))

        db_date = str(query_date_last_log)

        if instance.only_logs_after:
            last_date_processed = db_date if datetime.strptime(db_date, '%Y%m%d') > instance.only_logs_after else \
                datetime.strftime(instance.only_logs_after, '%Y%m%d')
        else:
            last_date_processed = db_date

    assert instance.get_date_last_log(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == last_date_processed


@pytest.mark.parametrize('account_id', [None, [utils.TEST_ACCOUNT_ID]])
@pytest.mark.parametrize('regions', [[utils.TEST_REGION], None])
@patch('aws_bucket.AWSBucket.find_regions', side_effect=[[utils.TEST_REGION], []])
@patch('aws_bucket.AWSBucket.find_account_ids', return_value=[utils.TEST_ACCOUNT_ID])
@patch('config.AWSConfigBucket.get_date_list', return_value=['2022/12/24'])
@patch('config.AWSConfigBucket.iter_files_in_bucket')
@patch('aws_bucket.AWSBucket.db_maintenance')
def test_aws_config_bucket_iter_regions_and_accounts(mock_db_maintenance, mock_iter_files, mock_date_list,
                                                     mock_find_accounts, mock_find_regions,
                                                     regions: list[str] or None, account_id: list[str] or None):
    """Test 'iter_regions_and_accounts' method makes the necessary calls in order to process the bucket's files.

    Parameters
    ----------
    regions: list[str] or None
        List of region names.
    account_id: list[str] or None
        List of account ids.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    instance.iter_regions_and_accounts(account_id, regions)

    if not account_id:
        mock_find_accounts.assert_called_once()
        account_id = instance.find_account_ids()
    for aws_account_id in account_id:
        if not regions:
            mock_find_regions.assert_called_with(aws_account_id)
            regions = instance.find_regions(aws_account_id)
            if not regions:
                continue
        for region in regions:
            date_list = instance.get_date_list(aws_account_id, region)
            for date in date_list:
                mock_iter_files.assert_called_with(aws_account_id, region, date)
            mock_db_maintenance.assert_called_with(aws_account_id=aws_account_id, aws_region=region)


@pytest.mark.parametrize('date, expected_date', [
    ('2021/1/19', '20210119'),
    ('2021/1/1', '20210101'),
    ('2021/01/01', '20210101'),
    ('2000/2/12', '20000212'),
    ('2022/02/1', '20220201')
])
def test_aws_config_bucket__format_created_date(date: str, expected_date: str):
    """Test AWSConfigBucket's _format_created_date method.

    Parameters
    ----------
    date : str
        The date introduced.
    expected_date : str
        The date that the method should return.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    assert instance._format_created_date(date) == expected_date


@pytest.mark.parametrize('marker, result_marker', [
    ('AWSLogs/123456789012/Config/us-east-1/2020/01/06', 'AWSLogs/123456789012/Config/us-east-1/2020/1/6'),
    ('AWSLogs/123456789/Config/us-east-1/2019/04/15/', 'AWSLogs/123456789/Config/us-east-1/2019/4/15/'),
    ('AWSLogs/123456789/Config/us-east-1/2019/12/06/', 'AWSLogs/123456789/Config/us-east-1/2019/12/6/')
])
@patch('aws_bucket.AWSBucket.marker_only_logs_after')
def test_aws_config_bucket_marker_only_logs_after(mock_marker_only_logs_after, marker: str, result_marker: str):
    """Test 'marker_only_logs_after' method returns the expected marker.

    Parameters
    ----------
    marker: str
        The marker introduced.
    result_marker: str
        The marker the method should return without padding zeros in the date.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, only_logs_after=utils.TEST_ONLY_LOGS_AFTER)
    mock_marker_only_logs_after.return_value = result_marker

    assert instance.marker_only_logs_after(utils.TEST_ACCOUNT_ID,
                                           utils.TEST_REGION) == instance._remove_padding_zeros_from_marker(marker)


@patch('aws_bucket.AWSBucket.marker_only_logs_after')
def test_aws_config_bucket_marker_only_logs_after_ko(mock_marker_only_logs_after):
    """Test 'marker_only_logs_after' method handles the AtrributeError exception and exits
    with the expected exit code."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    mock_marker_only_logs_after.return_value = 'AWSLogs/123456789/Config/us-east-1/2019/12/06/'

    with patch('re.sub') as mock_re_sub:
        with pytest.raises(SystemExit) as e:
            mock_re_sub.side_effect = AttributeError
            instance.marker_only_logs_after(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

        assert e.value.code == utils.THROTTLING_ERROR_CODE


@patch('aws_bucket.AWSBucket.marker_custom_date')
def test_aws_config_bucket_marker_custom_date(mock_marker_custom_date):
    """Test 'marker_custom_date' method returns the expected marker when specifying a custom date."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)
    custom_date = datetime(2022, 9, 8)

    mock_marker_custom_date.return_value = f'AWSLogs/{utils.TEST_ACCOUNT_ID}/Config/{utils.TEST_REGION}/{custom_date.strftime(instance.date_format)}'

    assert instance.marker_custom_date(utils.TEST_ACCOUNT_ID, utils.TEST_REGION,
                                       custom_date) == instance._remove_padding_zeros_from_marker(
        mock_marker_custom_date(instance, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, custom_date))


@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('only_logs_after', ['20230201', None])
@pytest.mark.parametrize('iterating', [True, False])
@pytest.mark.parametrize('region', [utils.TEST_REGION, 'region_for_empty_db'])
def test_aws_config_bucket_build_s3_filter_args(custom_database,
                                                region: str, iterating: bool, only_logs_after: str or None,
                                                reparse: bool):
    """Test 'build_s3_filter_args' method returns the expected filter arguments for the list_objects_v2 call.

    Parameters
    ----------
    region: str
        Region name.
    iterating: bool
        Whether the call to the method is being made inside a loop due to a truncated response.
    only_logs_after: str or None
        Date after which obtain logs.
    reparse: bool
        Whether to parse already parsed logs or not.
    """
    utils.database_execute_script(custom_database, TEST_CONFIG_SCHEMA)

    aws_account_id = utils.TEST_ACCOUNT_ID
    aws_region = region
    date = TEST_DATE

    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, reparse=reparse, only_logs_after=only_logs_after)

    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.db_table_name = TEST_TABLE_NAME

    if instance.reparse:
        filter_marker = instance.marker_custom_date(aws_region, aws_account_id,
                                                    datetime.strptime(date, instance.date_format))
    else:
        filter_marker = utils.database_execute_query(instance.db_connector, SQL_FIND_LAST_KEY_PROCESSED.format(
            table_name=instance.db_table_name))

    if aws_region == 'region_for_empty_db':
        filter_marker = instance.get_full_prefix(aws_account_id, aws_region) + date

    config_prefix = instance.get_full_prefix(aws_account_id, aws_region) + date + '/'

    expected_filter_args = {
        'Bucket': instance.bucket,
        'MaxKeys': 1000,
        'Prefix': config_prefix
    }

    if not iterating:
        extracted_date = instance._extract_date_regex.search(filter_marker).group(0)
        filter_marker_date = datetime.strptime(extracted_date, instance.date_format)

        if not instance.only_logs_after or instance.only_logs_after < filter_marker_date:
            expected_filter_args['StartAfter'] = filter_marker
        else:
            expected_filter_args['StartAfter'] = instance.marker_only_logs_after(aws_region, aws_account_id)

    assert expected_filter_args == instance.build_s3_filter_args(aws_account_id, aws_region, date, iterating)


def test_aws_config_bucket_build_s3_filter_args_ko():
    """Test 'build_s3_filter_args' method handles exceptions raised and exits with the expected exit code."""
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, reparse=True)

    aws_account_id = utils.TEST_ACCOUNT_ID
    aws_region = utils.TEST_REGION

    with patch('config.AWSConfigBucket.marker_custom_date', return_value='NotExpectedValue'), \
            patch('aws_bucket.AWSLogsBucket.get_full_prefix'):
        with pytest.raises(SystemExit) as e:
            instance.build_s3_filter_args(aws_account_id, aws_region, TEST_DATE)
        assert e.value.code == utils.THROTTLING_ERROR_CODE


@pytest.mark.parametrize('object_list',
                         [utils.LIST_OBJECT_V2, utils.LIST_OBJECT_V2_NO_PREFIXES, utils.LIST_OBJECT_V2_TRUNCATED])
@pytest.mark.parametrize('reparse', [True, False])
@pytest.mark.parametrize('delete_file', [True, False])
@patch('aws_bucket.aws_tools.debug')
@patch('config.AWSConfigBucket.build_s3_filter_args')
def test_aws_config_bucket_iter_files_in_bucket(mock_build_filter, mock_debug,
                                                delete_file: bool, reparse: bool, object_list: dict):
    """Test 'iter_files_in_bucket' method makes the necessary method calls in order to process the logs inside the bucket.

    Parameters
    ----------
    delete_file: bool
        Whether to remove the file from the bucket or not.
    reparse: bool
        Whether to parse already parsed logs or not.
    object_list: dict
        Objects to be returned by list_objects_v2.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket, bucket=utils.TEST_BUCKET, delete_file=delete_file,
                                       reparse=reparse)
    mock_build_filter.return_value = {
        'Bucket': instance.bucket,
        'MaxKeys': 1000,
        'Prefix': utils.TEST_PREFIX
    }

    instance.client.list_objects_v2.return_value = object_list

    aws_account_id = utils.TEST_ACCOUNT_ID
    aws_region = utils.TEST_REGION

    with patch('aws_bucket.AWSBucket.already_processed', return_value=True) as mock_already_processed, \
            patch('aws_bucket.AWSBucket.get_log_file') as mock_get_log_file, \
            patch('aws_bucket.AWSBucket.iter_events') as mock_iter_events, \
            patch('aws_bucket.AWSBucket.mark_complete') as mock_mark_complete:
        if 'IsTruncated' in object_list and object_list['IsTruncated']:
            instance.client.list_objects_v2.side_effect = [object_list, utils.LIST_OBJECT_V2_NO_PREFIXES]

        instance.iter_files_in_bucket(aws_account_id, aws_region, TEST_DATE)

        if 'Contents' not in object_list:
            mock_debug.assert_any_call("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
        else:
            for bucket_file in object_list['Contents']:
                if not bucket_file['Key']:
                    continue

                if bucket_file['Key'][-1] == '/':
                    continue

                mock_already_processed.assert_called_with(bucket_file['Key'], aws_account_id, aws_region)
                if instance.reparse:
                    mock_debug.assert_any_call("++ File previously processed, but reparse flag set: {file}".format(
                        file=bucket_file['Key']), 1)
                else:
                    mock_debug.assert_any_call(
                        "++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                    continue

                mock_debug.assert_any_call("++ Found new log: {0}".format(bucket_file['Key']), 2)
                mock_get_log_file.assert_called_with(aws_account_id, bucket_file['Key'])
                mock_iter_events.assert_called()

                if instance.delete_file:
                    mock_debug.assert_any_call("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)

                mock_mark_complete.assert_called_with(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, bucket_file)


def test_aws_config_bucket_iter_files_in_bucket_ko():
    """Test 'iter_files_in_bucket' method handles exceptions raised when trying to fetch objects from AWS
    or by an unexpected cause and exits with the expected exit code.
    """
    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    instance.client = MagicMock()

    with patch('config.AWSConfigBucket.build_s3_filter_args') as mock_build_filter:
        with pytest.raises(SystemExit) as e:
            instance.client.list_objects_v2.side_effect = botocore.exceptions.ClientError(
                {'Error': {'Code': aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE}}, "name")
            instance.iter_files_in_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, TEST_DATE)
        assert e.value.code == utils.THROTTLING_ERROR_CODE

        with pytest.raises(SystemExit) as e:
            mock_build_filter.side_effect = Exception
            instance.iter_files_in_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION, TEST_DATE)
        assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3


@pytest.mark.parametrize('security_groups', ['securityGroupId', [{'groupId': 'id', 'groupName': 'name'}],
                                             {'groupId': 'id', 'groupName': 'name'}])
@pytest.mark.parametrize('availability_zones',
                         ['zone', [{'subnetId': 'id', 'zoneName': 'name'}], {'subnetId': 'id', 'zoneName': 'name'}])
@pytest.mark.parametrize('state', ['stateName', {}])
@pytest.mark.parametrize('created_time', [1672763065, '2020-06-01T01:03:03.106Z'])
@pytest.mark.parametrize('iam_profile', ['iamInstanceProfileName', {}])
@patch('aws_bucket.AWSBucket.reformat_msg')
def test_aws_config_bucket_reformat_msg(mock_reformat,
                                        iam_profile: str or dict, created_time: int or str, state: str or dict,
                                        availability_zones: str or dict, security_groups: str or dict):
    """Test 'reformat_msg' method applies the expected format to a given event.

    Parameters
    ----------
    iam_profile: str or dict
        IAM instance profile.
    created_time: int or str
        Event creation time.
    state: str or dict
        State values for the state key.
    availability_zones: str or dict
        Availability zones values for the availabilityZones key.
    security_groups: str or dict
        Security groups values for the securityGroups key.
    """
    event = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    event['aws'].update(
        {
            'configuration': {
                'securityGroups': security_groups,
                'availabilityZones': availability_zones,
                'state': state,
                'createdTime': created_time,
                'iamInstanceProfile': iam_profile,
                'unnecesary_fields': {
                    'Content': {
                        'example_key': 'example_value'
                    }
                }
            }
        }
    )

    instance = utils.get_mocked_bucket(class_=config.AWSConfigBucket)

    formatted_event = instance.reformat_msg(event)

    assert isinstance(formatted_event['aws']['configuration']['securityGroups'], dict)
    assert isinstance(formatted_event['aws']['configuration']['availabilityZones'], dict)
    assert isinstance(formatted_event['aws']['configuration']['state'], dict)
    assert isinstance(formatted_event['aws']['configuration']['createdTime'], float)
    assert isinstance(formatted_event['aws']['configuration']['iamInstanceProfile'], dict)
    assert isinstance(formatted_event['aws']['configuration']['unnecesary_fields']['Content'], list)
