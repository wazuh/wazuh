import copy
import gzip
import os
import sqlite3
import sys
import zipfile
from datetime import datetime
from unittest.mock import MagicMock, patch

import botocore
import pytest
import zlib

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'buckets_s3'))
import aws_bucket

TEST_FULL_PREFIX = "base/account_id/service/region/"
TEST_CLOUDTRAIL_SCHEMA = "schema_cloudtrail_test.sql"
TEST_EMPTY_TABLE_SCHEMA = "schema_empty_table.sql"

CLOUDTRAIL_SCHEMA_COUNT = 8

SQL_COUNT_ROWS = """SELECT count(*) FROM {table_name};"""
SQL_GET_ROW = "SELECT bucket_path, aws_account_id, aws_region, log_key, created_date FROM {table_name};"
SQL_COUNT_TABLES = """SELECT count(*) FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"""
SQL_SELECT_TABLES = """SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"""

SAMPLE_EVENT_1 = {'key1': 'value1', 'key2': 'value2'}
SAMPLE_EVENT_2 = {'key1': 'value1', 'key2': None}

LIST_OBJECT_V2 = {'CommonPrefixes': [{'Prefix': f'AWSLogs/{utils.TEST_REGION}/'},
                                     {'Prefix': f'AWSLogs/prefix/{utils.TEST_REGION}/'}]}
LIST_OBJECT_V2_NO_PREFIXES = {'Name': 'string'}


@pytest.mark.parametrize('only_logs_after', [None, "20220101"])
@patch('wazuh_integration.WazuhIntegration.check_metadata_version')
@patch('wazuh_integration.sqlite3.connect')
@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH)
@patch('wazuh_integration.utils.get_wazuh_version')
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_AWSBucket__init__(mock_wazuh_integration, mock_version, mock_path, mock_client, mock_connect, mock_metadata,
                           only_logs_after):
    """Test if the instances of AWSBucket are created properly."""
    kwargs = utils.get_AWSBucket_parameters(db_table_name=utils.TEST_TABLE_NAME, bucket=utils.TEST_BUCKET,
                                            aws_profile=utils.TEST_AWS_PROFILE, access_key=utils.TEST_ACCESS_KEY,
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
    mock_wazuh_integration.assert_called_with(integration, db_name=aws_bucket.DEFAULT_DATABASE_NAME,
                                              db_table_name=kwargs["db_table_name"], service_name="s3",
                                              access_key=kwargs["access_key"], secret_key=kwargs["secret_key"],
                                              aws_profile=kwargs["aws_profile"], iam_role_arn=kwargs["iam_role_arn"],
                                              region=kwargs["region"], discard_field=kwargs["discard_field"],
                                              discard_regex=kwargs["discard_regex"],
                                              sts_endpoint=kwargs["sts_endpoint"],
                                              service_endpoint=kwargs["service_endpoint"],
                                              iam_role_duration=kwargs["iam_role_duration"])

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


@pytest.mark.parametrize('match_start, expected_result', [
    (len(TEST_FULL_PREFIX), True),
    (len(TEST_FULL_PREFIX) - 1, False),
    (0, False),
    (None, False),
])
def test_AWSBucket_same_prefix(match_start, expected_result):
    """Test `_same_prefixCheck` detects if the prefix of a file key is the same as the one expected."""
    bucket = utils.get_mocked_AWSBucket()
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=TEST_FULL_PREFIX):
        assert bucket._same_prefix(match_start=match_start, aws_account_id="", aws_region="") == expected_result


@pytest.mark.parametrize('log_file, bucket, account_id, region, expected_result', [
    (utils.TEST_LOG_FULL_PATH_1, utils.TEST_BUCKET, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    (utils.TEST_LOG_FULL_PATH_2, utils.TEST_BUCKET, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, True),
    ("", utils.TEST_BUCKET, utils.TEST_ACCOUNT_ID, utils.TEST_REGION, False),
    (utils.TEST_LOG_FULL_PATH_1, utils.TEST_BUCKET, utils.TEST_ACCOUNT_ID, "", False),
    (utils.TEST_LOG_FULL_PATH_1, utils.TEST_BUCKET, "", utils.TEST_REGION, False),
])
def test_AWSBucket_already_processed(custom_database, log_file, bucket, account_id, region, expected_result):
    """Test `_get_last_key_processed` find the required keys in the database as expected."""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)

    bucket = utils.get_mocked_AWSBucket(bucket=bucket, region=region)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = 'cloudtrail'

    assert bucket.already_processed(downloaded_file=log_file, aws_account_id=account_id,
                                    aws_region=region) == expected_result


def test_AWSBucket_mark_complete(custom_database):
    utils.database_execute_script(custom_database, TEST_EMPTY_TABLE_SCHEMA)

    bucket = utils.get_mocked_AWSBucket(bucket=utils.TEST_BUCKET)
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    assert utils.database_execute_query(bucket.db_connector,
                                        SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 0

    with patch('aws_bucket.AWSBucket.get_creation_date', return_value=utils.TEST_CREATION_DATE):
        bucket.mark_complete(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION,
                             log_file={'Key': utils.TEST_LOG_FULL_PATH_1})

    assert utils.database_execute_query(bucket.db_connector,
                                        SQL_COUNT_ROWS.format(table_name=bucket.db_table_name)) == 1

    row = utils.database_execute_query(bucket.db_connector, SQL_GET_ROW.format(table_name=bucket.db_table_name))
    assert row[0] == f"{utils.TEST_BUCKET}/"
    assert row[1] == utils.TEST_ACCOUNT_ID
    assert row[2] == utils.TEST_REGION
    assert row[3] == utils.TEST_LOG_FULL_PATH_1
    assert row[4] == utils.TEST_CREATION_DATE

def test_AWSBucket_create_table(custom_database):
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    assert utils.database_execute_query(bucket.db_connector, SQL_COUNT_TABLES) == 0
    bucket.create_table()
    assert utils.database_execute_query(bucket.db_connector, SQL_SELECT_TABLES) == utils.TEST_TABLE_NAME

def test_AWSBucket_create_table_ko(custom_database):
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = sqlite3.OperationalError
    bucket.db_cursor = mocked_cursor

    assert utils.database_execute_query(bucket.db_connector, SQL_COUNT_TABLES) == 0
    with pytest.raises(SystemExit) as e:
        bucket.create_table()
    assert e.value.code == utils.UNABLE_TO_CREATE_DB
    assert utils.database_execute_query(bucket.db_connector, SQL_COUNT_TABLES) == 0


@pytest.mark.parametrize('already_initialised', [True, False])
def test_AWSBucket_init_db(custom_database, already_initialised):
    """Test 'init_db' function checks if the database has already been initialised and creates it if not."""
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    if already_initialised:
        utils.database_execute_query(bucket.db_connector,
                                     bucket.sql_create_table.format(table_name=bucket.db_table_name))
        assert utils.database_execute_query(bucket.db_connector, bucket.sql_find_table, {'name': bucket.db_table_name})
    else:
        assert not utils.database_execute_query(bucket.db_connector, bucket.sql_find_table, {'name': bucket.db_table_name})
    bucket.init_db()
    assert utils.database_execute_query(bucket.db_connector, bucket.sql_find_table, {'name': bucket.db_table_name})


def test_AWSBucket_init_db_ko(custom_database):
    """Test init_db handles exceptions when accessing the database."""
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = sqlite3.OperationalError
    bucket.db_cursor = mocked_cursor

    with pytest.raises(SystemExit) as e:
        bucket.init_db()
    assert e.value.code == utils.METADATA_ERROR_CODE
    assert not utils.database_execute_query(bucket.db_connector, bucket.sql_find_table, {'name': bucket.db_table_name})


@pytest.mark.parametrize('region', [utils.TEST_REGION, "invalid_region"])
def test_AWSBucket_db_count_region(custom_database, region):
    """Test 'db_count_region' function counts the number of rows in DB for a region"""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME

    expected_count = CLOUDTRAIL_SCHEMA_COUNT if region == utils.TEST_REGION else 0
    assert bucket.db_count_region(utils.TEST_ACCOUNT_ID, region) == expected_count


@pytest.mark.parametrize('expected_db_count', [CLOUDTRAIL_SCHEMA_COUNT, 0])
def test_AWSBucket_db_maintenance(custom_database, expected_db_count):
    """Test 'db_maintenance' function deletes rows from a table until the count is equal to 'retain_db_records'."""
    utils.database_execute_script(custom_database, TEST_CLOUDTRAIL_SCHEMA)
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = custom_database
    bucket.db_cursor = bucket.db_connector.cursor()
    bucket.db_table_name = utils.TEST_TABLE_NAME
    bucket.retain_db_records = expected_db_count

    assert utils.database_execute_query(bucket.db_connector, SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == CLOUDTRAIL_SCHEMA_COUNT

    with patch('aws_bucket.AWSBucket.db_count_region', return_value=CLOUDTRAIL_SCHEMA_COUNT):
        bucket.db_maintenance(aws_account_id=utils.TEST_ACCOUNT_ID, aws_region=utils.TEST_REGION)

    assert utils.database_execute_query(bucket.db_connector, SQL_COUNT_ROWS.format(
        table_name=bucket.db_table_name)) == expected_db_count


def test_AWSBucket_marker_custom_date():
    """Test 'marker_custom_date' function returns a valid AWS bucket marker when using a custom date."""
    bucket = utils.get_mocked_AWSBucket()
    bucket.date_format = '%Y-%m-%d'

    test_date = datetime.now()
    full_prefix = f"{utils.TEST_ACCOUNT_ID}/{utils.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_custom_date(aws_region=utils.TEST_REGION, aws_account_id=utils.TEST_ACCOUNT_ID,
                                                date=test_date)
    assert marker == f"{full_prefix}{test_date.strftime(bucket.date_format)}"


def test_AWSBucket_marker_only_logs_after():
    """Test 'marker_only_logs_after' function returns a valid marker using only_log_after."""
    test_only_logs_after = "20220101"
    bucket = utils.get_mocked_AWSBucket(only_logs_after=test_only_logs_after)
    bucket.date_format = '%Y-%m-%d'

    full_prefix = f"{utils.TEST_ACCOUNT_ID}/{utils.TEST_REGION}/"
    with patch('aws_bucket.AWSBucket.get_full_prefix', return_value=full_prefix):
        marker = bucket.marker_only_logs_after(aws_region=utils.TEST_REGION, aws_account_id=utils.TEST_ACCOUNT_ID)
    assert marker == f"{full_prefix}{test_only_logs_after[0:4]}-{test_only_logs_after[4:6]}-{test_only_logs_after[6:8]}"


@pytest.mark.parametrize('event', [SAMPLE_EVENT_1, SAMPLE_EVENT_2, None])
def test_AWSBucket_get_alert_msg(event):
    """Test 'get_alert_msg' function returns messages with valid format."""
    bucket = utils.get_mocked_AWSBucket(account_alias=utils.TEST_ACCOUNT_ALIAS)
    test_log_key = "test_log_key"
    expected_error_message = "error message"
    expected_msg = copy.deepcopy(aws_bucket.AWS_BUCKET_MSG_TEMPLATE)
    expected_msg['aws']['log_info'].update({
        'aws_account_alias': bucket.account_alias,
        'log_file': test_log_key,
        's3bucket': bucket.bucket
    })
    if event:
        # Remove 'None' values from the event before updating the message
        expected_msg['aws'].update({k: v for k, v in event.items() if v is not None})
    else:
        expected_msg['error_msg'] = expected_error_message
    assert bucket.get_alert_msg(utils.TEST_ACCOUNT_ID, test_log_key, event,
                                error_msg=expected_error_message) == expected_msg


@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
def test_AWSBucket_find_account_ids(mock_prefix):
    """Test 'find_account_ids' function returns a valid account_ids list."""
    object_list = {'CommonPrefixes': [{'Prefix': f'AWSLogs/{utils.TEST_ACCOUNT_ID}/'},
                                      {'Prefix': f'AWSLogs/prefix/{utils.TEST_ACCOUNT_ID}/'}]}
    bucket = utils.get_mocked_AWSBucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_account_ids()
    bucket.client.list_objects_v2.assert_called_with(Bucket=utils.TEST_BUCKET, Prefix=utils.TEST_PREFIX, Delimiter='/')
    assert accounts == [utils.TEST_ACCOUNT_ID for _ in object_list['CommonPrefixes']]


@pytest.mark.skip("Not implemented yet")
@pytest.mark.parametrize('error_code, exit_code', [
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, 16),
    (aws_bucket.THROTTLING_EXCEPTION_ERROR_CODE, 1)
])
@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
def test_AWSBucket_find_account_ids_ko_client_error(mock_prefix, error_code, exit_code):
    """Test 'find_account_ids' function handles client errors as expected."""
    bucket = utils.get_mocked_AWSBucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = botocore.exceptions.ClientError(error_code, "name")

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == exit_code

@patch('aws_bucket.AWSBucket.get_base_prefix', return_value=utils.TEST_PREFIX)
def test_AWSBucket_find_account_ids_ko_key_error(mock_prefix):
    """Test 'find_account_ids' function handles KeyError as expected."""
    bucket = utils.get_mocked_AWSBucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.side_effect = KeyError

    with pytest.raises(SystemExit) as e:
        bucket.find_account_ids()
    assert e.value.code == utils.INVALID_PREFIX_ERROR_CODE


@pytest.mark.parametrize('object_list', [LIST_OBJECT_V2, LIST_OBJECT_V2_NO_PREFIXES])
@patch('aws_bucket.AWSBucket.get_service_prefix', return_value=utils.TEST_PREFIX)
def test_AWSBucket_find_regions(mock_prefix, object_list):
    """Test 'find_regions' function returns a valid region list."""

    bucket = utils.get_mocked_AWSBucket(bucket=utils.TEST_BUCKET, prefix=utils.TEST_PREFIX)
    bucket.client = MagicMock()
    bucket.client.list_objects_v2.return_value = object_list

    accounts = bucket.find_regions(utils.TEST_ACCOUNT_ID)
    bucket.client.list_objects_v2.assert_called_with(Bucket=utils.TEST_BUCKET, Prefix=utils.TEST_PREFIX, Delimiter='/')
    if object_list.get('CommonPrefixes'):
        assert accounts == [utils.TEST_REGION for _ in object_list['CommonPrefixes']]
    else:
        assert len(accounts) == 0

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_find_regions_ko():
    pass


def test_AWSBucket_build_s3_filter_args():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_reformat_msg():
    pass


@patch('gzip.open')
def test_AWSBucket__decompress_gzip(mock_open):
    gzip_mock = MagicMock()
    mock_open.return_value = gzip_mock

    bucket = utils.get_mocked_AWSBucket()
    assert bucket._decompress_gzip(MagicMock()) == gzip_mock
    gzip_mock.read.assert_called_once()
    gzip_mock.seek.assert_called_with(0)


@pytest.mark.parametrize('error', [gzip.BadGzipFile, zlib.error, TypeError])
def test_AWSBucket__decompress_gzip(error):
    bucket = utils.get_mocked_AWSBucket()

    with patch('gzip.open', side_effect=error), \
            pytest.raises(SystemExit) as e:
        bucket._decompress_gzip(MagicMock())
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE


@patch('io.TextIOWrapper')
@patch('zipfile.ZipFile')
def test_AWSBucket__decompress_zip(mock_zip, mock_io):
    zip_mock = MagicMock()
    mock_zip.return_value = zip_mock
    zip_mock.namelist.return_value = ['name']
    zip_mock.open.return_value = "file contents"

    bucket = utils.get_mocked_AWSBucket()
    bucket._decompress_zip(MagicMock())

    zip_mock.namelist.assert_called_once()
    zip_mock.open.assert_called_with('name')
    mock_io.assert_called_with("file contents")


@patch('zipfile.ZipFile', side_effect=zipfile.BadZipFile)
def test_AWSBucket__decompress_zip_ko(mock_zip):
    bucket = utils.get_mocked_AWSBucket()

    with pytest.raises(SystemExit) as e:
        bucket._decompress_zip(MagicMock())
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE



@pytest.mark.parametrize('log_key, mocked_function', [
    ('test.gz', 'aws_bucket.AWSBucket._decompress_gzip'),
    ('test.zip', 'aws_bucket.AWSBucket._decompress_zip'),
    ('test.tar', 'io.TextIOWrapper')
])
@patch('io.BytesIO')
def test_AWSBucket_decompress_file(mock_io, log_key, mocked_function):
    bucket = utils.get_mocked_AWSBucket()
    bucket.client = MagicMock()

    with patch(mocked_function) as mock_decompress:
        bucket.decompress_file(log_key)

    bucket.client.get_object.assert_called_once()
    mock_decompress.assert_called_once()


@patch('io.BytesIO')
def test_AWSBucket_decompress_file_ko(mock_io):
    bucket = utils.get_mocked_AWSBucket()
    bucket.client = MagicMock()

    with pytest.raises(SystemExit) as e:
        bucket.decompress_file('test.snappy')
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE


@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_get_log_file():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_exception_handler():
    pass


@patch('aws_bucket.AWSBucket.iter_regions_and_accounts')
@patch('aws_bucket.AWSBucket.init_db')
def test_AWSBucket_iter_bucket(mock_init, mock_iter):
    """Test 'iter_bucket' function calls the appropriated functions."""
    bucket = utils.get_mocked_AWSBucket()
    bucket.db_connector = MagicMock()
    bucket.db_cursor = MagicMock()
    bucket.iter_bucket(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)

    mock_init.assert_called_once()
    mock_iter.assert_called_with(utils.TEST_ACCOUNT_ID, utils.TEST_REGION)
    bucket.db_connector.commit.assert_called_once()
    bucket.db_cursor.execute.assert_called_with(bucket.sql_db_optimize)
    bucket.db_connector.close.assert_called_once()


@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_iter_regions_and_accounts():
    pass


@patch('aws_bucket.AWSBucket.send_msg')
@patch('aws_bucket.AWSBucket.reformat_msg', return_value="formatted event")
def test_AWSBucket_send_event(mock_reformat, mock_send):
    bucket = utils.get_mocked_AWSBucket()
    bucket.send_event("event")
    mock_reformat.assert_called_with("event")
    mock_send.assert_called_with("formatted event")


@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_iter_events():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_check_recursive():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_check_regex():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_event_should_be_skipped():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_iter_files_in_bucket():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSBucket_check_bucket():
    pass



@pytest.mark.parametrize('prefix', [utils.TEST_PREFIX, None])
@pytest.mark.parametrize('suffix', [utils.TEST_SUFFIX, None])
@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_AWSLogsBucket__init__(mock_bucket, mock_integration, prefix, suffix):
    """Test if the instances of AWSLogsBucket are created properly."""
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, prefix=prefix, suffix=suffix)
    mock_bucket.assert_called_once()
    assert instance.bucket_path == f"{utils.TEST_BUCKET}/{prefix}{suffix}"


@pytest.mark.parametrize('organization_id', [utils.TEST_ORGANIZATION_ID, None])
@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_AWSLogsBucket_get_base_prefix(mock_bucket, mock_integration, organization_id):
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, aws_organization_id=organization_id,
                                       prefix=f'{utils.TEST_PREFIX}/', suffix=f'{utils.TEST_SUFFIX}/')
    expected_base_prefix = f'{utils.TEST_PREFIX}/AWSLogs/{utils.TEST_SUFFIX}{"/" + organization_id if organization_id else ""}/'
    assert instance.get_base_prefix() == expected_base_prefix


@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('aws_bucket.AWSLogsBucket.get_base_prefix', return_value='base_prefix/')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_AWSLogsBucket_get_service_prefix(mock_bucket, mock_base_prefix, mock_integration):
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    instance.service = utils.TEST_SERVICE_NAME
    expected_base_prefix = f'base_prefix/{utils.TEST_ACCOUNT_ID}/{utils.TEST_SERVICE_NAME}/'
    assert instance.get_service_prefix(utils.TEST_ACCOUNT_ID) == expected_base_prefix


@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('aws_bucket.AWSLogsBucket.get_service_prefix', return_value='service_prefix/')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_AWSLogsBucket_get_full_prefix(mock_bucket, mock_service_prefix, mock_integration):
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket, region=utils.TEST_REGION)
    expected_base_prefix = f'service_prefix/{utils.TEST_REGION}/'
    assert instance.get_full_prefix(utils.TEST_ACCOUNT_ID, utils.TEST_REGION) == expected_base_prefix


@patch('wazuh_integration.WazuhIntegration.__init__')
@patch('aws_bucket.AWSBucket.__init__', side_effect=aws_bucket.AWSBucket.__init__)
def test_AWSLogsBucket_get_creation_date(mock_bucket, mock_integration):
    log_file = {'Key': utils.TEST_LOG_FULL_PATH_1}
    expected_result = 20190401
    instance = utils.get_mocked_bucket(class_=aws_bucket.AWSLogsBucket)
    assert instance.get_creation_date(log_file) == expected_result



@pytest.mark.skip("Not implemented yet")
def test_AWSLogsBucket_get_extra_data_from_filename():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSLogsBucket_get_alert_msg():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSLogsBucket_load_information_from_file():
    pass





@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket__init__():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_load_information_from_file():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_json_event_generator():
    pass

# @pytest.mark.skip("Not implemented yet")
# @pytest.mark.parametrize('log_file, expected_date', [
#     ({'Key': 'AWSLogs/166157441623/elasticloadbalancing/us-west-1/2021/12/21/166157441623_elasticloadbalancing'},
#      20211221),
#     ({'Key': 'AWSLogs/875611522134/elasticloadbalancing/us-west-1/2020/01/03/166157441623_elasticloadbalancing'},
#      20200103),
#     ({'Key': '981837383623/iplogs/2020-09-20/2020-09-20-00-00-moyl.csv.gz'}, 20200920),
#     ({'Key': '836629801214/iplogs/2021-01-18/2021-01-18-00-00-zxsb.csv.gz'}, 20210118),
#     ({'Key': '2020/09/30/13/firehose_guardduty-1-2020-09-30-13-17-05-532e184c-1hfba.zip'}, 20200930),
#     ({'Key': '2020/10/15/03/firehose_guardduty-1-2020-10-15-03-22-01-ea728dd1-763a4.zip'}, 20201015),
#     ({'Key': '2021/03/18/aws-waf-logs-delivery-stream-1-2021-03-18-10-32-48-77baca34f-efad-4f14-45bd7871'},
#      20210318),
#     ({'Key': '2021/09/06/aws-waf-logs-delivery-stream-1-2021-09-06-21-02-18-8ba031bbd-babf-4c6a-83ba282c'},
#      20210906),
#     ({'Key': '2021-11-12-09-11-26-B9F9F891E8D0EB13'}, 20211112),
#     ({'Key': '20-03-02-21-02-43-A8269E82CA8BDD21', 'LastModified': datetime.strptime('2021/01/23', '%Y/%m/%d')},
#      20210123)
# ])
# def test_AWSCustomBucket_get_creation_date(log_file: dict, expected_date: int, aws_custom_bucket: AWSCustomBucket):
#     """
#     Test AWSCustomBucket's get_creation_date method.
#     Parameters
#     ----------
#     log_file : dict
#         The log file introduced
#     expected_date : int
#         The date that the method should return.
#     aws_custom_bucket : aws_bucket.AWSCustomBucket
#         Instance of the AWSCustomBucket class.
#     """
#     assert aws_custom_bucket.get_creation_date(log_file) == expected_date


@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_get_full_prefix():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_reformat_msg():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_list_paths_from_dict():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_iter_regions_and_accounts():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_already_processed():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_mark_complete():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_db_count_custom():
    pass

@pytest.mark.skip("Not implemented yet")
def test_AWSCustomBucket_db_maintenance():
    pass
