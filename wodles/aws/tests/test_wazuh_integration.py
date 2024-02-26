# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import gzip
import os
import socket
import sqlite3
import sys
import zipfile
import zlib
from datetime import datetime, timezone
from json import dumps
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration
import aws_tools

TEST_METADATA_SCHEMA = "schema_metadata_test.sql"
TEST_METADATA_DEPRECATED_TABLES_SCHEMA = "schema_metadata_deprecated_tables_test.sql"
METADATA_TABLE_NAME = 'metadata'
DB_TABLENAME = "test_table"


@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH)
@patch('wazuh_integration.utils.get_wazuh_version')
def test_wazuh_integration_initializes_properly(mock_version, mock_path, mock_client):
    """Test if the instances of WazuhIntegration are created properly."""

    args = utils.get_wazuh_integration_parameters()
    integration = wazuh_integration.WazuhIntegration(**args)
    mock_path.assert_called_once()
    mock_version.assert_called_once()
    assert integration.wazuh_path == utils.TEST_WAZUH_PATH
    assert integration.wazuh_queue == os.path.join(integration.wazuh_path, utils.QUEUE_PATH)
    assert integration.wazuh_wodle == os.path.join(integration.wazuh_path, utils.WODLE_PATH)
    mock_client.assert_called_with(profile=args["profile"], iam_role_arn=args["iam_role_arn"],
                                   service_name=args["service_name"], region=args["region"],
                                   sts_endpoint=args["sts_endpoint"], service_endpoint=args["service_endpoint"],
                                   iam_role_duration=args["iam_role_duration"], external_id=args["external_id"])

    assert integration.default_date == datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0,
                                                                 tzinfo=timezone.utc)


@pytest.mark.parametrize('file_exists, options, retry_attempts, retry_mode',
                         [(True, [aws_tools.RETRY_ATTEMPTS_KEY, aws_tools.RETRY_MODE_BOTO_KEY], 5, 'standard'),
                          (True, ['other_option'], None, None),
                          (False, None, None, None)]
                         )
def test_default_config(file_exists, options, retry_attempts, retry_mode):
    """Test if `default_config` function returns the Wazuh default Retry configuration if there is no user-defined
    configuration.

    Parameters
    ----------
    file_exists : bool
        The value to be returned by the mocked config reader call.
    options: list[str]
        List of options that can be found in an AWS config file.
    retry_attempts: int or None
        Number of attempts to set in the retries' configuration. None for when the retry_attempt option is not declared
        in the AWS config file.
    retry_mode: str or None
        Mode to set in the retries' configuration. None for when the retry_mode option is not declared in
        the AWS config file.
    """
    profile = utils.TEST_AWS_PROFILE
    with patch('wazuh_integration.path.exists', return_value=file_exists):
        if file_exists:
            with patch('aws_tools.get_aws_config_params') as mock_config:
                mock_config.options(profile).return_value = options
                profile_config = {option: mock_config.get(profile, option) for option in mock_config.options(profile)}

                config = wazuh_integration.WazuhIntegration.default_config(profile=utils.TEST_AWS_PROFILE)

            if aws_tools.RETRY_ATTEMPTS_KEY in profile_config or aws_tools.RETRY_MODE_CONFIG_KEY in profile_config:
                retries = {
                    aws_tools.RETRY_ATTEMPTS_KEY: retry_attempts,
                    aws_tools.RETRY_MODE_BOTO_KEY: retry_mode
                }
            else:
                retries = aws_tools.WAZUH_DEFAULT_RETRY_CONFIGURATION

            assert config['config'].retries == retries
        else:
            config = wazuh_integration.WazuhIntegration.default_config(profile=utils.TEST_AWS_PROFILE)
            assert 'config' in config
            assert config['config'].retries == aws_tools.WAZUH_DEFAULT_RETRY_CONFIGURATION


@pytest.mark.parametrize('profile', [
    None,
    utils.TEST_AWS_PROFILE,
])
@pytest.mark.parametrize('region', list(wazuh_integration.DEFAULT_GOV_REGIONS) + ['us-east-1', None])
@pytest.mark.parametrize('service_name', list(wazuh_integration.SERVICES_REQUIRING_REGION) + ['other'])
def test_wazuh_integration_get_client_authentication(profile, region, service_name):
    """Test `get_client` function uses the different authentication parameters properly.

    Parameters
    ----------
    profile : str
        AWS profile name.
    region : str
        Region name.
    service_name : str
        Name of the service.
    """
    kwargs = utils.get_wazuh_integration_parameters(
        profile=profile, region=region, service_name=service_name, iam_role_arn=None
    )
    expected_conn_args = {}

    if profile:
        expected_conn_args['profile_name'] = profile
    expected_conn_args['region_name'] = None

    if region and service_name in wazuh_integration.SERVICES_REQUIRING_REGION:
        expected_conn_args['region_name'] = region
    else:
        expected_conn_args['region_name'] = region if region in wazuh_integration.DEFAULT_GOV_REGIONS else None

    with patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('wazuh_integration.boto3.Session') as mock_boto:
        wazuh_integration.WazuhIntegration(**kwargs)
        mock_boto.assert_called_with(**expected_conn_args)


@pytest.mark.parametrize('external_id', [utils.TEST_EXTERNAL_ID, None])
@pytest.mark.parametrize('iam_role_arn', [utils.TEST_IAM_ROLE_ARN, None])
@pytest.mark.parametrize('service_name', ["cloudTrail", "cloudwatchlogs"])
def test_wazuh_integration_get_client(iam_role_arn, service_name, external_id):
    """Test `get_client` function creates a valid client object both when an IAM Role is provided and when it's not.

    Parameters
    ----------
    iam_role_arn : str
        IAM Role.
    service_name : str
        Name of the service.
    external_id : str
        External ID primarily used for Security Lake.
    """
    kwargs = utils.get_wazuh_integration_parameters(profile=None,
                                                    sts_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                    service_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                    service_name=service_name, iam_role_arn=iam_role_arn,
                                                    iam_role_duration=utils.TEST_IAM_ROLE_DURATION,
                                                    external_id=external_id)
    service_name = "logs" if service_name == "cloudwatchlogs" else service_name
    conn_kwargs = {'region_name': None}
    sts_kwargs = {'aws_access_key_id': None, 'aws_secret_access_key': None, 'aws_session_token': utils.TEST_TOKEN,
                  'region_name': None}
    assume_role_kwargs = {'RoleArn': iam_role_arn, 'RoleSessionName': 'WazuhLogParsing',
                          'DurationSeconds': utils.TEST_IAM_ROLE_DURATION}
    if external_id:
        assume_role_kwargs['ExternalId'] = external_id

    sts_role_assumption = {
        'Credentials': {'AccessKeyId': None, 'SecretAccessKey': None, 'SessionToken': utils.TEST_TOKEN}}

    mock_boto_session = MagicMock()
    mock_sts_session = MagicMock()
    mock_sts_client = MagicMock()
    mock_boto_session.client.return_value = mock_sts_client
    mock_sts_client.assume_role.return_value = sts_role_assumption

    with patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('wazuh_integration.boto3.Session', side_effect=[mock_boto_session, mock_sts_session]) as mock_session:
        instance = wazuh_integration.WazuhIntegration(**kwargs)

        if iam_role_arn:
            mock_session.assert_has_calls([call(**conn_kwargs), call(**sts_kwargs)])
            mock_boto_session.client.assert_called_with(service_name='sts', endpoint_url=utils.TEST_SERVICE_ENDPOINT,
                                                        **instance.connection_config)
            mock_sts_client.assume_role.assert_called_with(**assume_role_kwargs)
            mock_sts_session.client.assert_called_with(service_name=service_name,
                                                       endpoint_url=utils.TEST_SERVICE_ENDPOINT,
                                                       **instance.connection_config)
        else:
            mock_session.assert_called_with(**conn_kwargs)
            mock_boto_session.client.assert_called_with(service_name=service_name,
                                                        endpoint_url=utils.TEST_SERVICE_ENDPOINT,
                                                        **instance.connection_config)


def test_wazuh_integration_get_client_handles_exceptions_on_botocore_error():
    """Test `get_client` function handles botocore.exceptions as expected."""
    mock_boto_session = MagicMock()
    mock_boto_session.client.side_effect = wazuh_integration.botocore.exceptions.ClientError({'Error': {'Code': 1}},
                                                                                             'operation')

    with patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('wazuh_integration.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('wazuh_integration.boto3.Session', return_value=mock_boto_session):
        with pytest.raises(SystemExit) as e:
            wazuh_integration.WazuhIntegration(**utils.get_wazuh_integration_parameters())
        assert e.value.code == utils.INVALID_CREDENTIALS_ERROR_CODE


@pytest.mark.parametrize('profile', [
    None,
    utils.TEST_AWS_PROFILE,
])
def test_wazuh_integration_get_sts_client(profile):
    """Test `get_sts_client` function uses the expected configuration for the session and the client while returning a
    valid sts client object.

    Parameters
    ----------
    profile : str
        AWS profile name.
    """
    instance = utils.get_mocked_wazuh_integration(profile=profile)
    expected_conn_args = {}

    if profile:
        expected_conn_args['profile_name'] = profile

    mock_session = MagicMock()
    with patch('wazuh_integration.boto3.Session', return_value=mock_session) as mock_boto:
        sts_client = instance.get_sts_client(profile=profile)
        mock_boto.assert_called_with(**expected_conn_args)
        mock_session.client.assert_called_with(service_name='sts', **instance.connection_config)
        assert sts_client == mock_session.client()


def test_wazuh_integration_get_sts_client_handles_exceptions_when_invalid_creds_provided():
    """Test `get_sts_client` function handles invalid credentials exception as expected."""
    mock_boto_session = MagicMock()
    mock_boto_session.client.side_effect = wazuh_integration.botocore.exceptions.ClientError({'Error': {'Code': 1}},
                                                                                             'operation')

    instance = utils.get_mocked_wazuh_integration(profile=None)

    with patch('wazuh_integration.boto3.Session', return_value=mock_boto_session):
        with pytest.raises(SystemExit) as e:
            instance.get_sts_client(profile=None)
        assert e.value.code == utils.INVALID_CREDENTIALS_ERROR_CODE


@pytest.mark.parametrize("dump_json", [True, False])
def test_wazuh_integration_send_msg(dump_json):
    """Test `send_msg` function build the message using the expected format and sends it to the appropriate socket.

    Parameters
    ----------
    dump_json : bool
        Determine if the message should be dumped first.
    """
    instance = utils.get_mocked_wazuh_integration()
    msg = dumps(utils.TEST_MESSAGE) if dump_json else utils.TEST_MESSAGE
    with patch('wazuh_integration.socket.socket') as mock_socket:
        m = MagicMock()
        mock_socket.return_value = m
        instance.send_msg(utils.TEST_MESSAGE, dump_json=dump_json)
        mock_socket.assert_called_once()
        m.send.assert_called_with(f"{wazuh_integration.MESSAGE_HEADER}{msg}".encode())
        m.close.assert_called_once()


@pytest.mark.parametrize("error_code, expected_exit_code", [
    (111, utils.UNABLE_TO_CONNECT_SOCKET_ERROR_CODE),
    (1, utils.SENDING_MESSAGE_SOCKET_ERROR_CODE),
    (90, None)
])
def test_wazuh_integration_send_msg_socket_error(error_code, expected_exit_code):
    """Test `send_msg` function handles the different expected socket exceptions.

    Parameters
    ----------
    error_code : int
        Error code number for the socket error to be raised.
    expected_exit_code : int
        Error code number for the expected exit exception.
    """
    instance = utils.get_mocked_wazuh_integration()
    error = socket.error()
    error.errno = error_code

    with patch('wazuh_integration.socket.socket') as mock_socket:
        mock_socket.side_effect = error
        if expected_exit_code:
            with pytest.raises(SystemExit) as e:
                instance.send_msg(utils.TEST_MESSAGE)
            assert e.value.code == expected_exit_code
        else:
            instance.send_msg(utils.TEST_MESSAGE)


@patch('io.BytesIO')
def test_wazuh_integration_decompress_file(mock_io):
    """Test 'decompress_file' method calls the expected function for a determined file type."""
    integration = utils.get_mocked_wazuh_integration()
    integration.client = MagicMock()
    # Instance that inherits from WazuhIntegration sets the attribute bucket in its constructor
    integration.bucket = utils.TEST_BUCKET

    with patch('gzip.open', return_value=MagicMock()) as mock_gzip_open:
        gzip_mock = mock_gzip_open.return_value
        integration.decompress_file(integration.bucket, 'test.gz')

    integration.client.get_object.assert_called_once()
    mock_gzip_open.assert_called_once()
    gzip_mock.read.assert_called_once()
    gzip_mock.seek.assert_called_with(0)

    with patch('zipfile.ZipFile', return_value=MagicMock()) as mock_zip, \
            patch('io.TextIOWrapper') as mock_io_text:
        zip_mock = mock_zip.return_value
        zip_mock.namelist.return_value = ['name']
        zip_mock.open.return_value = "file contents"
        integration.decompress_file(integration.bucket, 'test.zip')
    zip_mock.namelist.assert_called_once()
    zip_mock.open.assert_called_with('name')
    mock_io_text.assert_called_with("file contents")

    with patch('io.TextIOWrapper') as mock_io_text:
        integration.decompress_file(integration.bucket, 'test.tar')
        mock_io_text.assert_called_once()


@patch('io.BytesIO')
def test_aws_wazuh_integration_decompress_file_handles_exceptions_when_decompress_fails(mock_io):
    """Test 'decompress_file' method handles exceptions raised when trying to decompress a file and
    exits with the expected exit code.
    """
    integration = utils.get_mocked_wazuh_integration()
    integration.client = MagicMock()

    # Instance that inherits from WazuhIntegration sets the attribute bucket in its constructor
    integration.bucket = utils.TEST_BUCKET

    with patch('gzip.open', side_effect=[gzip.BadGzipFile, zlib.error, TypeError]), \
            pytest.raises(SystemExit) as e:
        integration.decompress_file(integration.bucket, 'test.gz')
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE

    with patch('zipfile.ZipFile', side_effect=zipfile.BadZipFile), \
            pytest.raises(SystemExit) as e:
        integration.decompress_file(integration.bucket, 'test.zip')
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE

    with pytest.raises(SystemExit) as e:
        integration.decompress_file(integration.bucket, 'test.snappy')
    assert e.value.code == utils.DECOMPRESS_FILE_ERROR_CODE


def test_wazuh_integration_send_msg_handles_exceptions():
    """Test `send_msg` function handles the other expected exceptions."""
    instance = utils.get_mocked_wazuh_integration()

    with patch('wazuh_integration.socket.socket') as mock_socket:
        mock_socket.side_effect = TypeError
        with pytest.raises(SystemExit) as e:
            instance.send_msg(utils.TEST_MESSAGE)
        assert e.value.code == utils.SENDING_MESSAGE_SOCKET_ERROR_CODE


@patch('wazuh_integration.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH)
@patch('wazuh_integration.utils.get_wazuh_version')
@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('wazuh_integration.WazuhAWSDatabase.check_metadata_version')
@patch('wazuh_integration.sqlite3.connect')
def test_wazuh_aws_database_initializes_properly(mock_connect, mock_metadata, mock_client, mock_version, mock_path):
    """Test if the instances of WazuhAWSDatabase are created properly."""
    mock_connect.return_value = MagicMock()
    args = utils.get_wazuh_aws_database_parameters()
    wazuh_aws_db = wazuh_integration.WazuhAWSDatabase(**args)

    assert wazuh_aws_db.db_path == os.path.join(wazuh_aws_db.wazuh_wodle, f"{utils.TEST_DATABASE}.db")
    mock_connect.assert_called_once()
    wazuh_aws_db.db_connector.cursor.assert_called_once()
    mock_metadata.assert_called_once()


def test_wazuh_aws_database_create_table():
    """Test `create_table` function creates the table using the expected SQL."""
    instance = utils.get_mocked_wazuh_aws_database()
    instance.db_cursor = MagicMock()
    test_sql = "test"
    instance.create_table(test_sql)
    instance.db_cursor.execute.assert_called_with(test_sql)


def test_wazuh_aws_database_create_table_handles_exceptions_when_table_not_created():
    """Test `create_table` function handles exceptions raised
    and exits with the expected code when the table cannot be created.
    """
    instance = utils.get_mocked_wazuh_aws_database()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.side_effect = Exception

    with pytest.raises(SystemExit) as e:
        instance.create_table("")
    assert e.value.code == utils.UNABLE_TO_CREATE_DB


@pytest.mark.parametrize("table_list", [
    ["table_1", "table_2", DB_TABLENAME],
    ["table_1", "table_2"],
    [DB_TABLENAME],
    []
])
@patch('wazuh_integration.WazuhAWSDatabase.create_table')
def test_wazuh_aws_database_db_initialization(mock_create_table, table_list):
    """Test `init_db` function checks if the required table exists and creates it if not.

    Parameters
    ----------
    table_list : list of str
        Table list to be returned by the mocked database query.
    """
    instance = utils.get_mocked_wazuh_aws_database()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.return_value = [(x,) for x in table_list]
    instance.db_table_name = DB_TABLENAME
    test_sql = "test"
    instance.init_db(test_sql)

    if DB_TABLENAME in table_list:
        mock_create_table.assert_not_called()
    else:
        mock_create_table.assert_called_with(test_sql)


def test_wazuh_aws_database_db_initialization_handles_exceptions():
    """Test `init_db` function handles exception as expected."""
    instance = utils.get_mocked_wazuh_aws_database()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.side_effect = sqlite3.OperationalError

    with pytest.raises(SystemExit) as e:
        instance.init_db("")
    assert e.value.code == utils.METADATA_ERROR_CODE


def test_wazuh_aws_database_close_db():
    """Test `close_db` function closes the database objects properly."""
    instance = utils.get_mocked_wazuh_aws_database()
    instance.db_connector = MagicMock()
    instance.db_cursor = MagicMock()

    instance.close_db()

    instance.db_connector.commit.assert_called_once()
    instance.db_cursor.execute.assert_called_with(instance.sql_db_optimize)
    instance.db_connector.close.assert_called_once()


def test_wazuh_aws_database_check_metadata_version_existing_table(custom_database):
    """Test if `check_metadata_version` function updates the metadata value when the table already exists."""
    # Populate the database
    utils.database_execute_script(custom_database, TEST_METADATA_SCHEMA)

    instance = utils.get_mocked_wazuh_aws_database(db_name=utils.TEST_DATABASE)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    old_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert old_metadata_value != utils.WAZUH_VERSION

    instance.check_metadata_version()
    new_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert new_metadata_value == utils.WAZUH_VERSION


def test_wazuh_aws_database_check_metadata_version_no_table(custom_database):
    """Test if `check_metadata_version` function updates the metadata value when the table does not exist."""
    instance = utils.get_mocked_wazuh_aws_database(db_name=utils.TEST_DATABASE)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.check_metadata_version()
    new_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert new_metadata_value == utils.WAZUH_VERSION


@pytest.mark.parametrize('table_exists', [True, False, sqlite3.Error])
def test_wazuh_aws_database_check_metadata_version_handles_exceptions(custom_database, table_exists):
    """Test if `check_metadata_version` function handles exceptions properly.

    Parameters
    ----------
    table_exists : bool or sqlite3.Error
        The value to be returned by the mocked database call.
    """
    mocked_table_exists = MagicMock()
    if isinstance(table_exists, bool):
        mocked_table_exists.fetchone.return_value = table_exists
    else:
        mocked_table_exists.fetchone.side_effect = table_exists
    mocked_cursor = MagicMock()
    mocked_cursor.execute.side_effect = [mocked_table_exists, sqlite3.OperationalError]

    instance = utils.get_mocked_wazuh_aws_database(db_name=utils.TEST_DATABASE)
    instance.db_connector = custom_database
    instance.db_cursor = mocked_cursor

    with pytest.raises(SystemExit) as e:
        instance.check_metadata_version()
    assert e.value.code == utils.METADATA_ERROR_CODE


def test_wazuh_aws_database_delete_deprecated_tables(custom_database):
    """Test `delete_deprecated_tables` function remove unwanted tables while keeping the rest intact."""
    # Populate the database
    utils.database_execute_script(custom_database, TEST_METADATA_DEPRECATED_TABLES_SCHEMA)

    instance = utils.get_mocked_wazuh_aws_database(db_name=utils.TEST_DATABASE)
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    for table in wazuh_integration.DEPRECATED_TABLES:
        assert instance.db_cursor.execute(instance.sql_find_table, {'name': table}).fetchone()[0]
    assert instance.db_cursor.execute(instance.sql_find_table, {'name': METADATA_TABLE_NAME}).fetchone()[0]

    instance.delete_deprecated_tables()

    # The deprecated tables were deleted
    for table in wazuh_integration.DEPRECATED_TABLES:
        assert not instance.db_cursor.execute(instance.sql_find_table, {'name': table}).fetchone()
    # The metadata table is still present
    assert instance.db_cursor.execute(instance.sql_find_table, {'name': METADATA_TABLE_NAME}).fetchone()[0]
