import os
import socket
import sqlite3
import sys
from datetime import datetime, timezone
from json import dumps
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import aws_s3

# Error codes
INVALID_CREDENTIALS_ERROR_CODE = 3
METADATA_ERROR_CODE = 5
UNABLE_TO_CREATE_DB = 6
UNABLE_TO_CONNECT_SOCKET_ERROR_CODE = 11
SENDING_MESSAGE_SOCKET_ERROR_CODE = 13

TEST_METADATA_SCHEMA = "schema_metadata_test.sql"
TEST_METADATA_DEPRECATED_TABLES_SCHEMA = "schema_metadata_deprecated_tables_test.sql"
METADATA_TABLE_NAME = 'metadata'
DB_TABLENAME = "test_table"


@patch('aws_s3.WazuhIntegration.check_metadata_version')
@patch('aws_s3.sqlite3.connect')
@patch('aws_s3.WazuhIntegration.get_client')
@patch('aws_s3.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH)
@patch('aws_s3.utils.get_wazuh_version')
def test_WazuhIntegration__init__(mock_version, mock_path, mock_client, mock_connect, mock_metadata):
    """Test if the instances of WazuhIntegration are created properly."""
    mock_connect.return_value = MagicMock()
    args = utils.get_WazuhIntegration_parameters(bucket="test")
    integration = aws_s3.WazuhIntegration(**args)
    mock_path.assert_called_once()
    mock_version.assert_called_once()
    assert integration.wazuh_path == utils.TEST_WAZUH_PATH
    assert integration.wazuh_queue == os.path.join(integration.wazuh_path, utils.QUEUE_PATH)
    assert integration.wazuh_wodle == os.path.join(integration.wazuh_path, utils.WODLE_PATH)
    mock_client.assert_called_with(access_key=args["access_key"], secret_key=args["secret_key"],
                                   profile=args["aws_profile"], iam_role_arn=args["iam_role_arn"],
                                   service_name=args["service_name"], region=args["region"],
                                   sts_endpoint=args["sts_endpoint"], service_endpoint=args["service_endpoint"],
                                   iam_role_duration=args["iam_role_duration"])
    assert integration.db_path == os.path.join(integration.wazuh_wodle, f"{utils.TEST_DATABASE}.db")
    mock_connect.assert_called_once()
    integration.db_connector.cursor.assert_called_once()
    mock_metadata.assert_called_once()
    assert integration.default_date == datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0,
                                                                 tzinfo=timezone.utc)

def test_WazuhIntegration_check_metadata_version_existing_table(custom_database):
    """Test if `check_metadata_version` function updates the metadata value when the table already exists."""
    # Populate the database
    utils.database_execute_script(custom_database, TEST_METADATA_SCHEMA)

    instance = utils.get_mocked_WazuhIntegration()
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    old_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert old_metadata_value != utils.WAZUH_VERSION

    instance.check_metadata_version()
    new_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert new_metadata_value == utils.WAZUH_VERSION


def test_WazuhIntegration_check_metadata_version_no_table(custom_database):
    """Test if `check_metadata_version` function updates the metadata value when the table does not exist."""
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()
    instance.check_metadata_version()
    new_metadata_value = utils.database_execute_query(custom_database, instance.sql_get_metadata_version)
    assert new_metadata_value == utils.WAZUH_VERSION


@pytest.mark.parametrize('table_exists', [True, False, sqlite3.Error])
def test_WazuhIntegration_check_metadata_version_ko(custom_database, table_exists):
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
    mocked_cursor.execute.side_effect=[mocked_table_exists, sqlite3.OperationalError]

    instance = utils.get_mocked_WazuhIntegration()
    instance.db_connector = custom_database
    instance.db_cursor = mocked_cursor

    with pytest.raises(SystemExit) as e:
        instance.check_metadata_version()
    assert e.value.code == METADATA_ERROR_CODE


def test_WazuhIntegration_delete_deprecated_tables(custom_database):
    """Test `delete_deprecated_tables` function remove unwanted tables while keeping the rest intact."""
    # Populate the database
    utils.database_execute_script(custom_database, TEST_METADATA_DEPRECATED_TABLES_SCHEMA)

    instance = utils.get_mocked_WazuhIntegration()
    instance.db_connector = custom_database
    instance.db_cursor = instance.db_connector.cursor()

    for table in aws_s3.DEPRECATED_TABLES:
        assert instance.db_cursor.execute(instance.sql_find_table, {'name': table}).fetchone()[0]
    assert instance.db_cursor.execute(instance.sql_find_table, {'name': METADATA_TABLE_NAME}).fetchone()[0]

    instance.delete_deprecated_tables()

    # The deprecated tables were deleted
    for table in aws_s3.DEPRECATED_TABLES:
        assert not instance.db_cursor.execute(instance.sql_find_table, {'name': table}).fetchone()
    # The metadata table is still present
    assert instance.db_cursor.execute(instance.sql_find_table, {'name': METADATA_TABLE_NAME}).fetchone()[0]


@patch('aws_s3.botocore')
@pytest.mark.parametrize('file_exists', [True, False])
def test_default_config(mock_botocore, file_exists):
    """Test if `default_config` function returns the Wazuh default Retry configuration if there is no user-defined
    configuration.

    Parameters
    ----------
    file_exists : bool
        The value to be returned by the mocked config reader call.
    """
    with patch('aws_s3.path.exists', return_value=file_exists):
        config = aws_s3.WazuhIntegration.default_config()
    if not file_exists:
        mock_botocore.config.Config.assert_called_with(retries=aws_s3.WAZUH_DEFAULT_RETRY_CONFIGURATION)
        assert 'config' in config
        assert config['config'] == mock_botocore.config.Config(retries=aws_s3.WAZUH_DEFAULT_RETRY_CONFIGURATION)
    else:
        assert config == dict()


@pytest.mark.parametrize('access_key, secret_key, profile', [
    (utils.TEST_ACCESS_KEY, utils.TEST_SECRET_KEY, None),
    (utils.TEST_ACCESS_KEY, None, None),
    (None, utils.TEST_SECRET_KEY, None),
    (None, None, utils.TEST_AWS_PROFILE),
    (None, None, utils.TEST_AWS_PROFILE),
])
@pytest.mark.parametrize('region', list(aws_s3.DEFAULT_GOV_REGIONS) + ['us-east-1', None])
@pytest.mark.parametrize('service_name', list(aws_s3.SERVICES_REQUIRING_REGION) + ['other'])
def test_WazuhIntegration_get_client_authentication(access_key, secret_key, profile, region, service_name):
    """Test `get_client` function uses the different authentication parameters properly.

    Parameters
    ----------
    access_key : str
        Access key value.
    secret_key : str
        Secret key value.
    profile : str
        AWS profile name.
    region : str
        Region name.
    service_name : str
        Name of the service.
    """
    kwargs = utils.get_WazuhIntegration_parameters(access_key=access_key, secret_key=secret_key, aws_profile=profile,
                                                   region=region, service_name=service_name, iam_role_arn=None)
    expected_conn_args = {}
    if access_key and secret_key:
        expected_conn_args['aws_access_key_id'] = access_key
        expected_conn_args['aws_secret_access_key'] = secret_key

    if profile:
        expected_conn_args['profile_name'] = profile
    expected_conn_args['region_name'] = None

    if region and service_name in aws_s3.SERVICES_REQUIRING_REGION:
        expected_conn_args['region_name'] = region
    else:
        expected_conn_args['region_name'] = region if region in aws_s3.DEFAULT_GOV_REGIONS else None

    with patch('aws_s3.WazuhIntegration.check_metadata_version'), \
            patch('aws_s3.sqlite3.connect'), \
            patch('aws_s3.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('aws_s3.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('aws_s3.boto3.Session') as mock_boto:
        aws_s3.WazuhIntegration(**kwargs)
        mock_boto.assert_called_with(**expected_conn_args)


@pytest.mark.parametrize('iam_role_arn', [utils.TEST_IAM_ROLE_ARN, None])
@pytest.mark.parametrize('service_name', ["cloudTrail", "cloudwatchlogs"])
def test_WazuhIntegration_get_client(iam_role_arn, service_name):
    """Test `get_client` function creates a valid client object both when an IAM Role is provided and when it's not.

    Parameters
    ----------
    iam_role_arn : str
        IAM Role.
    service_name : str
        Name of the service.
    """
    kwargs = utils.get_WazuhIntegration_parameters(access_key=None, secret_key=None, aws_profile=None,
                                                   sts_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                   service_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                   service_name=service_name, iam_role_arn=iam_role_arn,
                                                   iam_role_duration=utils.TEST_IAM_ROLE_DURATION)
    service_name = "logs" if service_name == "cloudwatchlogs" else service_name
    conn_kwargs = {'region_name': None}
    sts_kwargs = {'aws_access_key_id': None, 'aws_secret_access_key': None, 'aws_session_token': utils.TEST_TOKEN,
                  'region_name': None}
    assume_role_kwargs = {'RoleArn': iam_role_arn, 'RoleSessionName': 'WazuhLogParsing',
                          'DurationSeconds': utils.TEST_IAM_ROLE_DURATION}
    sts_role_assumption = {
        'Credentials': {'AccessKeyId': None, 'SecretAccessKey': None, 'SessionToken': utils.TEST_TOKEN}}

    mock_boto_session = MagicMock()
    mock_sts_session = MagicMock()
    mock_sts_client = MagicMock()
    mock_boto_session.client.return_value = mock_sts_client
    mock_sts_client.assume_role.return_value = sts_role_assumption

    with patch('aws_s3.WazuhIntegration.check_metadata_version'), \
            patch('aws_s3.sqlite3.connect'), \
            patch('aws_s3.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('aws_s3.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('aws_s3.boto3.Session', side_effect=[mock_boto_session, mock_sts_session]) as mock_session:
        instance = aws_s3.WazuhIntegration(**kwargs)

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


def test_WazuhIntegration_get_client_ko():
    """Test `get_client` function handles botocore.exceptions as expected."""
    mock_boto_session = MagicMock()
    mock_boto_session.client.side_effect=aws_s3.botocore.exceptions.ClientError({'Error': {'Code': 1}}, 'operation')

    with patch('aws_s3.WazuhIntegration.check_metadata_version'), \
            patch('aws_s3.sqlite3.connect'), \
            patch('aws_s3.utils.find_wazuh_path', return_value=utils.TEST_WAZUH_PATH), \
            patch('aws_s3.utils.get_wazuh_version', return_value=utils.WAZUH_VERSION), \
            patch('aws_s3.boto3.Session', return_value=mock_boto_session):
        with pytest.raises(SystemExit) as e:
            aws_s3.WazuhIntegration(**utils.get_WazuhIntegration_parameters())
        assert e.value.code == INVALID_CREDENTIALS_ERROR_CODE


@pytest.mark.parametrize('access_key, secret_key, profile', [
    (utils.TEST_ACCESS_KEY, utils.TEST_SECRET_KEY, None),
    (utils.TEST_ACCESS_KEY, None, None),
    (None, utils.TEST_SECRET_KEY, None),
    (None, None, utils.TEST_AWS_PROFILE),
    (None, None, utils.TEST_AWS_PROFILE),
])
def test_WazuhIntegration_get_sts_client(access_key, secret_key, profile):
    """Test `get_sts_client` function uses the expected configuration for the session and the client while returning a
    valid sts client object.

    Parameters
    ----------
    access_key : str
        Access key value.
    secret_key : str
        Secret key value.
    profile : str
        AWS profile name.
    """
    instance = utils.get_mocked_WazuhIntegration(access_key=access_key, secret_key=secret_key, aws_profile=profile)
    expected_conn_args = {}
    if access_key and secret_key:
        expected_conn_args['aws_access_key_id'] = access_key
        expected_conn_args['aws_secret_access_key'] = secret_key

    if profile:
        expected_conn_args['profile_name'] = profile

    mock_session = MagicMock()
    with patch('aws_s3.boto3.Session', return_value=mock_session) as mock_boto:
        sts_client = instance.get_sts_client(access_key=access_key, secret_key=secret_key, profile=profile)
        mock_boto.assert_called_with(**expected_conn_args)
        mock_session.client.assert_called_with(service_name='sts', **instance.connection_config)
        assert sts_client == mock_session.client()


def test_WazuhIntegration_get_sts_client_ko():
    """Test `get_sts_client` function handles invalid credentials exception as expected."""
    mock_boto_session = MagicMock()
    mock_boto_session.client.side_effect=aws_s3.botocore.exceptions.ClientError({'Error': {'Code': 1}}, 'operation')

    instance = utils.get_mocked_WazuhIntegration(access_key=None, secret_key=None, aws_profile=None)

    with patch('aws_s3.boto3.Session', return_value=mock_boto_session):
        with pytest.raises(SystemExit) as e:
            instance.get_sts_client(access_key=None, secret_key=None, profile=None)
        assert e.value.code == INVALID_CREDENTIALS_ERROR_CODE


@pytest.mark.parametrize("dump_json", [True, False])
def test_WazuhIntegration_send_msg(dump_json):
    """Test `send_msg` function build the message using the expected format and sends it to the appropriate socket.

    Parameters
    ----------
    dump_json : bool
        Determine if the message should be dumped first.
    """
    instance = utils.get_mocked_WazuhIntegration()
    msg = dumps(utils.TEST_MESSAGE) if dump_json else utils.TEST_MESSAGE
    with patch('aws_s3.socket.socket') as mock_socket:
        m = MagicMock()
        mock_socket.return_value = m
        instance.send_msg(utils.TEST_MESSAGE, dump_json=dump_json)
        mock_socket.assert_called_once()
        m.send.assert_called_with(f"{aws_s3.MESSAGE_HEADER}{msg}".encode())
        m.close.assert_called_once()


@pytest.mark.parametrize("error_code, expected_exit_code", [
    (111, UNABLE_TO_CONNECT_SOCKET_ERROR_CODE),
    (1, SENDING_MESSAGE_SOCKET_ERROR_CODE),
    (90, None)
])
def test_WazuhIntegration_send_msg_socket_error(error_code, expected_exit_code):
    """Test `send_msg` function handles the different expected socket exceptions.

    Parameters
    ----------
    error_code : int
        Error code number for the socket error to be raised.
    expected_exit_code : int
        Error code number for the expected exit exception.
    """
    instance = utils.get_mocked_WazuhIntegration()
    error = socket.error()
    error.errno = error_code

    with patch('aws_s3.socket.socket') as mock_socket:
        mock_socket.side_effect = error
        if expected_exit_code:
            with pytest.raises(SystemExit) as e:
                instance.send_msg(utils.TEST_MESSAGE)
            assert e.value.code == expected_exit_code
        else:
            instance.send_msg(utils.TEST_MESSAGE)


def test_WazuhIntegration_send_msg_ko():
    """Test `send_msg` function handles the other expected exceptions."""
    instance = utils.get_mocked_WazuhIntegration()

    with patch('aws_s3.socket.socket') as mock_socket:
        mock_socket.side_effect = TypeError
        with pytest.raises(SystemExit) as e:
            instance.send_msg(utils.TEST_MESSAGE)
        assert e.value.code == SENDING_MESSAGE_SOCKET_ERROR_CODE


def test_WazuhIntegration_create_table():
    """Test `create_table` function creates the table using the expected SQL."""
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_cursor = MagicMock()
    test_sql = "test"
    instance.create_table(test_sql)
    instance.db_cursor.execute.assert_called_with(test_sql)


def test_WazuhIntegration_create_table_ko():
    """Test `create_table` function creates the table using the expected SQL."""
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.side_effect = Exception

    with pytest.raises(SystemExit) as e:
        instance.create_table("")
    assert e.value.code == UNABLE_TO_CREATE_DB


@pytest.mark.parametrize("table_list", [
    ["table_1", "table_2", DB_TABLENAME],
    ["table_1", "table_2"],
    [DB_TABLENAME],
    []
])
@patch('aws_s3.WazuhIntegration.create_table')
def test_WazuhIntegration_init_db(mock_create_table, table_list):
    """Test `init_db` function checks if the required table exists and creates it if not.

    Parameters
    ----------
    table_list : list of str
        Table list to be returned by the mocked database query.
    """
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.return_value = [(x, ) for x in table_list]
    instance.db_table_name = DB_TABLENAME
    test_sql = "test"
    instance.init_db(test_sql)

    if DB_TABLENAME in table_list:
        mock_create_table.assert_not_called()
    else:
        mock_create_table.assert_called_with(test_sql)


def test_WazuhIntegration_init_db_ko():
    """Test `init_db` function handles exception as expected."""
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_cursor = MagicMock()
    instance.db_cursor.execute.side_effect = sqlite3.OperationalError

    with pytest.raises(SystemExit) as e:
        instance.init_db("")
    assert e.value.code == METADATA_ERROR_CODE



def test_WazuhIntegration_close_db():
    """Test `close_db` function closes the database objects properly."""
    instance = utils.get_mocked_WazuhIntegration()
    instance.db_connector = MagicMock()
    instance.db_cursor = MagicMock()

    instance.close_db()

    instance.db_connector.commit.assert_called_once()
    instance.db_cursor.execute.assert_called_with(instance.sql_db_optimize)
    instance.db_connector.close.assert_called_once()
