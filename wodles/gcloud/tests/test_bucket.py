#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for bucket module."""

import json
import os
import sqlite3
import sys
from datetime import datetime
from logging import Logger
from unittest.mock import MagicMock
from unittest.mock import call, patch

import pytest
import pytz
from google.api_core import exceptions as google_exceptions

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import exceptions
from buckets.access_logs import GCSAccessLogs
from buckets.bucket import WazuhGCloudBucket


BUCKET_ATTRIBUTES = ['bucket_name', 'bucket', 'client', 'project_id', 'prefix', 'delete_file', 'only_logs_after',
                     'db_connector', 'datetime_format']
TABLE_COLUMNS = ["project_id", "bucket_name", "prefix", "blob_name", "creation_time"]
TEST_TABLE_NAME = "test_table"
TEST_BUCKET_NAME = "test_bucket"
TEST_PROJECT_ID = "project_123"
TEST_BLOB_LIST = ["test_blob_1", "test_blob_2"]
TEST_BLOB_LIST_WITH_FOLDER = ['blob_1', 'blob_2', 'folder/']

data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/')
SQL_FILE = "testing_database.sql"


@pytest.fixture(scope='function')
def clean_shared_cache():
    """Drop any table present in the cached database before and after the test."""
    _drop_all_tables()
    yield
    _drop_all_tables()


def _drop_all_tables():
    """List and drop every user table."""
    db_connector = sqlite3.connect('file::memory:?cache=shared', uri=True)
    table_names = get_all_table_names(db_connector)
    for table in table_names:
        db_connector.execute(f"DROP TABLE {table};")
    db_connector.close()


def get_wodle_config(credentials_file: str = "credentials.json", logger: Logger = None,
                     bucket_name: str = "test_bucket", prefix: str = "", delete_file: bool = False,
                     only_logs_after: str = None, reparse: bool = False) -> dict:
    """Return a dict containing every parameter supported by WazuhGCloudBucket. Used to simulate different ossec.conf
    configurations.

    Parameters
    ----------
    credentials_file : str
        Path to credentials file.
    logger: logging.Logger
        The logger that will be used to send messages to stdout.
    bucket_name : str
        Name of the bucket to read the logs from.
    prefix : prefix
        Expected prefix for the logs. It can be used to specify the relative path where the logs are stored.
    delete_file : bool
        Indicate whether blobs should be deleted after being processed.
    only_logs_after : datetime
        Date after which obtain logs.
    reparse : bool
        Whether to parse already parsed logs or not

    Returns
    -------
    dict
        A dict containing the configuration parameters with their values
    """
    return {'credentials_file': credentials_file, 'logger': logger if logger else MagicMock(),
            'bucket_name': bucket_name, 'prefix': prefix, 'delete_file': delete_file, 'reparse': reparse,
            'only_logs_after': only_logs_after.replace(tzinfo=pytz.UTC) if only_logs_after else None}


def get_num_rows(db_connector: sqlite3.Connection, table_name: str) -> int:
    """Get the row count for the given table_name.

    Parameters
    ----------
    db_connector : sqlite3.Connection
        The connector used to execute the query.
    table_name : str
        The name of the table to count the rows.

    Returns
    -------
    int
        The row count for the given table.
    """
    return db_connector.execute(f"SELECT count(*) FROM {table_name}").fetchone()[0]


def get_blobs_in_database(db_connector, table_name, bucket_name, project_id, prefix) -> list[str]:
    """List the blobs available for the given parameters.

    Parameters
    ----------
    db_connector : sqlite3.Connection
        The connector used to execute the query.
    table_name : str
        The name of the table to list the blobs.
    bucket_name : str
        The name of the table to list the blobs.
    project_id : str
        The name of the project for a pubsub integration
    prefix : prefix
        Expected prefix for the logs. It can be used to specify the relative path where the logs are stored.

    Returns
    -------
    list[str]
        List of blob names.
    """
    rows = db_connector.execute(f"SELECT blob_name FROM {table_name} where "
                                f"bucket_name='{bucket_name}' and "
                                f"project_id='{project_id}' and "
                                f"prefix='{prefix}'").fetchall()
    return [row[0] for row in rows]


def get_all_table_names(db_connector) -> list[str]:
    """List all tables present in the database.

    Parameters
    ----------
    db_connector : sqlite3.Connection
        The connector used to execute the query.

    Returns
    -------
    list[str]
        List of table names.
    """
    table_list = db_connector.execute(
        "SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"
    ).fetchall()
    return [table[0] for table in table_list]


def create_mocked_blob(blob_name: str, creation_time: datetime = None):
    """Return a fake blob with name and creation time.

    Parameters:
    ----------
    blob_name : str
        The name of the fake blob.
    creation_time : str
        The creation time of the fake blob. datetime.now() will be used if no creation_time is provided.

    Returns
    -------
    MagicMock
         A fake blob
    """
    blob = MagicMock()
    blob.name = blob_name
    blob.time_created = creation_time if creation_time else datetime.now()
    blob.time_created = blob.time_created.replace(tzinfo=pytz.UTC)
    return blob


def create_custom_database():
    """Create a custom database in memory without cache."""
    memory_db = sqlite3.connect(':memory:')
    with open(os.path.join(data_path, SQL_FILE)) as f:
        memory_db.cursor().executescript(f.read())
    return memory_db


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket__init__(mock_client):
    """Test if an instance of WazuhGCloudBucket is created properly."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    for attribute in BUCKET_ATTRIBUTES:
        assert hasattr(bucket, attribute)


@pytest.mark.parametrize('credentials_file, errcode', [
    ('un-existent_file', 1001),
    ('invalid_credentials_file.json', 1000)
])
def test_WazuhGCloudBucket__init__ko(credentials_file, errcode):
    """Test that the appropriate exceptions are raised when the WazuhGCloudBucket constructor is called with
    invalid parameters."""
    with pytest.raises(exceptions.GCloudError) as e:
        WazuhGCloudBucket(**get_wodle_config(credentials_file=os.path.join(data_path, credentials_file)))
    assert e.value.errcode == errcode


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_init_db(mock_client, clean_shared_cache):
    """Test init_db creates the database with the expected tables with valid structures."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    bucket.db_table_name = TEST_TABLE_NAME
    # Set database in memory using cache
    with patch('buckets.bucket.sqlite3.connect', return_value=sqlite3.connect('file::memory:?cache=shared', uri=True)):
        bucket.init_db()
        # Call init again to force an operational error because the table already exists. Execution must continue.
        bucket.init_db()
    
    # Check there is only one table, and it has the expected name
    table_list = get_all_table_names(bucket.db_connector)
    assert len(table_list) == 1
    assert table_list[0] == TEST_TABLE_NAME

    # Check the table has the expected 
    table_columns = bucket.db_connector.execute(f"SELECT * FROM {TEST_TABLE_NAME}").description
    assert set([column[0] for column in table_columns]) == set(TABLE_COLUMNS)


@pytest.mark.parametrize('project_id, expected_length', [(TEST_PROJECT_ID, 2), ("invalid_project_id", 0)])
@patch('buckets.bucket.WazuhGCloudBucket.init_db')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_get_last_processed_files(mock_client, mock_db, project_id, expected_length):
    """Test _get_last_processed_files returns the expected number of items."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    bucket.db_connector = create_custom_database()
    bucket.db_table_name = TEST_TABLE_NAME
    bucket.project_id = project_id
    item_list = bucket._get_last_processed_files()
    assert isinstance(item_list, list)
    assert len(item_list) == expected_length


@pytest.mark.parametrize('project_id, prefix, processed_files', [
    (TEST_PROJECT_ID, "", []),
    (TEST_PROJECT_ID, "", TEST_BLOB_LIST),
    (TEST_PROJECT_ID, "prefix/", TEST_BLOB_LIST),
    ("non-existent_project_id", "", TEST_BLOB_LIST),
])
@patch('buckets.bucket.WazuhGCloudBucket.init_db')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_update_last_processed_files(mock_client, mock_db, project_id, prefix,
                                                       processed_files):
    """Test _update_last_processed_files updates the database by adding and removing rows when required."""
    bucket = WazuhGCloudBucket(**get_wodle_config(prefix=prefix))
    bucket.db_connector = create_custom_database()
    bucket.db_table_name = TEST_TABLE_NAME
    bucket.project_id = project_id

    # Initialize the blob list
    blob_list = [create_mocked_blob(blob_name=name) for name in processed_files]

    # Check database state before the call
    row_count_before_test = get_num_rows(table_name=TEST_TABLE_NAME, db_connector=bucket.db_connector)
    previous_processed_files = get_blobs_in_database(db_connector=bucket.db_connector, table_name=TEST_TABLE_NAME,
                                                     bucket_name=TEST_BUCKET_NAME, project_id=bucket.project_id,
                                                     prefix=prefix)

    # Invoke the function we want to test
    bucket._update_last_processed_files(processed_files=blob_list)

    # Check database state after the call
    row_count_after_test = get_num_rows(table_name=TEST_TABLE_NAME, db_connector=bucket.db_connector)
    new_processed_files = get_blobs_in_database(db_connector=bucket.db_connector, table_name=TEST_TABLE_NAME,
                                                bucket_name=TEST_BUCKET_NAME, project_id=bucket.project_id, prefix=prefix)

    # Check that the integrity of the database has been preserved, with no uninvolved rows deleted
    assert row_count_after_test == row_count_before_test + (len(new_processed_files) - len(previous_processed_files))

    # Check the blobs stored in the database for the last processed files are the expected ones
    if processed_files:
        assert len(new_processed_files) == len(processed_files)
        assert set(new_processed_files) == set(processed_files)
    else:
        assert set(previous_processed_files) == set(new_processed_files)


@patch('buckets.bucket.WazuhGCloudBucket.init_db')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_update_last_processed_files_ko(mock_client, mock_db):
    """Test _update_last_processed_files does not remove any row when an exception is raised."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    bucket.db_connector = create_custom_database()
    bucket.db_table_name = TEST_TABLE_NAME
    bucket.project_id = TEST_PROJECT_ID

    # Initialize the blob list
    blob_list = [create_mocked_blob(blob_name=name) for name in TEST_BLOB_LIST]

    # Check database state before the call
    row_count_before_test = get_num_rows(table_name=TEST_TABLE_NAME, db_connector=bucket.db_connector)

    # Replace the deletion query before invoking the function to ensure the deletion process fails
    bucket.sql_delete_processed_files = "invalid query"
    bucket._update_last_processed_files(processed_files=blob_list)

    # Check database state after the call
    row_count_after_test = get_num_rows(table_name=TEST_TABLE_NAME, db_connector=bucket.db_connector)
    assert row_count_before_test == row_count_after_test - len(TEST_BLOB_LIST)


@pytest.mark.parametrize('project_id, expected_result', [("project_123", 2), ("invalid_project_id", 0)])
@patch('buckets.bucket.WazuhGCloudBucket.init_db')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_get_last_creation_time(mock_client, mock_db, project_id, expected_result):
    """Test _get_last_creation_time always returns a datetime object."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    bucket.db_connector = create_custom_database()
    bucket.db_table_name = TEST_TABLE_NAME
    bucket.project_id = project_id
    item_list = bucket._get_last_creation_time()
    assert isinstance(item_list, datetime)


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
@pytest.mark.parametrize('google_exception, errcode', [
    (google_exceptions.NotFound, 1100),
    (google_exceptions.Forbidden, 1101)
])
def test_WazuhGCloudBucket_check_permissions(mock_client, google_exception, errcode):
    """Test check_permissions raises the expected exceptions when the user doesn't have the required permissions."""
    mock_client.get_bucket.side_effect = google_exception("placeholder")
    bucket = WazuhGCloudBucket(**get_wodle_config())
    bucket.client = mock_client
    with pytest.raises(exceptions.GCloudError) as e:
        bucket.check_permissions()
    assert e.value.errcode == errcode


@patch('buckets.bucket.WazuhGCloudBucket.init_db')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
@pytest.mark.parametrize('prefix, blob_creation_time, only_logs_after, last_creation_time, reparse, message_per_blob, total_messages', [
    # Every blob will be skipped because of comparison_date
    ('', datetime(2022, 1, 1, 12, 00, 00, 0), None, datetime.min, False, 100, 0),
    ('prefix/', datetime(2022, 1, 1, 12, 00, 00, 0), None, datetime.min, False, 100, 0),
    # Every blob will be processed. Only the last blob will be stored in processed_files
    ('', None, datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 200),
    ('prefix/', None, datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 200),
    # Every blob will be processed. Every blob will be stored in processed_files
    ('', datetime(2022, 12, 31, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 200),
    ('prefix/', datetime(2022, 12, 31, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 200),
    # Every blob will be processed because of the reparse option
    ('', datetime(2022, 1, 1, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime(9999, 1, 1, 12, 00, 00, 0), True, 100, 200),
    ('prefix/', datetime(2022, 1, 1, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime(9999, 1, 1, 12, 00, 00, 0), True, 100, 200),
    # Every blob will be skipped as they are considered already processed because of the last_creation_time
    ('', datetime(2022, 1, 1, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime(9999, 1, 1, 12, 00, 00, 0), False, 100, 0),
    ('prefix/', datetime(2022, 1, 1, 12, 00, 00, 0), datetime(2022, 1, 1, 12, 00, 00, 0), datetime(9999, 1, 1, 12, 00, 00, 0), False, 100, 0),
    # Every blob will be skipped because they are old
    ('', datetime.min, datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 0),
    ('prefix/', datetime.min, datetime(2022, 1, 1, 12, 00, 00, 0), datetime.min, False, 100, 0)
])
def test_WazuhGCloudBucket_process_data(mock_client, mock_init_db, prefix, blob_creation_time,
                                        only_logs_after, last_creation_time, reparse, message_per_blob, total_messages):
    """Test process_data ignore or process the different blobs taking into account only_logs_after, creation dates and
    already processed files."""
    bucket = WazuhGCloudBucket(**get_wodle_config(prefix=prefix, only_logs_after=only_logs_after, reparse=reparse))
    bucket.db_table_name = TEST_TABLE_NAME
    blob_list = [create_mocked_blob(blob_name=name, creation_time=blob_creation_time) for name in TEST_BLOB_LIST_WITH_FOLDER]
    filtered_blob_list = [blob for blob in blob_list if not blob.name.endswith('/')]

    # Setup mocks
    mock_db_connector = MagicMock()
    mock_update_last_processed_files = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.list_blobs.return_value = blob_list
    mock_process_blob = MagicMock(return_value=message_per_blob)
    mock_last_creation_time = MagicMock(return_value=last_creation_time.replace(tzinfo=pytz.UTC))

    # Apply mocks
    bucket.bucket = mock_bucket
    bucket.process_blob = mock_process_blob
    bucket.db_connector = mock_db_connector
    bucket._update_last_processed_files = mock_update_last_processed_files
    bucket._get_last_creation_time = mock_last_creation_time

    # Call the function we want to test
    processed_messages = bucket.process_data()

    # Assert mocks
    mock_bucket.list_blobs.assert_called_with(prefix=prefix, delimiter='/')
    mock_init_db.assert_called_once()

    if blob_creation_time and not only_logs_after:
        # The creation time of blob is older than the only_logs_after value. They should be skipped.
        mock_process_blob.assert_not_called()
        mock_update_last_processed_files.assert_called_with([])
    elif not blob_creation_time and only_logs_after:
        # The blobs don't share the same creation time.
        # Every blob should be processed, but only the last one should be stored in the last_processed_files
        mock_process_blob.assert_has_calls([call(blob) for blob in filtered_blob_list])
        mock_update_last_processed_files.assert_called_with(filtered_blob_list[-1:])
    elif blob_creation_time > only_logs_after or reparse:
        # The blobs share the same creation time. They should be processed because of their creation time or reparse
        mock_process_blob.assert_has_calls([call(blob) for blob in filtered_blob_list])
        mock_update_last_processed_files.assert_called_with(filtered_blob_list)
    else:
        # The blobs share the same creation time, but it's older than the only_logs_after value and there is no reparse
        mock_process_blob.assert_not_called()
        mock_update_last_processed_files.assert_called_with([])

    mock_db_connector.commit.assert_called_once()
    mock_db_connector.close.assert_called_once()
    assert processed_messages == total_messages


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_load_information_from_file(mock_client):
    """Test load_information_from_file is not implemented for this base class."""
    bucket = WazuhGCloudBucket(**get_wodle_config())
    with pytest.raises(NotImplementedError):
        bucket.load_information_from_file('')


@patch('buckets.access_logs.GCSAccessLogs.send_msg')
@patch('buckets.access_logs.GCSAccessLogs.initialize_socket')
@patch('buckets.access_logs.GCSAccessLogs.load_information_from_file')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
@pytest.mark.parametrize('delete_file', [False, True])
def test_WazuhGCloudBucket_process_blob(mock_client, mock_load_information, mock_socket, mock_send_msg, delete_file):
    """Test process_blob sends formatted messages to the socket and request blob deletion if required."""
    num_events = 100
    mock_load_information.return_value = [f"event {i}" for i in range(num_events)]
    bucket = GCSAccessLogs(**get_wodle_config(delete_file=delete_file))
    bucket.db_table_name = TEST_TABLE_NAME
    bucket.bucket = MagicMock()
    num_messages_sent = bucket.process_blob(create_mocked_blob("blob"))
    mock_send_msg.assert_has_calls([call(bucket.format_msg(json.dumps(msg))) for msg in mock_load_information()])
    assert num_messages_sent == num_events
    if delete_file:
        bucket.bucket.delete_blob.assert_called_with("blob")


@patch('buckets.access_logs.GCSAccessLogs.load_information_from_file')
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_WazuhGCloudBucket_process_blob_ko(mock_client, mock_load_information):
    """Test process_blob handles exceptions as expected."""
    mock_load_information.side_effect = google_exceptions.NotFound("")
    bucket = GCSAccessLogs(**get_wodle_config())
    num_messages_sent = bucket.process_blob(create_mocked_blob("blob"))
    assert num_messages_sent == 0


@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_GCSAccessLogs__init__(mock_client):
    """Test if an instance of GCSAccessLogs is created properly."""
    bucket = GCSAccessLogs(**get_wodle_config())
    for attribute in BUCKET_ATTRIBUTES:
        assert hasattr(bucket, attribute)
    assert bucket.db_table_name == "access_logs"


@pytest.mark.parametrize('file_path', [os.path.join(data_path, "access_logs.log")])
@patch('buckets.bucket.storage.client.Client.from_service_account_json')
def test_GSCAccessLogs_load_information_from_file(mock_client, file_path):
    """Test load_information_from_file process files with the expected format and returns valid events."""
    contents = None
    header = None
    with open(file_path) as f:
        contents = f.read()
        f.seek(0, 0)
        header = f.readline().rstrip()
    header = header.split(",")
    header.append("source")
    bucket = GCSAccessLogs(**get_wodle_config())
    for event in bucket.load_information_from_file(contents):
        keys = event.keys()
        assert set(header) == set(keys)
        for key in keys:
            assert event[key] == "gcp_bucket" if key == "source" else event[key] == f'{key}_value'
