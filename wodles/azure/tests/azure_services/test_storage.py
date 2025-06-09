#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import json
import sys
from datetime import datetime
from hashlib import md5
from os.path import abspath, dirname, join, realpath
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest
import pytz
from azure.core.exceptions import AzureError, ClientAuthenticationError, HttpResponseError
from dateutil.parser import parse

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_services.storage import get_blobs, start_storage
from db import orm

PAST_DATE = '2022-01-01T12:00:00.000000Z'
PRESENT_DATE = '2022-06-15T12:00:00.000000Z'
FUTURE_DATE = '2022-12-31T12:00:00.000000Z'

TEST_DATA_PATH = join(dirname(dirname(realpath(__file__))), 'data')


def create_mocked_blob(blob_name: str, last_modified: datetime = None, content_length: Optional[int] = None):
    """Return a fake blob with name and creation time.

    Parameters:
    ----------
    blob_name : str
        The name of the fake blob.
    last_modified : str
        The last modified time property of the fake blob. datetime.now() will be used if no creation_time is provided.
    content_length: Optional[int]
        The content_length property of the fake blob. This property is only set if the length is not None

    Returns
    -------
    MagicMock
         A fake blob.
    """
    blob = MagicMock()
    blob.name = blob_name
    blob.last_modified = (last_modified if last_modified else datetime.now()).replace(tzinfo=pytz.UTC)

    # Add Blob length property
    if content_length is not None:
        blob.size = content_length

    return blob


@pytest.mark.parametrize(
    'auth_path, name, key, container_name',
    [
        (None, 'name', 'key', 'container'),
        ('/var/ossec/', '', '', '*'),
    ],
)
@patch('azure_services.storage.get_blobs')
@patch('azure_services.storage.create_new_row')
@patch('azure_services.storage.orm.get_row', return_value=None)
@patch('azure_services.storage.BlobServiceClient')
@patch('azure_services.storage.read_auth_file')
def test_start_storage(
    mock_auth,
    mock_blob,
    mock_get_row,
    mock_create,
    mock_get_blobs,
    auth_path,
    name,
    key,
    container_name,
):
    """Test start_storage process blobs in bucket as expected."""
    offset = '1d'
    args = MagicMock(
        storage_auth_path=auth_path,
        account_name=name,
        account_key=key,
        container=container_name,
        storage_time_offset=offset,
    )
    mock_create.return_value = MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE)
    mock_auth.return_value = (name, key)
    m = MagicMock()
    m.list_containers.return_value = [MagicMock(name=container_name)]
    mock_blob.return_value = m
    start_storage(args)

    if auth_path:
        mock_auth.assert_called_with(auth_path=auth_path, fields=('account_name', 'account_key'))
    else:
        mock_auth.assert_not_called()

    md5_hash = md5(name.encode()).hexdigest()
    mock_blob.assert_called_with(
        account_url=f'https://{name}.blob.core.windows.net/',
        credential={'account_name': name, 'account_key': key}
    )
    mock_get_row.assert_called_with(orm.Storage, md5=md5_hash)
    mock_create.assert_called_with(table=orm.Storage, query=name, md5_hash=md5_hash, offset=offset)
    mock_get_blobs.assert_called_once()


@pytest.mark.parametrize(
    'container_name, exception',
    [
        ('', None),
        ('', AzureError('')),
        ('*', ClientAuthenticationError),
        ('*', AzureError('')),
        ('*', None),
    ],
)
@patch('azure_utils.logging.error')
@patch('azure_services.storage.create_new_row', side_effect=orm.AzureORMError)
@patch('db.orm.get_row', return_value=None)
@patch('azure_services.storage.BlobServiceClient')
def test_start_storage_ko(mock_blob, mock_get, mock_create, mock_logging, container_name, exception):
    """Test start_log_analytics shows error message if get_log_analytics_events returns an HTTP error."""
    args = MagicMock(
        storage_auth_path=None,
        account_name='test',
        account_key='test',
        container=container_name,
        storage_time_offset='',
    )
    m = MagicMock()
    if container_name == '*':
        m.list_containers.return_value = [MagicMock(name=container_name)]
        m.list_containers.side_effect = exception
    else:
        m.exists.return_value = None
        m.exists.side_effect = exception
    mock_blob.return_value = m

    with pytest.raises(SystemExit) as err:
        start_storage(args)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure_utils.logging.error')
def test_start_storage_ko_credentials(mock_logging):
    """Test start_storage stops its execution if no valid credentials are provided."""
    args = MagicMock(storage_auth_path=None, account_name=None, account_key=None)
    with pytest.raises(SystemExit) as err:
        start_storage(args)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'blob_date, min_date, max_date, desired_date, extension, reparse, json_file, inline, send_events',
    [
        # blob_date < desired_date - Blobs should be skipped
        (
            PRESENT_DATE,
            PAST_DATE,
            PAST_DATE,
            FUTURE_DATE,
            None,
            False,
            False,
            False,
            False,
        ),
        # blob_date > desired_date, min_date == blob_date and blob_date < max_date - Blobs should be skipped
        (
            PRESENT_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            PAST_DATE,
            None,
            False,
            False,
            False,
            False,
        ),
        # blob_date > desired_date, min_date < blob_date and blob_date == max_date - Blobs should be skipped
        (
            FUTURE_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            PAST_DATE,
            None,
            False,
            False,
            False,
            False,
        ),
        # blob_date > desired_date, min_date < blob_date and blob_date < max_date - Blobs should be skipped
        (
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            PAST_DATE,
            None,
            False,
            False,
            False,
            False,
        ),
        # blob_date < min_datetime - Blobs must be processed
        (
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            PAST_DATE,
            None,
            False,
            False,
            False,
            True,
        ),
        # blob_date > max_datetime - Blobs must be processed
        (
            FUTURE_DATE,
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            None,
            False,
            False,
            True,
            True,
        ),
        # Reparse old logs
        (
            FUTURE_DATE,
            FUTURE_DATE,
            FUTURE_DATE,
            FUTURE_DATE,
            None,
            True,
            False,
            True,
            True,
        ),
        # Only .json files must be processed
        (
            FUTURE_DATE,
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            '.json',
            False,
            False,
            False,
            True,
        ),
        (
            FUTURE_DATE,
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            '.json',
            False,
            False,
            True,
            True,
        ),
        (
            FUTURE_DATE,
            PAST_DATE,
            PRESENT_DATE,
            FUTURE_DATE,
            '.json',
            False,
            True,
            False,
            True,
        ),
    ],
)
@patch('azure_services.storage.update_row_object')
@patch('azure_services.storage.SocketConnection.send_message')
def test_get_blobs(
    mock_send,
    mock_update,
    blob_date,
    min_date,
    max_date,
    desired_date,
    extension,
    reparse,
    json_file,
    inline,
    send_events,
):
    """Test get_blobs obtains the blobs from a container and send their content to the socket."""
    blob_date_str = parse(blob_date)
    blob_list = [create_mocked_blob(blob_name=f'blob_{i}', last_modified=blob_date_str) for i in range(5)] + [
        create_mocked_blob(blob_name=f'blob_{i}{extension}', last_modified=blob_date_str) for i in range(5)
    ]

    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.return_value = iter(blob_list)

    if json_file:
        test_file = 'storage_events_json'
    elif inline:
        test_file = 'storage_events_inline'
    else:
        test_file = 'storage_events_plain'

    with open(join(TEST_DATA_PATH, test_file)) as f:
        contents = f.read()
        data_mock = MagicMock(name='data_mock')
        data_mock.readall.return_value = contents
        container_client.download_blob.return_value = data_mock

    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client

    container_name = 'container'
    md5_hash = 'hash'
    tag = 'tag'
    get_blobs(
        container_name=container_name,
        service_client=service_client,
        md5_hash=md5_hash,
        min_datetime=parse(min_date),
        max_datetime=parse(max_date),
        desired_datetime=parse(desired_date),
        tag=tag,
        reparse=reparse,
        json_file=json_file,
        json_inline=inline,
        blob_extension=extension,
    )

    service_client.get_container_client.assert_called_with(container_name)
    container_client.list_blobs.assert_called_with(name_starts_with=None)
    container_client.download_blob.assert_has_calls(
        [call(blob, encoding='UTF-8', max_concurrency=2) for blob in blob_list if extension and extension in blob.name]
    )
    if send_events:
        calls = list()
        extension = extension if extension else ''
        for blob in blob_list:
            if extension in blob.name:
                if json_file:
                    for record in json.loads(contents)['records']:
                        record['azure_tag'] = 'azure-storage'
                        record['azure_storage_tag'] = tag
                        calls.append(call(json.dumps(record)))
                else:
                    for line in [s for s in str(contents).splitlines() if s]:
                        if inline:
                            calls.append(
                                call(f'{{"azure_tag": "azure-storage", "azure_storage_tag": "{tag}", {line[1:]}')
                            )
                        else:
                            calls.append(call(f'azure_tag: azure-storage. azure_storage_tag: {tag}. {line}'))
        mock_send.assert_has_calls(calls)
        assert (
            mock_update.call_count == len(blob_list)
            if not extension
            else len([blob.name for blob in blob_list if extension in blob.name])
        )


@patch('azure_utils.logging.debug')
def test_that_empty_blobs_are_omitted(mock_logging):
    """Test get_blobs checks the size of the blob and omits it if is is empty"""
    # List of empty blobs to use
    list_of_empty_blobs = [
        create_mocked_blob('Example1', content_length=0),
        create_mocked_blob('Example2', content_length=0),
    ]

    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.return_value = iter(list_of_empty_blobs)

    # Mock for the service client
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client

    container_name = 'container'
    md5_hash = 'hash'
    get_blobs(
        container_name=container_name,
        service_client=service_client,
        md5_hash=md5_hash,
        min_datetime=parse(PRESENT_DATE),
        max_datetime=parse(FUTURE_DATE),
        desired_datetime=parse(FUTURE_DATE),
        tag='storage_tag',
        reparse=False,
        json_file=False,
        json_inline=False,
        blob_extension=None,
    )

    expected_calls = [
        call('Empty blob Example1, skipping'),
        call('Empty blob Example2, skipping'),
    ]
    mock_logging.assert_has_calls(expected_calls, any_order=False)
    container_client.download_blob.assert_not_called()


@patch('azure_services.storage.update_row_object')
@patch('azure_services.storage.SocketConnection.send_message')
def test_get_blobs_only_with_prefix(mock_send, mock_update):
    """Test get_blobs process only the blobs corresponding to a specific prefix, ignoring the rest."""
    MagicMock(blobs=None, json_file=False, json_inline=False, reparse=False)

    prefix = 'test_prefix'
    blob_date_str = parse(FUTURE_DATE)

    blob_list = (
        [create_mocked_blob(blob_name=f'blob_{i}', last_modified=blob_date_str) for i in range(5)]
        + [create_mocked_blob(blob_name=f'{prefix}/blob_{i}', last_modified=blob_date_str) for i in range(5)]
        + [create_mocked_blob(blob_name=f'other_prefix/blob_{i}', last_modified=blob_date_str) for i in range(5)]
    )

    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.return_value = iter(blob_list)

    data_mock = MagicMock(name='data_mock')
    data_mock.readall.return_value = ''
    container_client.download_blob.return_value = data_mock

    # Mock for the service client
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client

    container_name = 'container'
    md5_hash = 'hash'

    get_blobs(
        container_name=container_name,
        service_client=service_client,
        md5_hash=md5_hash,
        min_datetime=parse(PAST_DATE),
        max_datetime=parse(PRESENT_DATE),
        desired_datetime=parse(FUTURE_DATE),
        prefix=prefix,
        tag='storage_tag',
        reparse=False,
        json_file=False,
        json_inline=False,
        blob_extension=None,
    )

    container_client.list_blobs.assert_called_with(name_starts_with=prefix)
    container_client.download_blob.assert_has_calls(
        [call(blob, encoding='UTF-8', max_concurrency=2) for blob in blob_list if prefix in blob.name]
    )


@patch('azure_utils.logging.error')
def test_get_blobs_list_blobs_ko(mock_logging):
    """Test get_blobs_list_blobs handles exceptions from 'list_blobs'."""
    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.side_effect = AzureError('')
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client

    with pytest.raises(AzureError):
        get_blobs(
            container_name=None,
            service_client=service_client,
            md5_hash=None,
            min_datetime=None,
            max_datetime=None,
            desired_datetime=None,
            tag='storage_tag',
            reparse=False,
            json_file=False,
            json_inline=False,
            blob_extension=None,
        )
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'exception',
    [
        ValueError,
        AzureError(''),
        HttpResponseError,
    ],
)
@patch('azure_services.storage.logging.error')
@patch('azure_services.storage.update_row_object')
def test_get_blobs_blob_data_ko(mock_update, mock_logging, exception):
    """Test get_blobs_list_blobs handles exceptions from 'get_blob_to_text'."""
    num_blobs = 5
    blob_list = [create_mocked_blob(blob_name=f'blob_{i}') for i in range(num_blobs)]

    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.return_value = iter(blob_list)

    container_client.download_blob.side_effect = exception

    # Mock for the service client
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client


    get_blobs(
        container_name=None,
        service_client=service_client,
        md5_hash=None,
        min_datetime=None,
        max_datetime=None,
        desired_datetime=None,
        tag='storage_tag',
        reparse=True,
        json_file=False,
        json_inline=False,
        blob_extension=None,
    )
    assert mock_logging.call_count == num_blobs
    mock_update.assert_not_called()


@pytest.mark.parametrize('exception', [json.JSONDecodeError, TypeError, KeyError])
@patch('azure_services.storage.logging.error')
@patch('azure_services.storage.loads')
@patch('azure_services.storage.update_row_object')
def test_get_blobs_json_ko(mock_update, mock_loads, mock_logging, exception):
    """Test get_blobs_list_blobs handles exceptions from 'json.loads'."""
    num_blobs = 5
    blob_list = [create_mocked_blob(blob_name=f'blob_{i}') for i in range(num_blobs)]

    container_client = MagicMock(name='container_client_mock')
    container_client.list_blobs.return_value = iter(blob_list)

    data_mock = MagicMock(name='data_mock')
    data_mock.readall.return_value = 'invalid'
    container_client.download_blob.return_value = data_mock

    # Mock for the service client
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container_client

    mock_loads.side_effect = exception

    get_blobs(
        container_name=None,
        service_client=service_client,
        md5_hash=None,
        min_datetime=None,
        max_datetime=None,
        desired_datetime=None,
        tag='storage_tag',
        reparse=True,
        json_file=True,
        json_inline=False,
        blob_extension=None,
    )
    assert mock_logging.call_count == num_blobs
    mock_update.assert_not_called()
