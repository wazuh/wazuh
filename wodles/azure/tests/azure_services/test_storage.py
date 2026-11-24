#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from hashlib import md5
from os.path import abspath, dirname, join, realpath
from typing import Optional
from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest
import pytz
from azure.core.exceptions import AzureError, ClientAuthenticationError, HttpResponseError, ResourceModifiedError
from azure.storage.blob import BlobType
from dateutil.parser import parse
from freezegun import freeze_time
from sqlalchemy import create_engine

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_utils import DEFAULT_PATH_MAX_FOLDERS
from azure_services.storage import download_blob, expand_prefix, get_blobs, \
    get_folder_date, get_prefix_date_fields, is_nested, render_prefix, start_storage
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
        prefix='prefix/',
        blobs='.json',
    )
    mock_create.return_value = MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE)
    mock_auth.return_value = (name, key)
    listed_container = MagicMock()
    listed_container.name = 'listed_container'
    m = MagicMock()
    m.list_containers.return_value = [listed_container]
    mock_blob.return_value = m
    start_storage(args)

    if auth_path:
        mock_auth.assert_called_with(auth_path=auth_path, fields=('account_name', 'account_key'))
    else:
        mock_auth.assert_not_called()

    container = listed_container.name if container_name == '*' else container_name
    md5_hash = orm.create_pk(account=name, container=container, prefix='prefix/', blobs='.json')
    mock_blob.assert_called_with(
        account_url=f'https://{name}.blob.core.windows.net/',
        credential={'account_name': name, 'account_key': key}
    )
    mock_get_row.assert_called_with(orm.Storage, md5=md5_hash)
    mock_create.assert_called_with(table=orm.Storage, query=container, md5_hash=md5_hash, offset=offset)
    mock_get_blobs.assert_called_once()
    assert mock_get_blobs.call_args.kwargs['md5_hash'] == md5_hash
    assert mock_get_blobs.call_args.kwargs['account_md5_hash'] == md5(name.encode()).hexdigest()


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
        prefix=None,
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
@patch('azure_services.storage.send_message')
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
        account_md5_hash=md5_hash,
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
        [
            call(blob, offset=None, encoding='UTF-8', max_concurrency=2)
            for blob in blob_list if extension and extension in blob.name
        ]
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
        account_md5_hash=md5_hash,
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
@patch('azure_services.storage.send_message')
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
        account_md5_hash=md5_hash,
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
        [call(blob, offset=None, encoding='UTF-8', max_concurrency=2) for blob in blob_list if prefix in blob.name]
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
            account_md5_hash=None,
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
        account_md5_hash=None,
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
        account_md5_hash=None,
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

@ pytest.mark.parametrize("retries", [1, 3])
def test_download_blob_success(retries):
    """Test download_blob download blob as expected."""
    container = MagicMock()
    blob = create_mocked_blob("blob1")
    data_mock = MagicMock(name='data_mock', size=7)
    data_mock.readall.return_value = 'content'

    container.download_blob.return_value = data_mock

    result = download_blob(container, blob, number_of_retries=retries)
    assert result == ('content', 7)
    container.download_blob.assert_called_once_with(blob, offset=None, encoding="UTF-8", max_concurrency=2)


def test_download_blob_retry_then_success():
    """Test download_blob retries download after a ResourceModifiedError is raised."""
    container = MagicMock()
    blob = create_mocked_blob("blob2")
    data_mock = MagicMock(name='data_mock', size=7)
    data_mock.readall.return_value = 'content'

    container.download_blob.side_effect = [ResourceModifiedError("mod"), data_mock]

    result = download_blob(container, blob, number_of_retries=3)
    assert result == ('content', 7)
    assert container.download_blob.call_count == 2


@pytest.mark.parametrize("exc", [ValueError("bad"), AzureError("az"), HttpResponseError("http")])
def test_download_blob_fails_immediately_on_other_exceptions(exc):
    """Test download_blob handle and raise an exception on other exceptions."""
    container = MagicMock()
    blob = create_mocked_blob("blob3")

    container.download_blob.side_effect = exc

    with pytest.raises(type(exc)):
        download_blob(container, blob, number_of_retries=5)
    container.download_blob.assert_called_once()


def test_download_blob_retry_when_modified_while_reading():
    """Test download_blob retries the download if the blob changes while its contents are read."""
    container = MagicMock()
    blob = create_mocked_blob("blob4")
    modified = MagicMock(name='modified_mock')
    modified.readall.side_effect = ResourceModifiedError("mod")
    data_mock = MagicMock(name='data_mock', size=7)
    data_mock.readall.return_value = 'content'

    container.download_blob.side_effect = [modified, data_mock]

    assert download_blob(container, blob, number_of_retries=3) == ('content', 7)
    assert container.download_blob.call_count == 2


def test_download_blob_retry_then_fail():
    """Test download_blob raises exception after multiple retries."""
    container = MagicMock()
    blob = create_mocked_blob("blob2")
    data_mock = object()

    container.download_blob.side_effect = [ResourceModifiedError("mod"), ResourceModifiedError("mod"),
                                           ResourceModifiedError("mod")]

    with pytest.raises(ResourceModifiedError):
        result = download_blob(container, blob, number_of_retries=3)
    assert container.download_blob.call_count == 3


HOURLY_BLOB = 'tenantId=00000000-0000-0000-0000-000000000000/y=2026/m=10/d=07/h=08/m=00/PT1H.json'


class FakeContainer:
    """In-memory container that serves its blobs like Azure Storage does: every write updates the blob size and
    last modified time, append blobs only grow, and a blob created again gets a new creation time."""

    def __init__(self):
        self.blobs = {}
        self.downloads = []
        self.failed_reads = 0
        self.listed_prefixes = []
        self.clock = datetime.now(pytz.UTC) - timedelta(hours=1)

    def write(self, name: str, content: str, blob_type: str = BlobType.APPENDBLOB, append: bool = True,
              keep_creation_time: bool = False):
        self.clock += timedelta(minutes=1)
        blob = self.blobs.get(name)
        if append and blob:
            blob.update(data=blob['data'] + content.encode(), last_modified=self.clock)
        else:
            creation_time = blob['creation_time'] if keep_creation_time and blob else self.clock
            self.blobs[name] = {
                'data': content.encode(), 'type': blob_type, 'creation_time': creation_time, 'last_modified': self.clock
            }

    def exists(self):
        return True

    def list_blobs(self, name_starts_with=None):
        self.listed_prefixes.append(name_starts_with)
        listed = []
        for name, blob in self.blobs.items():
            if name_starts_with and not name.startswith(name_starts_with):
                continue
            item = create_mocked_blob(name, last_modified=blob['last_modified'], content_length=len(blob['data']))
            item.blob_type = blob['type']
            item.creation_time = blob['creation_time']
            listed.append(item)
        return iter(listed)

    def download_blob(self, blob, offset=None, encoding=None, max_concurrency=1):
        self.downloads.append(offset)
        data = self.blobs[blob.name]['data']
        if offset is not None and offset >= len(data):
            raise HttpResponseError('The range specified is invalid for the current size of the resource.')
        data = data[offset or 0:]
        downloader = MagicMock(name='downloader_mock', size=len(data))
        if self.failed_reads:
            # The blob changes while its chunks are downloaded
            self.failed_reads -= 1
            downloader.readall.side_effect = ResourceModifiedError('The condition specified was not met.')
        else:
            downloader.readall.return_value = data.decode(encoding) if encoding else data
        return downloader


def audit_records(*event_ids: str) -> str:
    """Return Entra ID audit log records, one JSON object per line, as written to the hourly blobs."""
    return ''.join(
        json.dumps({'operationName': 'Add application', 'category': 'AuditLogs', 'properties': {'id': event_id}}) + '\n'
        for event_id in event_ids
    )


def run_storage(container: FakeContainer, json_inline: bool = True, json_file: bool = False,
                reparse: bool = False, container_name: str = 'insights-logs-auditlogs', prefix: str = None,
                blobs: str = '.json', time_offset: Optional[str] = '24h', path_lookback: timedelta = timedelta(days=1),
                path_max_folders: int = DEFAULT_PATH_MAX_FOLDERS) -> list:
    """Run the Storage integration once against the given container and return the ids of the events sent."""
    args = MagicMock(
        storage_auth_path='auth_path',
        container=container_name,
        storage_time_offset=time_offset,
        storage_path_lookback=path_lookback,
        storage_path_max_folders=path_max_folders,
        prefix=prefix,
        storage_tag='tag',
        reparse=reparse,
        json_file=json_file,
        json_inline=json_inline,
        blobs=blobs,
    )
    service_client = MagicMock(name='service_client_mock')
    service_client.get_container_client.return_value = container
    with patch('azure_services.storage.read_auth_file', return_value=('account', 'key')), \
            patch('azure_services.storage.BlobServiceClient', return_value=service_client), \
            patch('azure_services.storage.send_message') as mock_send:
        start_storage(args)
    return [event_id for c in mock_send.call_args_list for event_id in re.findall(r'"id": "(\w+)"', c.args[0])]


@pytest.fixture
def in_memory_db():
    """Point the ORM to an empty in-memory database during the test."""
    engine = create_engine('sqlite:///', echo=False)
    session = orm.sessionmaker(bind=engine)()
    with patch.object(orm, 'engine', engine), patch.object(orm, 'session', session):
        orm.create_db()
        yield
    session.close()


@pytest.mark.parametrize('json_inline', [True, False])
def test_append_blob_only_new_records_are_sent(in_memory_db, json_inline):
    """Test records appended to a blob after a run are the only ones sent by the next run."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1'))
    sent_per_run = [run_storage(container, json_inline=json_inline)]
    container.write(HOURLY_BLOB, audit_records('E2'))
    sent_per_run.append(run_storage(container, json_inline=json_inline))
    container.write(HOURLY_BLOB, audit_records('E3'))
    sent_per_run.append(run_storage(container, json_inline=json_inline))
    sent_per_run.append(run_storage(container, json_inline=json_inline))

    assert sent_per_run == [['E1'], ['E2'], ['E3'], []]


def test_append_blob_reparse_sends_all_records(in_memory_db):
    """Test the reparse option sends every record of an append blob again."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1'))
    run_storage(container)
    container.write(HOURLY_BLOB, audit_records('E2'))

    assert run_storage(container, reparse=True) == ['E1', 'E2']


@pytest.mark.parametrize('new_events', [['E9'], ['E7', 'E8', 'E9'], ['E6', 'E7', 'E8', 'E9']])
def test_append_blob_created_again_is_read_from_the_start(in_memory_db, new_events):
    """Test a blob deleted and created again with the same name is read from its start, whatever its new size."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1', 'E2', 'E3'))
    run_storage(container)
    container.write(HOURLY_BLOB, audit_records(*new_events), append=False)

    assert run_storage(container) == new_events


def test_append_blob_smaller_than_its_offset_is_read_from_the_start(in_memory_db):
    """Test a blob replaced with less data than already processed is read from its start even if it keeps its
    creation time."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1', 'E2', 'E3'))
    run_storage(container)
    container.write(HOURLY_BLOB, audit_records('E9'), append=False, keep_creation_time=True)

    assert run_storage(container) == ['E9']


def test_blob_modified_while_downloading_does_not_move_the_bookmark(in_memory_db):
    """Test a blob that keeps changing while it is downloaded doesn't move the bookmark, so the next run can send it."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1'))
    container.failed_reads = 3

    assert run_storage(container) == []
    assert run_storage(container) == ['E1']


def test_append_blob_offset_removed_with_the_blob(in_memory_db):
    """Test the offset of an append blob is removed once the blob is no longer in the container."""
    container = FakeContainer()
    next_hour_blob = HOURLY_BLOB.replace('/h=08/', '/h=09/')
    container.write(HOURLY_BLOB, audit_records('E1'))
    container.write(next_hour_blob, audit_records('E2'))
    run_storage(container)
    del container.blobs[HOURLY_BLOB]
    run_storage(container)

    assert [row.blob for row in orm.get_all_rows(table=orm.StorageBlobOffset)] == [next_hour_blob]


def test_block_blob_replaced_is_sent_again(in_memory_db):
    """Test a block blob replaced with new content is sent in full, as block blobs are not appended to."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1'), blob_type=BlobType.BLOCKBLOB)
    run_storage(container)
    container.write(HOURLY_BLOB, audit_records('E1', 'E2'), blob_type=BlobType.BLOCKBLOB, append=False)

    assert run_storage(container) == ['E1', 'E2']


def test_append_blob_json_file_is_read_whole(in_memory_db):
    """Test blobs holding a single JSON document are always downloaded whole, as they cannot be parsed in parts."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, json.dumps({'records': [{'properties': {'id': 'E1'}}]}))
    assert run_storage(container, json_inline=False, json_file=True) == ['E1']
    container.write(HOURLY_BLOB, '\n')
    run_storage(container, json_inline=False, json_file=True)

    assert container.downloads == [None, None]


@pytest.mark.parametrize('blob_type', [BlobType.APPENDBLOB, BlobType.BLOCKBLOB])
def test_containers_of_the_same_account_keep_their_own_bookmark(in_memory_db, blob_type):
    """Test the blobs of a container are not skipped because another container of the same storage account sent
    newer ones first."""
    sign_in_logs, audit_logs = FakeContainer(), FakeContainer()
    sign_in_logs.write(HOURLY_BLOB, audit_records('S1'), blob_type=blob_type)
    audit_logs.clock = sign_in_logs.clock
    audit_logs.write(HOURLY_BLOB, audit_records('A1'), blob_type=blob_type)

    assert run_storage(audit_logs, container_name='insights-logs-auditlogs') == ['A1']
    assert run_storage(sign_in_logs, container_name='insights-logs-signinlogs') == ['S1']


@pytest.mark.parametrize('first, second', [
    ({'prefix': 'access/', 'blobs': '.json'}, {'prefix': 'firewall/', 'blobs': '.json'}),
    ({'prefix': None, 'blobs': '.json'}, {'prefix': None, 'blobs': '.log'}),
], ids=['path', 'blobs'])
def test_blocks_of_a_container_with_other_filters_keep_their_own_bookmark(in_memory_db, first, second):
    """Test the blobs of a container are not skipped because another block of the same container, with another path
    or blob extension, sent newer ones first."""
    container = FakeContainer()
    container.write(f"{second['prefix'] or ''}PT1H{second['blobs']}", audit_records('S1'))
    container.write(f"{first['prefix'] or ''}PT1H{first['blobs']}", audit_records('F1'))

    assert run_storage(container, **first) == ['F1']
    assert run_storage(container, **second) == ['S1']


def test_append_blob_offsets_kept_after_upgrading(in_memory_db):
    """Test append blobs processed by previous versions, which stored their offsets under the storage account, only
    send what was appended since."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, audit_records('E1'))
    blob = container.blobs[HOURLY_BLOB]
    orm.set_blob_offset(md5=md5(b'account').hexdigest(), container='insights-logs-auditlogs', blob=HOURLY_BLOB,
                        creation_time=str(blob['creation_time']), processed_bytes=len(blob['data']))
    container.write(HOURLY_BLOB, audit_records('E2'))

    assert run_storage(container) == ['E2']


def test_json_file_records_that_are_not_objects_are_skipped(in_memory_db):
    """Test the records of a JSON file that are not objects are skipped with a single warning, and the rest of the
    blob is sent once."""
    container = FakeContainer()
    records = [{'properties': {'id': 'E1'}}, 'E2', 3, None, ['E4'], {'properties': {'id': 'E5'}}]
    container.write(HOURLY_BLOB, json.dumps({'records': records}))
    container.write(HOURLY_BLOB.replace('/h=08/', '/h=09/'), json.dumps({'records': [{'properties': {'id': 'E6'}}]}))

    with patch('azure_services.storage.logging.warning') as mock_warning:
        assert run_storage(container, json_inline=False, json_file=True) == ['E1', 'E5', 'E6']
    mock_warning.assert_called_once_with(
        f'Storage: Skipped records of the blob "{HOURLY_BLOB}" that are not JSON objects: 4.'
    )
    assert run_storage(container, json_inline=False, json_file=True) == []


@pytest.mark.parametrize('records', [{'properties': {'id': 'E1'}}, 'E1', 1, None])
def test_json_file_records_that_are_not_a_list_skip_the_blob(in_memory_db, records):
    """Test a JSON file whose records are not a list is skipped without stopping the blobs that follow."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, json.dumps({'records': records}))
    container.write(HOURLY_BLOB.replace('/h=08/', '/h=09/'), json.dumps({'records': [{'properties': {'id': 'E2'}}]}))

    assert run_storage(container, json_inline=False, json_file=True) == ['E2']


def test_json_file_records_that_are_not_a_list_do_not_move_the_bookmark(in_memory_db):
    """Test a JSON file whose records are not a list is not marked as processed."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, json.dumps({'records': 'E1'}))
    run_storage(container, json_inline=False, json_file=True)
    run_storage(container, json_inline=False, json_file=True)

    assert container.downloads == [None, None]


@pytest.mark.parametrize('contents', [
    '{"records": ' + '[' * 5000 + ']' * 5000 + '}',
    '{"records": [{"properties": {"id": "E1"}, "value": ' + '9' * 5000 + '}]}',
], ids=['nested_too_deeply', 'integer_too_long'])
def test_json_file_that_cannot_be_parsed_skips_the_blob(in_memory_db, contents):
    """Test a JSON file that cannot be parsed is skipped without stopping the blobs that follow."""
    container = FakeContainer()
    container.write(HOURLY_BLOB, contents)
    container.write(HOURLY_BLOB.replace('/h=08/', '/h=09/'), json.dumps({'records': [{'properties': {'id': 'E2'}}]}))

    assert run_storage(container, json_inline=False, json_file=True) == ['E2']


NOW = datetime(2026, 11, 21, 11, 15, tzinfo=timezone.utc)


def frozen_now(now: datetime = NOW):
    """Freeze the current date, so the date folders listed don't depend on when the test runs."""
    return freeze_time(now)


@pytest.mark.parametrize('prefix, fields', [
    (None, set()),
    ('logs/', set()),
    ('%Y%m%d/', {'Y', 'm', 'd'}),
    ('y=%Y/m=%m/d=%d/h=%H/m=00/', {'Y', 'm', 'd', 'H'}),
    ('%y/%j/', {'y', 'j'}),
    ('exports%20raw/%M/%%/', set()),
    ('literal%%Y/%d/', {'d'}),
])
def test_get_prefix_date_fields(prefix, fields):
    """Test only the supported date fields of a prefix are found, any other '%' being part of the name."""
    assert get_prefix_date_fields(prefix) == fields


@pytest.mark.parametrize('prefix, rendered', [
    ('%Y%m%d/', '20261121/'),
    ('y=%Y/m=%m/d=%d/h=%H/m=00/', 'y=2026/m=11/d=21/h=11/m=00/'),
    ('100%/%y/%j/%20/%M/', '100%/26/325/%20/%M/'),
    ('literal%%Y/%d/', 'literal%%Y/21/'),
])
def test_render_prefix(prefix, rendered):
    """Test only the supported date fields of a prefix are replaced."""
    assert render_prefix(prefix, NOW) == rendered


@pytest.mark.parametrize('prefix', [None, 'logs/', 'exports%20raw/%%/', 'literal%%Y/'])
def test_expand_prefix_without_date_fields(prefix):
    """Test a prefix without date fields is listed as it is."""
    assert expand_prefix(prefix, NOW - timedelta(days=30)) == [prefix]


@pytest.mark.parametrize('prefix, since, expected', [
    ('%Y%m%d/', '2026-11-20T10:00:00Z', ['20261119/', '20261120/', '20261121/']),
    ('d=%d/h=%H/', '2026-11-21T09:30:00', [f'd={d}/h={h:02d}/' for d, h in [(20, 9)] + [(20, h) for h in range(10, 24)]
                                           + [(21, h) for h in range(0, 12)]]),
    ('%Y/%m/', '2026-11-01T00:00:00Z', ['2026/10/', '2026/11/']),
    ('%Y%m%d/', '2026-11-25T00:00:00Z', ['20261121/']),
], ids=['daily', 'hourly_without_time_zone', 'monthly', 'since_the_future'])
def test_expand_prefix(prefix, since, expected):
    """Test a prefix with date fields expands to the folders from the default lookback, one day, before the given
    date until now."""
    with frozen_now():
        assert expand_prefix(prefix, parse(since)) == expected


@pytest.mark.parametrize('prefix, days, expected_length, last', [
    ('%Y%m%d/h=%H/', 365, DEFAULT_PATH_MAX_FOLDERS, '20261121/h=11/'),
    ('%Y%m%d/', 3650, DEFAULT_PATH_MAX_FOLDERS, '20261121/'),
])
@patch('azure_services.storage.logging.warning')
def test_expand_prefix_lists_a_limited_number_of_folders(mock_warning, prefix, days, expected_length, last):
    """Test a long time window lists only the most recent folders and warns about it."""
    with frozen_now():
        prefixes = expand_prefix(prefix, NOW - timedelta(days=days))

    assert len(prefixes) == expected_length
    assert prefixes[-1] == last
    mock_warning.assert_called_once()


@patch('azure_services.storage.logging.warning')
def test_expand_prefix_coarse_folders_are_not_limited_by_their_days(mock_warning):
    """Test monthly folders over a window longer than the limit in days are all listed."""
    with frozen_now():
        prefixes = expand_prefix('%Y/%m/', NOW - timedelta(days=1200))

    assert prefixes[0] == '2023/08/'
    assert len(prefixes) == 40
    mock_warning.assert_not_called()


@pytest.mark.parametrize('blob_name, prefix, nested', [
    ('logs/blob.json', 'logs/', False),
    ('logs/blob.json', 'logs', False),
    ('logs/day/blob.json', 'logs/', True),
    ('a/b/c/blob.json', 'a/b/c/', False),
    ('a/b/c/d/blob.json', 'a/b/c/', True),
    ('20261121/blob.log.gz', '2026', False),
    ('logs/day/blob.json', 'logs', True),
    ('logs/2026/11/24/blob.json', 'logs/2026/11/24', False),
    ('logs/2026/11/24/h/blob.json', 'logs/2026/11/24', True),
])
def test_is_nested(blob_name, prefix, nested):
    """Test a blob is nested only when it is under a subfolder of the folder the prefix points to, with or without
    the trailing slash."""
    assert is_nested(blob_name, prefix) == nested


@freeze_time(NOW)
def test_prefix_with_date_fields_lists_only_the_folders_in_the_time_window(in_memory_db):
    """Test a prefix with date fields lists the folders from one day before the time offset, not the whole
    container."""
    container = FakeContainer()
    for days, event_id in [(3, 'OLD'), (1, 'E1'), (0, 'E2')]:
        container.write(f'{NOW - timedelta(days=days):%Y%m%d}/batch_{event_id}.json', audit_records(event_id))

    assert run_storage(container, prefix='%Y%m%d/') == ['E1', 'E2']
    assert container.listed_prefixes == ['20261119/', '20261120/', '20261121/']


@freeze_time(NOW)
def test_prefix_with_hourly_date_fields_sends_blobs_nested_like_azure_diagnostic_settings(in_memory_db):
    """Test a prefix pointing to the hourly folders of Azure diagnostic settings exports sends their blobs."""
    container = FakeContainer()
    template = 'resourceId=/SUBSCRIPTIONS/0000/y=%Y/m=%m/d=%d/h=%H/m=00/'
    container.write(f'{NOW - timedelta(hours=50):{template}}PT1H.json', audit_records('OLD'))
    container.write(f'{NOW - timedelta(hours=1):{template}}PT1H.json', audit_records('E1'))
    container.write(f'{NOW:{template}}PT1H.json', audit_records('E2'))

    assert run_storage(container, prefix=template) == ['E1', 'E2']
    assert len(container.listed_prefixes) == 49


def test_prefix_with_date_fields_sends_late_appends_to_older_folders(in_memory_db):
    """Test records appended to the blob of an earlier hour after a run are sent, without a time offset."""
    template = 'y=%Y/m=%m/d=%d/h=%H/m=00/'
    earlier_hour = f'{NOW - timedelta(hours=3):{template}}PT1H.json'
    with frozen_now():
        container = FakeContainer()
        container.write(earlier_hour, audit_records('E1'))
        container.write(f'{NOW:{template}}PT1H.json', audit_records('E2'))
        assert run_storage(container, prefix=template, time_offset=None) == ['E1', 'E2']
        container.write(earlier_hour, audit_records('LATE'))
        assert run_storage(container, prefix=template, time_offset=None) == ['LATE']


def test_prefix_with_literal_percent_is_listed_as_it_is(in_memory_db):
    """Test a prefix with a '%' that is not a date field keeps working as a plain prefix."""
    container = FakeContainer()
    container.write('exports%20raw/batch.json', audit_records('E1'))

    assert run_storage(container, prefix='exports%20raw/') == ['E1']
    assert container.listed_prefixes == ['exports%20raw/']


def test_prefix_with_several_folders_sends_the_blobs_directly_under_it(in_memory_db):
    """Test a prefix of several folders sends the blobs right under it and skips the ones in its subfolders."""
    container = FakeContainer()
    prefix = 'resourceId=/SUBSCRIPTIONS/0000/'
    container.write(f'{prefix}PT1H.json', audit_records('E1'))
    container.write(f'{prefix}y=2026/PT1H.json', audit_records('NESTED'))

    assert run_storage(container, prefix=prefix) == ['E1']


def test_prefix_with_date_fields_reparse_lists_since_the_oldest_blob_processed(in_memory_db):
    """Test a reparse lists the folders since the oldest date of the bookmark, not only the time window."""
    template = '%Y%m%d/'
    with frozen_now():
        container = FakeContainer()
        container.clock = NOW - timedelta(days=5)
        container.write(f'{NOW - timedelta(days=5):{template}}batch.json', audit_records('E1'))
        assert run_storage(container, prefix=template, time_offset='7d') == ['E1']
        container.listed_prefixes.clear()
        assert run_storage(container, prefix=template, reparse=True) == ['E1']

    # The bookmark was created with the 7 days offset, and the listing starts one folder before it
    assert container.listed_prefixes[0] == f'{NOW - timedelta(days=8):{template}}'


@freeze_time(NOW)
def test_prefix_with_date_fields_removes_the_offsets_out_of_the_time_window(in_memory_db):
    """Test the offsets of append blobs removed from a listed folder or in a folder older than the time window are
    deleted, and the ones of other paths are kept."""
    container = FakeContainer()
    old_blob = f'{NOW - timedelta(days=5):%Y%m%d}/PT1H.json'
    removed_blob = f'{NOW:%Y%m%d}/removed.json'
    kept_blob = f'{NOW:%Y%m%d}/PT1H.json'
    other_path_blob = 'archive/PT1H.json'
    for name in (old_blob, removed_blob, kept_blob, other_path_blob):
        container.write(name, audit_records('E1'))
    run_storage(container)
    del container.blobs[removed_blob]
    run_storage(container, prefix='%Y%m%d/')

    assert sorted(row.blob for row in orm.get_all_rows(table=orm.StorageBlobOffset)) == \
        sorted([kept_blob, other_path_blob])


@pytest.mark.parametrize('lookback, expected', [
    (timedelta(0), ['20261120/', '20261121/']),
    (timedelta(hours=12), ['20261119/', '20261120/', '20261121/']),
    (timedelta(days=3), ['20261117/', '20261118/', '20261119/', '20261120/', '20261121/']),
])
def test_expand_prefix_with_lookback(lookback, expected):
    """Test the lookback sets how many folders before the one of the given date are listed."""
    with frozen_now():
        assert expand_prefix('%Y%m%d/', parse('2026-11-20T10:00:00Z'), lookback=lookback) == expected


@patch('azure_services.storage.logging.warning')
def test_expand_prefix_with_max_folders(mock_warning):
    """Test the most folders listed can be set, keeping the most recent ones."""
    with frozen_now():
        prefixes = expand_prefix('h=%H/', NOW - timedelta(days=2), max_folders=5)

    assert prefixes == ['h=07/', 'h=08/', 'h=09/', 'h=10/', 'h=11/']
    mock_warning.assert_called_once()


def test_prefix_with_date_fields_late_appends_beyond_the_lookback_are_not_listed(in_memory_db):
    """Test records appended to the blob of an earlier hour are not sent when the hour is older than the lookback.
    Once the hour is out of the time window its offset is removed, so a longer lookback reads the blob from its
    start."""
    template = 'y=%Y/m=%m/d=%d/h=%H/m=00/'
    earlier_hour = f'{NOW - timedelta(hours=3):{template}}PT1H.json'
    with frozen_now():
        container = FakeContainer()
        container.write(earlier_hour, audit_records('E1'))
        container.write(f'{NOW:{template}}PT1H.json', audit_records('E2'))
        assert run_storage(container, prefix=template, time_offset=None, path_lookback=timedelta(0)) == ['E1', 'E2']
        container.write(earlier_hour, audit_records('LATE'))
        assert run_storage(container, prefix=template, time_offset=None, path_lookback=timedelta(0)) == []
        assert run_storage(container, prefix=template, time_offset=None, path_lookback=timedelta(hours=4)) == \
            ['E1', 'LATE']


@pytest.mark.parametrize('prefix, name, date', [
    ('logs/%Y%m%d/', 'logs/20261121/batch.log.gz', datetime(2026, 11, 21, tzinfo=timezone.utc)),
    ('y=%Y/m=%m/d=%d/h=%H/m=00/', 'y=2026/m=11/d=21/h=08/m=00/PT1H.json',
     datetime(2026, 11, 21, 8, tzinfo=timezone.utc)),
    ('%y/%j/', '26/325/x', datetime(2026, 11, 21, tzinfo=timezone.utc)),
    ('%Y/%m/', '2026/11/', datetime(2026, 11, 1, tzinfo=timezone.utc)),
    ('logs/%Y%m%d/', 'other/20261121/batch.log.gz', None),
    ('logs/%Y%m%d/', 'logs/20261341/batch.log.gz', None),
    ('%m/%d/', '11/21/x', None),
    ('%Y/%Y/', '2026/2025/x', None),
    ('logs/%Y%m%d/', 'logs/20261121/sub/batch.log.gz', None),
], ids=['daily', 'hourly', 'day_of_year', 'rendered_prefix', 'other_path', 'invalid_date', 'no_year', 'two_years',
        'nested'])
def test_get_folder_date(prefix, name, date):
    """Test the date of a blob folder is read from the date fields of the prefix."""
    assert get_folder_date(prefix, name) == date


@pytest.mark.parametrize('lookback, max_folders', [
    (timedelta(days=3650), 100000),
    (timedelta(days=999999), 10),
])
def test_expand_prefix_large_limits_do_not_overflow(lookback, max_folders):
    """Test limits that reach dates older than can be represented list the folders from the oldest one."""
    with frozen_now():
        prefixes = expand_prefix('%Y/', NOW, lookback=lookback, max_folders=max_folders)

    assert prefixes[-1] == '2026/'


@freeze_time(NOW)
def test_prefix_with_date_fields_keeps_the_offsets_of_blobs_it_does_not_read(in_memory_db):
    """Test the offsets out of the time window of blobs in a subfolder or with another extension, which other blocks
    of the container can read, are kept."""
    container = FakeContainer()
    old_folder = f'{NOW - timedelta(days=5):%Y%m%d}'
    read_blob, nested_blob, other_extension_blob = \
        f'{old_folder}/PT1H.json', f'{old_folder}/sub/PT1H.json', f'{old_folder}/PT1H.log'
    for name in (read_blob, nested_blob, other_extension_blob):
        container.write(name, audit_records('E1'))
    run_storage(container, blobs='')
    assert len(orm.get_all_rows(table=orm.StorageBlobOffset)) == 3
    run_storage(container, prefix='%Y%m%d/')

    assert sorted(row.blob for row in orm.get_all_rows(table=orm.StorageBlobOffset)) == \
        sorted([nested_blob, other_extension_blob])
