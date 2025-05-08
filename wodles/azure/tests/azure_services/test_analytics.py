#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import json
import sys
from hashlib import md5
from os.path import abspath, dirname, join, realpath
from unittest.mock import MagicMock, call, patch

import pytest
from dateutil.parser import parse
from requests import HTTPError

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_services.analytics import (
    URL_ANALYTICS,
    build_log_analytics_query,
    get_log_analytics_events,
    get_time_position,
    iter_log_analytics_events,
    start_log_analytics,
)
from db import orm

PAST_DATE = '2022-01-01T12:00:00.000000Z'
PRESENT_DATE = '2022-06-15T12:00:00.000000Z'
FUTURE_DATE = '2022-12-31T12:00:00.000000Z'

TEST_DATA_PATH = join(dirname(dirname(realpath(__file__))), 'data')


@pytest.mark.parametrize(
    'auth_path, la_id, key, offset, query, workspace, reparse, tag',
    [
        (None, 'client', 'secret', '1d', 'query', 'workspace', False, 'la_tag'),
        ('/var/ossec/', None, None, '', '', '', False, ''),
    ],
)
@patch('azure_services.analytics.get_log_analytics_events')
@patch('azure_services.analytics.build_log_analytics_query')
@patch('azure_services.analytics.get_token')
@patch('azure_services.analytics.read_auth_file')
def test_start_log_analytics(
    mock_auth,
    mock_token,
    mock_build,
    mock_get_logs,
    auth_path,
    la_id,
    key,
    offset,
    query,
    workspace,
    reparse,
    tag,
):
    """Test start_log_analytics reads the credentials, obtains a token, builds the query using that token and attempts
    to get the log analytics logs."""
    tenant = 'tenant'
    args = MagicMock(
        la_tenant_domain=tenant,
        la_auth_path=auth_path,
        la_id=la_id,
        la_key=key,
        la_query=query,
        la_time_offset=offset,
        workspace=workspace,
        reparse=reparse,
        la_tag=tag,
    )

    mock_auth.return_value = credentials = ('client', 'secret')
    mock_token.return_value = token = 'token'
    mock_build.return_value = body = 'body'
    start_log_analytics(args)

    if auth_path:
        mock_auth.assert_called_with(auth_path=auth_path, fields=('application_id', 'application_key'))
    else:
        mock_auth.assert_not_called()

    # Check a token is requested using the right parameters
    mock_token.assert_called_with(
        client_id=credentials[0],
        secret=credentials[1],
        domain=tenant,
        scope=f'{URL_ANALYTICS}/.default',
    )
    md5_hash = md5(query.encode()).hexdigest()
    mock_build.assert_called_with(query=query, offset=offset, reparse=reparse, md5_hash=md5_hash)
    mock_get_logs.assert_called_with(
        url=f'{URL_ANALYTICS}/v1/workspaces/{workspace}/query',
        body=body,
        headers={'Authorization': f'Bearer {token}'},
        md5_hash=md5_hash,
        query=query,
        tag=tag,
    )


@patch('azure_utils.logging.error')
@patch('azure_services.analytics.get_log_analytics_events', side_effect=HTTPError)
@patch('azure_services.analytics.build_log_analytics_query')
@patch('azure_services.analytics.get_token')
@patch('azure_services.analytics.read_auth_file', return_value=('client', 'secret'))
def test_start_log_analytics_ko(mock_auth, mock_token, mock_build, mock_get_logs, mock_logging):
    """Test start_log_analytics shows error message if get_log_analytics_events returns an HTTP error."""
    args = MagicMock(
        la_tenant_domain='test',
        la_id='test',
        la_key='test',
        la_query='test',
        la_time_offset='',
        workspace='test',
    )
    start_log_analytics(args)
    mock_logging.assert_called_once()


@patch('azure_utils.logging.error')
def test_start_log_analytics_ko_credentials(mock_logging):
    """Test start_log_analytics stops its execution if no valid credentials are provided."""
    args = MagicMock(la_tenant_domain=None)
    with pytest.raises(SystemExit) as err:
        start_log_analytics(args)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'min_date, max_date, desired_date, reparse',
    [
        (PRESENT_DATE, FUTURE_DATE, PAST_DATE, False),
        (PAST_DATE, PRESENT_DATE, FUTURE_DATE, False),
        (PAST_DATE, FUTURE_DATE, PRESENT_DATE, False),
        (PAST_DATE, PAST_DATE, PRESENT_DATE, True),
    ],
)
@patch('azure_services.analytics.offset_to_datetime')
@patch('azure_services.analytics.create_new_row')
@patch('db.orm.get_row', return_value=None)
def test_build_log_analytics_query(mock_get, mock_create, mock_datetime, min_date, max_date, desired_date, reparse):
    """Test build_log_analytics_query creates the required query with the expected "TimeGenerated" filter values."""
    la_query = 'test_query'
    mock_create.return_value = MagicMock(min_processed_date=min_date, max_processed_date=max_date)
    mock_datetime.return_value = parse(desired_date)
    result = build_log_analytics_query(query=la_query, offset=desired_date, md5_hash='', reparse=reparse)
    mock_get.assert_called_with(orm.LogAnalytics, md5='')
    mock_create.assert_called_with(
        table=orm.LogAnalytics,
        query=la_query,
        md5_hash='',
        offset=desired_date,
    )

    if reparse:
        expected_str = f'TimeGenerated >= datetime({desired_date})'
    else:
        if parse(desired_date) < parse(min_date, fuzzy=True):
            expected_str = (
                f'( TimeGenerated < datetime({min_date}) and TimeGenerated >= datetime({desired_date})) '
                f'or ( TimeGenerated > datetime({max_date}))'
            )
        elif parse(desired_date) > parse(max_date, fuzzy=True):
            expected_str = f'TimeGenerated >= datetime({desired_date})'
        else:
            expected_str = f'TimeGenerated > datetime({max_date})'

    assert expected_str in result['query']


@patch('azure_utils.logging.error')
@patch('db.orm.get_row', side_effect=orm.AzureORMError)
def test_build_log_analytics_query_ko(mock_get, mock_logging):
    """Test build_log_analytics_query handles ORM exceptions."""
    with pytest.raises(SystemExit) as err:
        build_log_analytics_query(query='', offset='', reparse=False, md5_hash='')
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'file, time_position',
    [
        ('log_analytics_events', 0),
        ('log_analytics_events', None),
        ('log_analytics_events_no_results', None),
        ('log_analytics_events_empty', None),
    ],
)
@patch('azure_utils.logging.error')
@patch('azure_services.analytics.update_row_object')
@patch('azure_services.analytics.iter_log_analytics_events')
@patch('azure_services.analytics.get_time_position')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events(mock_get, mock_position, mock_iter, mock_update, mock_logging, file, time_position):
    """Test get_log_analytics_events gets the logs, process the response and iterate the events if the 'TimeGenerated'
    field was present."""
    la_query = 'test_query'
    m = MagicMock(status_code=200)
    with open(join(TEST_DATA_PATH, file)) as f:
        try:
            events = json.loads(f.read())
            m.json.return_value = events
            columns = events['tables'][0]['columns']
            rows = events['tables'][0]['rows']
        except (KeyError, json.decoder.JSONDecodeError):
            m.json.return_value = {}
            columns = None
            rows = None

    mock_get.return_value = m
    mock_position.return_value = time_position
    url = 'url'
    body = 'body'
    headers = 'headers'
    tag = 'test'
    tenant = 'tenant'
    get_log_analytics_events(url=url, body=body, headers=headers, md5_hash='', query=la_query, tag=tag, tenant=tenant)
    mock_get.assert_called_with(url, params=body, headers=headers, timeout=10)
    if rows is None or (len(rows) > 0 and time_position is None):
        mock_logging.assert_called_once()
    elif len(rows) == 0:
        mock_position.assert_not_called()
        mock_iter.assert_not_called()
        mock_update.assert_not_called()
    else:
        mock_position.assert_called_with(columns)
        mock_iter.assert_called_with(columns, rows, tag)
        mock_update.assert_called_once()


@patch('azure_services.analytics.get')
def test_get_log_analytics_events_error_responses(mock_get):
    """Test get_log_analytics_events handles invalid responses from the request module."""
    la_query = 'test_query'
    response_mock = MagicMock(status_code=400)
    mock_get.return_value = response_mock
    get_log_analytics_events(url=None, body=None, headers=None, md5_hash=None, query=la_query, tag='', tenant='tenant')
    response_mock.raise_for_status.assert_called_once()


@pytest.mark.parametrize(
    'columns, position',
    [
        ([{'name': 'TimeGenerated'}, {'name': 'test'}], 0),
        ([{'name': 'test'}, {'name': 'TimeGenerated'}], 1),
        ([{'name': 'test'}, {'name': 'test'}], None),
    ],
)
def test_get_time_position(columns, position):
    """Test get_time_position returns the position of the 'TimeGenerated' field."""
    result = get_time_position(columns)
    assert result == position


@patch('azure_services.analytics.send_message')
def test_iter_log_analytics_events(mock_send):
    """Test iter_log_analytics_events iterates through the columns and rows to build the events and send them to the
    socket."""
    la_tag = 'tag'
    with open(join(TEST_DATA_PATH, 'log_analytics_events')) as f:
        events = json.loads(f.read())
        columns = events['tables'][0]['columns']
        rows = events['tables'][0]['rows']
    iter_log_analytics_events(columns=columns, rows=rows, tag=la_tag)
    keys = [col['name'] for col in columns]
    tag_keys = ['azure_tag', 'log_analytics_tag']
    tag_values = ['azure-log-analytics', la_tag]
    expected_calls = [call(json.dumps({k: v for k, v in zip(keys + tag_keys, values + tag_values)})) for values in rows]
    mock_send.assert_has_calls(expected_calls)
