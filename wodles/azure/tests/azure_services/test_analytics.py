#!/usr/bin/env python3
#
# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import json
import sys
from os.path import abspath, dirname, join, realpath
from unittest.mock import MagicMock, call, patch

import pytest
from dateutil.parser import parse
from requests import HTTPError

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_services.analytics import (
    INGESTION_TIME_COLUMN,
    QUERY_TIME_COLUMN,
    URL_ANALYTICS,
    build_log_analytics_query,
    get_log_analytics_events,
    get_time_position,
    iter_log_analytics_events,
    pop_column,
    start_log_analytics,
)
from db import orm
import os
PAST_DATE = '2022-01-01T12:00:00.000000Z'
PRESENT_DATE = '2022-06-15T12:00:00.000000Z'
FUTURE_DATE = '2022-12-31T12:00:00.000000Z'
LAST_INGESTION = '2022-06-15T13:00:00.1234567Z'
LAST_TIME_GENERATED = '2022-06-15T12:59:00.7654321Z'
QUERY_TIME = '2022-06-15T13:00:00Z'

TEST_DATA_PATH = join(dirname(dirname(realpath(__file__))), 'data')


@pytest.mark.parametrize('auth_path, offset, query, workspace, reparse, tag', [
    (os.environ.get('INSTALLDIR', '/var/wazuh-manager'), '1d', 'query', 'workspace', False, 'la_tag')
])
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

    mock_auth.assert_called_with(auth_path=auth_path, fields=('application_id', 'application_key'))

    # Check a token is requested using the right parameters
    mock_token.assert_called_with(
        client_id=credentials[0],
        secret=credentials[1],
        domain=tenant,
        scope=f'{URL_ANALYTICS}/.default',
    )
    md5_hash = orm.create_pk(workspace=workspace, query=query)
    mock_build.assert_called_with(query=query, offset=offset, reparse=reparse, md5_hash=md5_hash)
    mock_get_logs.assert_called_with(
        url=f'{URL_ANALYTICS}/v1/workspaces/{workspace}/query',
        body=body,
        headers={'Authorization': f'Bearer {token}'},
        md5_hash=md5_hash,
        query=query,
        tag=tag,
        tenant=tenant
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
        la_auth_path='test',
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


@patch('azure_utils.logging.error')
def test_start_log_analytics_ko_deprecated_credentials(mock_logging):
    """Test start_log_analytics stops its execution when deprecated credentials are provided instead of auth_path."""
    args = MagicMock(la_tenant_domain='test', la_auth_path=None, la_id='test', la_key='test')
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
@patch('azure_services.analytics.get_ingestion_cursor', return_value=None)
@patch('azure_services.analytics.offset_to_datetime')
@patch('azure_services.analytics.create_new_row')
@patch('db.orm.get_row', return_value=None)
def test_build_log_analytics_query(
    mock_get, mock_create, mock_datetime, mock_ingestion, min_date, max_date, desired_date, reparse
):
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
                f'or ( TimeGenerated > min_of(datetime({max_date}), now()))'
            )
        elif parse(desired_date) > parse(max_date, fuzzy=True):
            expected_str = f'TimeGenerated >= datetime({desired_date})'
        else:
            expected_str = f'TimeGenerated > min_of(datetime({max_date}), now())'

    assert expected_str in result['query']
    assert result['query'].startswith(
        f'{la_query} | extend {INGESTION_TIME_COLUMN} = ingestion_time(), {QUERY_TIME_COLUMN} = now() | where ( '
    )
    assert result['query'].endswith(
        f') and ( isnull({INGESTION_TIME_COLUMN}) or {INGESTION_TIME_COLUMN} <= ago(2m) ) '
        f'| order by {INGESTION_TIME_COLUMN} asc, TimeGenerated asc '
    )
    mock_ingestion.assert_called_with('')


@pytest.mark.parametrize(
    'offset, min_date, desired_date, expected_lower, backfill',
    [
        # The time offset is newer than the lookback from the last ingestion time
        ('1d', PAST_DATE, PRESENT_DATE, PRESENT_DATE, False),
        # Without time offset, the lookback from the last ingestion time applies
        ('', PAST_DATE, None, '2022-06-13T12:00:00.123456Z', False),
        # Records older than the oldest date processed are left to the backfill
        ('', '2022-06-14T00:00:00.000000Z', None, '2022-06-14T00:00:00.000000Z', False),
        # The time offset is older than the oldest record processed
        ('1d', PRESENT_DATE, PAST_DATE, PRESENT_DATE, True),
    ],
)
@patch('azure_services.analytics.get_ingestion_cursor', return_value=(LAST_INGESTION, LAST_TIME_GENERATED))
@patch('azure_services.analytics.offset_to_datetime')
@patch('db.orm.get_row')
def test_build_log_analytics_query_ingestion_time(
    mock_get, mock_datetime, mock_ingestion, offset, min_date, desired_date, expected_lower, backfill
):
    """Test build_log_analytics_query requests the records ingested after the last record processed."""
    mock_get.return_value = MagicMock(min_processed_date=min_date, max_processed_date=PRESENT_DATE)
    mock_datetime.return_value = parse(desired_date) if desired_date else None
    result = build_log_analytics_query(query='test_query', offset=offset, md5_hash='', reparse=False)

    expected_str = (
        f'test_query | extend {INGESTION_TIME_COLUMN} = ingestion_time(), {QUERY_TIME_COLUMN} = now() '
        f'| where ( ( TimeGenerated >= datetime({expected_lower}) and ( '
        f'{INGESTION_TIME_COLUMN} > datetime({LAST_INGESTION}) or '
        f'( {INGESTION_TIME_COLUMN} == datetime({LAST_INGESTION}) and '
        f'TimeGenerated > datetime({LAST_TIME_GENERATED}) ) or '
        f'( isnull({INGESTION_TIME_COLUMN}) and TimeGenerated > min_of(datetime({PRESENT_DATE}), now()) ) ) )'
    )
    if backfill:
        expected_str += f' or ( TimeGenerated < datetime({min_date}) and TimeGenerated >= datetime({desired_date}))'
    expected_str += (
        f' ) and ( isnull({INGESTION_TIME_COLUMN}) or {INGESTION_TIME_COLUMN} <= ago(2m) ) '
        f'| order by {INGESTION_TIME_COLUMN} asc, TimeGenerated asc '
    )
    assert result['query'] == expected_str


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
@patch('azure_services.analytics.update_ingestion_cursor')
@patch('azure_utils.logging.error')
@patch('azure_services.analytics.update_row_object')
@patch('azure_services.analytics.iter_log_analytics_events')
@patch('azure_services.analytics.get_time_position')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events(
    mock_get, mock_position, mock_iter, mock_update, mock_logging, mock_update_ingestion, file, time_position
):
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
        mock_update_ingestion.assert_not_called()
    elif len(rows) == 0:
        mock_position.assert_not_called()
        mock_iter.assert_not_called()
        mock_update.assert_not_called()
        mock_update_ingestion.assert_not_called()
    else:
        mock_position.assert_called_with(columns)
        mock_iter.assert_called_with(columns, rows, tag)
        mock_update.assert_called_once()
        mock_update_ingestion.assert_called_once_with('', [], [row[time_position] for row in rows])


@patch('azure_services.analytics.lower_max_processed_date')
@patch('azure_services.analytics.update_ingestion_cursor')
@patch('azure_services.analytics.update_row_object')
@patch('azure_services.analytics.iter_log_analytics_events')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events_ingestion_time(mock_get, mock_iter, mock_update, mock_update_ingestion, mock_lower):
    """Test get_log_analytics_events removes the columns added by the module from the events and stores the ingestion
    times, and stores the oldest and newest TimeGenerated whatever their order in the results."""
    columns = [
        {'name': 'TimeGenerated'},
        {'name': INGESTION_TIME_COLUMN},
        {'name': 'OperationName'},
        {'name': QUERY_TIME_COLUMN},
    ]
    rows = [
        ['2022-06-15T11:30:00Z', '2022-06-15T11:40:00Z', 'op2', QUERY_TIME],
        ['2022-06-15T11:00:00Z', '2022-06-15T12:00:00.1234567Z', 'op1', QUERY_TIME],
        ['2022-06-15T11:00:00.5Z', '2022-06-15T12:00:00.1234567Z', 'op3', QUERY_TIME],
    ]
    mock_get.return_value = MagicMock(
        status_code=200, json=MagicMock(return_value={'tables': [{'columns': columns, 'rows': rows}]})
    )
    get_log_analytics_events(url='url', body='body', headers='headers', md5_hash='md5', query='q', tag='', tenant='')

    mock_iter.assert_called_once_with(
        [{'name': 'TimeGenerated'}, {'name': 'OperationName'}],
        [['2022-06-15T11:30:00Z', 'op2'], ['2022-06-15T11:00:00Z', 'op1'], ['2022-06-15T11:00:00.5Z', 'op3']],
        '',
    )
    mock_update.assert_called_once_with(
        table=orm.LogAnalytics,
        md5_hash='md5',
        new_min='2022-06-15T11:00:00Z',
        new_max='2022-06-15T11:30:00Z',
        query='q',
    )
    mock_update_ingestion.assert_called_once_with(
        'md5',
        ['2022-06-15T11:40:00Z', '2022-06-15T12:00:00.1234567Z', '2022-06-15T12:00:00.1234567Z'],
        ['2022-06-15T11:30:00Z', '2022-06-15T11:00:00Z', '2022-06-15T11:00:00.5Z'],
    )
    mock_lower.assert_called_once_with(orm.LogAnalytics, 'md5', QUERY_TIME)


@pytest.mark.parametrize(
    'ingestion_times, logged',
    [
        ([None, None], True),
        (['2022-06-15T12:00:00Z', None], False),
        (['2022-06-15T12:00:00Z', '2022-06-15T12:30:00Z'], False),
    ],
)
@patch('azure_utils.logging.debug')
@patch('azure_services.analytics.update_ingestion_cursor')
@patch('azure_services.analytics.update_row_object')
@patch('azure_services.analytics.iter_log_analytics_events')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events_no_ingestion_time(
    mock_get, mock_iter, mock_update, mock_update_ingestion, mock_debug, ingestion_times, logged
):
    """Test get_log_analytics_events logs when no record of the results has an ingestion time."""
    columns = [{'name': 'TimeGenerated'}, {'name': INGESTION_TIME_COLUMN}]
    rows = [['2022-06-15T11:00:00Z', ingestion_times[0]], ['2022-06-15T11:30:00Z', ingestion_times[1]]]
    mock_get.return_value = MagicMock(
        status_code=200, json=MagicMock(return_value={'tables': [{'columns': columns, 'rows': rows}]})
    )
    get_log_analytics_events(url='url', body='body', headers='headers', md5_hash='md5', query='q', tag='', tenant='')

    assert any('have no ingestion time' in str(c) for c in mock_debug.call_args_list) == logged
    mock_update.assert_called_once()


@pytest.mark.parametrize(
    'times, query_time, expected_max',
    [
        (['2022-06-15T11:00:00Z', '2022-06-15T11:30:00Z'], QUERY_TIME, '2022-06-15T11:30:00Z'),
        # A TimeGenerated set after the query ran isn't stored as the newest one
        (['2022-06-15T11:00:00Z', '2022-06-16T11:00:00Z'], QUERY_TIME, QUERY_TIME),
        (['2022-06-15T11:00:00Z', '2022-06-15T13:00:00.0000001Z'], QUERY_TIME, QUERY_TIME),
        (['2022-06-15T11:00:00Z', '2022-06-16T11:00:00Z'], None, '2022-06-16T11:00:00Z'),
    ],
)
@patch('azure_services.analytics.lower_max_processed_date')
@patch('azure_services.analytics.update_ingestion_cursor')
@patch('azure_services.analytics.update_row_object')
@patch('azure_services.analytics.iter_log_analytics_events')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events_query_time(
    mock_get, mock_iter, mock_update, mock_update_ingestion, mock_lower, times, query_time, expected_max
):
    """Test get_log_analytics_events doesn't store a TimeGenerated later than the time the query ran, and lowers a
    stored one to it."""
    columns = [{'name': 'TimeGenerated'}] + ([{'name': QUERY_TIME_COLUMN}] if query_time else [])
    rows = [[time] + ([query_time] if query_time else []) for time in times]
    mock_get.return_value = MagicMock(
        status_code=200, json=MagicMock(return_value={'tables': [{'columns': columns, 'rows': rows}]})
    )
    get_log_analytics_events(url='url', body='body', headers='headers', md5_hash='md5', query='q', tag='', tenant='')

    mock_update.assert_called_once_with(
        table=orm.LogAnalytics, md5_hash='md5', new_min='2022-06-15T11:00:00Z', new_max=expected_max, query='q'
    )
    mock_update_ingestion.assert_called_once_with('md5', [], times)
    if query_time:
        mock_lower.assert_called_once_with(orm.LogAnalytics, 'md5', query_time)
    else:
        mock_lower.assert_not_called()


@pytest.mark.parametrize(
    'columns, rows, name, expected_columns, expected_rows, expected_values',
    [
        (
            [{'name': 'a'}, {'name': INGESTION_TIME_COLUMN}, {'name': 'b'}],
            [[1, 't1', 2], [3, None, 4]],
            INGESTION_TIME_COLUMN,
            [{'name': 'a'}, {'name': 'b'}],
            [[1, 2], [3, 4]],
            ['t1', None],
        ),
        ([{'name': 'a'}], [[1], [2]], QUERY_TIME_COLUMN, [{'name': 'a'}], [[1], [2]], []),
    ],
)
def test_pop_column(columns, rows, name, expected_columns, expected_rows, expected_values):
    """Test pop_column removes the column from the columns and rows and returns its values."""
    assert pop_column(columns, rows, name) == expected_values
    assert columns == expected_columns
    assert rows == expected_rows


@patch('azure_services.analytics.get')
def test_get_log_analytics_events_error_responses(mock_get):
    """Test get_log_analytics_events handles invalid responses from the request module."""
    la_query = 'test_query'
    response_mock = MagicMock(status_code=400)
    mock_get.return_value = response_mock
    get_log_analytics_events(url=None, body=None, headers=None, md5_hash=None, query=la_query, tag='', tenant='tenant')
    response_mock.raise_for_status.assert_called_once()


@patch('azure_services.analytics.logging.debug')
@patch('azure_services.analytics.get')
def test_get_log_analytics_events_does_not_log_headers(mock_get, mock_logging):
    """Test get_log_analytics_events does not write the authentication token to the log."""
    token = 'A_TOKEN_THAT_MUST_NOT_BE_LOGGED'

    response_mock = MagicMock(status_code=200)
    response_mock.json.return_value = {'tables': [{'columns': [], 'rows': []}]}
    mock_get.return_value = response_mock

    get_log_analytics_events(
        url='url',
        body='body',
        headers={'Authorization': f'Bearer {token}'},
        md5_hash='',
        query='test_query',
        tag='test',
        tenant='tenant',
    )

    for call in mock_logging.call_args_list:
        assert token not in call[0][0]


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
