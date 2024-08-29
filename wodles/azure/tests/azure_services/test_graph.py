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
from unittest.mock import MagicMock, patch

import pytest
from dateutil.parser import parse
from requests import HTTPError

sys.path.insert(0, dirname(dirname(dirname(abspath(__file__)))))

from azure_services.graph import (
    URL_GRAPH,
    build_graph_url,
    get_graph_events,
    start_graph,
)
from db import orm

PAST_DATE = '2022-01-01T12:00:00.000000Z'
PRESENT_DATE = '2022-06-15T12:00:00.000000Z'
FUTURE_DATE = '2022-12-31T12:00:00.000000Z'

TEST_DATA_PATH = join(dirname(dirname(realpath(__file__))), 'data')


@pytest.mark.parametrize(
    'auth_path, graph_id, key, offset, query, tag, reparse',
    [
        (None, 'client', 'secret', '1d', 'query', 'tag', False),
        ('/var/ossec/', None, None, '', '', '', False),
    ],
)
@patch('azure_services.graph.get_graph_events')
@patch('azure_services.graph.build_graph_url')
@patch('azure_services.graph.get_token')
@patch('azure_services.graph.read_auth_file')
def test_start_graph(
    mock_auth,
    mock_token,
    mock_build,
    mock_graph,
    auth_path,
    graph_id,
    key,
    offset,
    query,
    tag,
    reparse,
):
    """Test start_graph attempts to process the logs available for the given authentication, query and offset values."""
    tenant = 'tenant'
    args = MagicMock(
        graph_tenant_domain=tenant,
        graph_auth_path=auth_path,
        graph_id=graph_id,
        graph_key=key,
        graph_time_offset=offset,
        graph_query=query,
        graph_tag=tag,
        reparse=reparse,
    )
    mock_auth.return_value = credentials = ('client', 'secret')
    mock_token.return_value = token = 'token'
    mock_build.return_value = url = 'url'

    start_graph(args)

    if auth_path and tenant:
        mock_auth.assert_called_with(auth_path=auth_path, fields=('application_id', 'application_key'))
    else:
        mock_auth.assert_not_called()

    mock_token.assert_called_with(
        client_id=credentials[0],
        secret=credentials[1],
        domain=tenant,
        scope=f'{URL_GRAPH}/.default',
    )
    md5_hash = md5(query.encode()).hexdigest()
    mock_build.assert_called_with(query=query, offset=offset, reparse=reparse, md5_hash=md5_hash)
    mock_graph.assert_called_with(
        url=url,
        headers={'Authorization': f'Bearer {token}'},
        md5_hash=md5_hash,
        query=query,
        tag=tag,
    )


@patch('azure_utils.logging.error')
@patch('azure_services.graph.get_graph_events', side_effect=HTTPError)
@patch('azure_services.graph.build_graph_url')
@patch('azure_services.graph.get_token')
@patch('azure_services.graph.read_auth_file', return_value=('client', 'secret'))
def test_start_graph_ko(mock_auth, mock_token, mock_build, mock_get, mock_logging):
    """Test start_graph shows error message if get_log_analytics_events returns an HTTP error."""
    args = MagicMock(graph_id='test', graph_key='test', graph_tenant_domain='test', graph_query='')
    start_graph(args)
    mock_logging.assert_called_once()


@patch('azure_utils.logging.error')
def test_start_graph_ko_credentials(mock_logging):
    """Test start_graph stops its execution if no valid credentials are provided."""
    args = MagicMock(graph_tenant_domain=None)
    with pytest.raises(SystemExit) as err:
        start_graph(args)
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
@patch('azure_services.graph.offset_to_datetime')
@patch('azure_services.graph.create_new_row')
@patch('db.orm.get_row', return_value=None)
def test_build_graph_url(
    mock_get,
    mock_create,
    mock_datetime,
    min_date,
    max_date,
    desired_date,
    reparse,
):
    """Test build_graph_url builds the URL applying the expected filters based on the dates provided."""
    mock_create.return_value = MagicMock(min_processed_date=min_date, max_processed_date=max_date)
    mock_datetime.return_value = parse(desired_date)
    query = 'query'
    offset = '1d'
    md5_hash = ''

    result = build_graph_url(offset=offset, query=query, reparse=reparse, md5_hash=md5_hash)

    mock_get.assert_called_with(orm.Graph, md5=md5_hash)
    mock_create.assert_called_with(table=orm.Graph, query=query, md5_hash=md5_hash, offset=offset)

    filtering_condition = 'createdDateTime' if 'signins' in query.lower() else 'activityDateTime'

    if reparse:
        expected_str = f'{filtering_condition}+ge+{desired_date}'
    else:
        if parse(desired_date) < parse(min_date, fuzzy=True):
            expected_str = (
                f'({filtering_condition}+lt+{min_date}+and+{filtering_condition}+ge+{desired_date})'
                f'+or+({filtering_condition}+gt+{max_date})'
            )
        elif parse(desired_date) > parse(max_date, fuzzy=True):
            expected_str = f'{filtering_condition}+ge+{desired_date}'
        else:
            expected_str = f'{filtering_condition}+gt+{max_date}'
    assert URL_GRAPH in result
    assert query in result
    assert expected_str in result


@patch('azure_utils.logging.error')
@patch('db.orm.get_row', side_effect=orm.AzureORMError)
def test_build_graph_url_ko(mock_get, mock_logging):
    """Test build_log_analytics_query handles ORM exceptions."""
    with pytest.raises(SystemExit) as err:
        build_graph_url(offset=None, query='query', reparse=False, md5_hash=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure_services.graph.send_message')
@patch('azure_services.graph.update_row_object')
@patch('azure_services.graph.get')
def test_get_graph_events(mock_get, mock_update, mock_send):
    """Test get_graph_events recursively request the data using the specified url and process the values present in the
    response."""

    def load_events(path):
        with open(join(TEST_DATA_PATH, path)) as f:
            return json.loads(f.read())

    # The first file contains both values and a nextLink to the following file
    event_list = MagicMock(status_code=200)
    contents = load_events('graph_events')
    event_list.json.return_value = contents
    num_events = len(contents['value'])
    url = contents['@odata.nextLink']

    # The second file has no values nor nextLink
    empty_event_list = MagicMock(status_code=200)
    empty_event_list.json.return_value = load_events('graph_events_no_values')

    mock_get.side_effect = [event_list, empty_event_list]

    headers = 'headers'
    get_graph_events(url=url, headers=headers, md5_hash='', query='query', tag='tag')
    mock_get.assert_called_with(url=url, headers=headers, timeout=10)
    assert mock_update.call_count == num_events
    assert mock_send.call_count == num_events


@pytest.mark.parametrize('status_code', [400, 500])
@patch('azure_utils.logging.error')
@patch('azure_services.graph.get')
def test_get_graph_events_error_responses(mock_get, mock_logging, status_code):
    """Test get_graph_events handles invalid responses from the request module."""
    response_mock = MagicMock(status_code=status_code)
    mock_get.return_value = response_mock
    get_graph_events(url=None, headers=None, md5_hash=None, query='query', tag='tag')

    if status_code == 400:
        assert mock_logging.call_count == 2
    else:
        response_mock.raise_for_status.assert_called_once()
