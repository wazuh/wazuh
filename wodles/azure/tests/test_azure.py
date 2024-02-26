# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import importlib
import json
import logging
import os
import socket
import sys
from datetime import datetime
from hashlib import md5
from unittest.mock import call, patch, MagicMock, PropertyMock

from typing import Optional

import pytest
import pytz
from dateutil.parser import parse
from requests import HTTPError

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501

with patch('azure-logs.orm'):
    azure = importlib.import_module("azure-logs")

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
TEST_AUTHENTICATION_PATH = os.path.join(TEST_DATA_PATH, 'authentication_files')

PAST_DATE = "2022-01-01T12:00:00.000000Z"
PRESENT_DATE = "2022-06-15T12:00:00.000000Z"
FUTURE_DATE = "2022-12-31T12:00:00.000000Z"


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
    blob.properties.last_modified = (last_modified if last_modified else datetime.now()).replace(tzinfo=pytz.UTC)

    # Add Blob length property
    if not (content_length is None):
        type(blob.properties).content_length = PropertyMock(return_value=content_length)

    return blob


@pytest.mark.parametrize('debug_level', [0, 1, 2, 3])
@patch('azure-logs.logging.basicConfig')
def test_set_logger(mock_logging, debug_level):
    """Test set_logger sets the expected logging verbosity level."""
    azure.args = MagicMock(debug_level=debug_level)
    azure.set_logger()
    mock_logging.assert_called_with(level=azure.LOG_LEVELS.get(debug_level, logging.INFO),
                                    format=azure.LOGGING_MSG_FORMAT,
                                    datefmt=azure.LOGGING_DATE_FORMAT)
    assert logging.getLogger('azure').level == azure.LOG_LEVELS.get(debug_level, logging.WARNING).real
    assert logging.getLogger("urllib3").level == logging.ERROR.real


def test_get_script_arguments(capsys):
    """Test get_script_arguments shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', '--graph']):
        azure.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'stdout was not empty'
    assert stderr == "", 'stderr was not empty'


@pytest.mark.parametrize('args', [
    ['main'],
    ['main', '--graph', '--log_analytics'],
    ['main', '--graph', '--storage'],
    ['main', '--log_analytics', '--storage'],
])
def test_get_script_arguments_exclusive(capsys, args):
    """Test get_script_arguments shows an error message when the required parameters are not provided."""
    with patch("sys.argv", args), pytest.raises(SystemExit) as exception:
        azure.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2


@pytest.mark.parametrize('arg_string', ['"string"', "'string'", None])
def test_arg_valid_container_name(arg_string):
    """Test arg_valid_container_name removes unwanted characters from the container name."""
    result = azure.arg_valid_container_name(arg_string)
    if result:
        assert '"' not in result


@pytest.mark.parametrize('arg_string', ['"string"', "'string'", "string\\$", "string 'test'", None])
def test_arg_valid_graph_query(arg_string):
    """Test arg_valid_graph_query removes unwanted characters from the graph query."""
    result = azure.arg_valid_graph_query(arg_string)
    if result:
        assert result[0] != "'"
        assert result[-1] != "'"
        assert "\\$" not in result


@pytest.mark.parametrize('arg_string', ['string!', 'string\\!', '\\!string\\!', None])
def test_arg_valid_la_query(arg_string):
    """Test arg_valid_la_query removes unwanted characters from the log analytics query."""
    result = azure.arg_valid_la_query(arg_string)
    if result:
        assert "\\!" not in result


@pytest.mark.parametrize('arg_string', ['"string"', '*', '"*"', None])
def test_arg_valid_blob_extension(arg_string):
    """Test arg_valid_blob_extension removes unwanted characters from the blob extension."""
    result = azure.arg_valid_blob_extension(arg_string)
    if result:
        assert '"' not in result
        assert '*' not in result


@pytest.mark.parametrize('file_name, fields', [
    ("valid_authentication_file", ("application_id", "application_key")),
    ("valid_authentication_file_alt", ("application_key", "application_id")),
    ("valid_authentication_file_extra_line", ("application_id", "application_key")),
    ("valid_authentication_file_storage", ("account_name", "account_key"))
])
def test_read_auth_file(file_name, fields):
    """Test read_auth_file correctly handles valid authentication files."""
    credentials = azure.read_auth_file(auth_path=os.path.join(TEST_AUTHENTICATION_PATH, file_name), fields=fields)
    assert isinstance(credentials, tuple)
    for i in range(len(fields)):
        assert credentials[i] == f"{fields[i]}_value"


@pytest.mark.parametrize('file_name', [
    "no_file",
    "empty_authentication_file",
    "invalid_authentication_file",
    "invalid_authentication_file_2",
    "invalid_authentication_file_3"
])
@patch('azure-logs.logging.error')
def test_read_auth_file_ko(mock_logging, file_name):
    """Test read_auth_file correctly handles invalid authentication files."""
    with pytest.raises(SystemExit) as err:
        azure.read_auth_file(auth_path=os.path.join(TEST_AUTHENTICATION_PATH, file_name), fields=("field", "field"))
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize('min_date, max_date', [
    (PAST_DATE, PRESENT_DATE),
    (PAST_DATE, FUTURE_DATE),
    (PRESENT_DATE, PRESENT_DATE),
    (PRESENT_DATE, FUTURE_DATE),
    (FUTURE_DATE, FUTURE_DATE)
])
@patch('azure-logs.orm.update_row')
@patch('azure-logs.orm.get_row')
def test_update_row_object(mock_get, mock_update, min_date, max_date):
    """Test update_row_object alter the database values when corresponds."""
    mock_table = MagicMock(__tablename__="")
    mock_get.return_value = MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE)
    azure.update_row_object(table=mock_table, md5_hash="", new_min=min_date, new_max=max_date, query="")
    if min_date < PRESENT_DATE or max_date > PRESENT_DATE:
        mock_update.assert_called_with(table=mock_table, md5="", query="",
                                       min_date=min_date if min_date < PRESENT_DATE else PRESENT_DATE,
                                       max_date=max_date if max_date > PRESENT_DATE else PRESENT_DATE)
    else:
        mock_update.assert_not_called()


@patch('azure-logs.logging.error')
@patch('azure-logs.orm.get_row', side_effect=AttributeError)
def test_update_row_object_ko(mock_get, mock_logging):
    """Test update_row_object handles ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        azure.update_row_object(table=MagicMock(__tablename__=""), md5_hash=None, new_min=None, new_max=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure-logs.logging.error')
@patch('azure-logs.orm.update_row', side_effect=azure.orm.AzureORMError)
@patch('azure-logs.orm.get_row', return_value=MagicMock(min_processed_date=PRESENT_DATE,
                                                        max_processed_date=PRESENT_DATE))
def test_update_row_object_ko_update(mock_get, mock_update, mock_logging):
    """Test update_row_object handles ORM errors as expected."""
    with pytest.raises(SystemExit) as err:
        azure.update_row_object(table=MagicMock(__tablename__=""), md5_hash=None, new_min=PAST_DATE,
                                new_max=FUTURE_DATE)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure-logs.orm')
def test_create_new_row(mock_orm):
    """Test create_new_row invokes the ORM functionality with a valid row object."""
    mock_table = MagicMock(__tablename__="")
    item = azure.create_new_row(table=mock_table, md5_hash="hash", query="query", offset=None)
    datetime_str = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime(azure.DATETIME_MASK)
    mock_table.assert_called_with(md5="hash", query="query", min_processed_date=datetime_str,
                                  max_processed_date=datetime_str)
    mock_orm.add_row.assert_called_with(row=item)


@patch('azure-logs.logging.error')
@patch('azure-logs.orm.add_row', side_effect=azure.orm.AzureORMError)
def test_create_new_row_ko(mock_add_row, mock_logging):
    """Test create_new_row raises an error if when attempting to add a invalid row object."""
    with pytest.raises(SystemExit) as err:
        azure.create_new_row(table=MagicMock(__tablename__=""), md5_hash="hash", query="query", offset=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize('auth_path, offset, query, workspace', [
    ("/var/ossec/", "1d", "query", "workspace"),
])
@patch('azure-logs.get_log_analytics_events')
@patch('azure-logs.build_log_analytics_query')
@patch('azure-logs.get_token')
@patch('azure-logs.read_auth_file')
def test_start_log_analytics(mock_auth, mock_token, mock_build, mock_get_logs, auth_path, offset, query, workspace):
    """Test start_log_analytics reads the credentials, obtains a token, builds the query using that token and attempts
    to get the log analytics logs."""
    tenant = "tenant"
    azure.args = MagicMock(
        la_tenant_domain=tenant, la_auth_path=auth_path, la_query=query, la_time_offset=offset, workspace=workspace
    )

    mock_auth.return_value = credentials = ("client", "secret")
    mock_token.return_value = token = "token"
    mock_build.return_value = body = "body"
    azure.start_log_analytics()

    if auth_path:
        mock_auth.assert_called_with(auth_path=auth_path, fields=("application_id", "application_key"))
    else:
        mock_auth.assert_not_called()

    # Check a token is requested using the right parameters
    mock_token.assert_called_with(client_id=credentials[0], secret=credentials[1], domain=tenant,
                                  scope=f'{azure.URL_ANALYTICS}/.default')
    md5_hash = md5(query.encode()).hexdigest()
    mock_build.assert_called_with(offset=offset, md5_hash=md5_hash)
    mock_get_logs.assert_called_with(url=f"{azure.URL_ANALYTICS}/v1/workspaces/{workspace}/query", body=body,
                                     headers={"Authorization": f"Bearer {token}"}, md5_hash=md5_hash)


@patch('azure-logs.logging.error')
@patch('azure-logs.get_log_analytics_events', side_effect=HTTPError)
@patch('azure-logs.build_log_analytics_query')
@patch('azure-logs.get_token')
@patch('azure-logs.read_auth_file', return_value=("client", "secret"))
def test_start_log_analytics_ko(mock_auth, mock_token, mock_build, mock_get_logs, mock_logging):
    """Test start_log_analytics shows error message if get_log_analytics_events returns an HTTP error."""
    azure.args = MagicMock(la_tenant_domain="test", la_id="test", la_key="test", la_query="test",
                           la_time_offset="", workspace="test")
    azure.start_log_analytics()
    mock_logging.assert_called_once()


@patch('azure-logs.logging.error')
def test_start_log_analytics_ko_credentials(mock_logging):
    """Test start_log_analytics stops its execution if no valid credentials are provided."""
    azure.args = MagicMock(la_tenant_domain=None)
    with pytest.raises(SystemExit) as err:
        azure.start_log_analytics()
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize('min_date, max_date, desired_date, reparse', [
    (PRESENT_DATE, FUTURE_DATE, PAST_DATE, False),
    (PAST_DATE, PRESENT_DATE, FUTURE_DATE, False),
    (PAST_DATE, FUTURE_DATE, PRESENT_DATE, False),
    (PAST_DATE, PAST_DATE, PRESENT_DATE, True),
])
@patch('azure-logs.offset_to_datetime')
@patch('azure-logs.create_new_row')
@patch('azure-logs.orm.get_row', return_value=None)
def test_build_log_analytics_query(mock_get, mock_create, mock_datetime, min_date, max_date, desired_date, reparse):
    """Test build_log_analytics_query creates the required query with the expected "TimeGenerated" filter values."""
    azure.args = MagicMock(reparse=reparse, la_query="test_query")
    mock_create.return_value = MagicMock(min_processed_date=min_date, max_processed_date=max_date)
    mock_datetime.return_value = parse(desired_date)
    result = azure.build_log_analytics_query(offset=desired_date, md5_hash="")
    mock_get.assert_called_with(azure.orm.LogAnalytics, md5="")
    mock_create.assert_called_with(table=azure.orm.LogAnalytics, query=azure.args.la_query, md5_hash="",
                                   offset=desired_date)

    if reparse:
        expected_str = f"TimeGenerated >= datetime({desired_date})"
    else:
        if parse(desired_date) < parse(min_date, fuzzy=True):
            expected_str = f"( TimeGenerated < datetime({min_date}) and TimeGenerated >= datetime({desired_date})) " \
                           f"or ( TimeGenerated > datetime({max_date}))"
        elif parse(desired_date) > parse(max_date, fuzzy=True):
            expected_str = f"TimeGenerated >= datetime({desired_date})"
        else:
            expected_str = f"TimeGenerated > datetime({max_date})"

    assert expected_str in result["query"]


@patch('azure-logs.logging.error')
@patch('azure-logs.orm.get_row', side_effect=azure.orm.AzureORMError)
def test_build_log_analytics_query_ko(mock_get, mock_logging):
    """Test build_log_analytics_query handles ORM exceptions."""
    with pytest.raises(SystemExit) as err:
        azure.build_log_analytics_query(offset=None, md5_hash=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize('file, time_position', [
    ("log_analytics_events", 0),
    ("log_analytics_events", None),
    ("log_analytics_events_no_results", None),
    ("log_analytics_events_empty", None)
])
@patch('azure-logs.logging.error')
@patch('azure-logs.update_row_object')
@patch('azure-logs.iter_log_analytics_events')
@patch('azure-logs.get_time_position')
@patch('azure-logs.get')
def test_get_log_analytics_events(mock_get, mock_position, mock_iter, mock_update, mock_logging, file, time_position):
    """Test get_log_analytics_events gets the logs, process the response and iterate the events if the 'TimeGenerated'
    field was present."""
    azure.args = MagicMock(la_query="test_query")
    m = MagicMock(status_code=200)
    with open(os.path.join(TEST_DATA_PATH, file)) as f:
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
    url = "url"
    body = "body"
    headers = "headers"
    azure.get_log_analytics_events(url=url, body=body, headers=headers, md5_hash="")
    mock_get.assert_called_with(url, params=body, headers=headers, timeout=10)
    if rows is None or (len(rows) > 0 and time_position is None):
        mock_logging.assert_called_once()
    elif len(rows) == 0:
        mock_position.assert_not_called()
        mock_iter.assert_not_called()
        mock_update.assert_not_called()
    else:
        mock_position.assert_called_with(columns)
        mock_iter.assert_called_with(columns, rows)
        mock_update.assert_called_once()


@patch('azure-logs.get')
def test_get_log_analytics_events_error_responses(mock_get):
    """Test get_log_analytics_events handles invalid responses from the request module."""
    azure.args = MagicMock(la_query="test_query")
    response_mock = MagicMock(status_code=400)
    mock_get.return_value = response_mock
    azure.get_log_analytics_events(url=None, body=None, headers=None, md5_hash=None)
    response_mock.raise_for_status.assert_called_once()


@pytest.mark.parametrize('columns, position', [
    ([{'name': 'TimeGenerated'}, {'name': 'test'}], 0),
    ([{'name': 'test'}, {'name': 'TimeGenerated'}], 1),
    ([{'name': 'test'}, {'name': 'test'}], None)
])
def test_get_time_position(columns, position):
    """Test get_time_position returns the position of the 'TimeGenerated' field."""
    result = azure.get_time_position(columns)
    assert result == position


@patch('azure-logs.send_message')
def test_iter_log_analytics_events(mock_send):
    """Test iter_log_analytics_events iterates through the columns and rows to build the events and send them to the
    socket."""
    azure.args = MagicMock(la_tag="tag")
    with open(os.path.join(TEST_DATA_PATH, "log_analytics_events")) as f:
        events = json.loads(f.read())
        columns = events['tables'][0]['columns']
        rows = events['tables'][0]['rows']
    azure.iter_log_analytics_events(columns=columns, rows=rows)
    keys = [col['name'] for col in columns]
    tag_keys = ["azure_tag", "log_analytics_tag"]
    tag_values = ["azure-log-analytics", azure.args.la_tag]
    expected_calls = [call(json.dumps({k: v for k, v in zip(keys + tag_keys, values + tag_values)})) for values in rows]
    mock_send.assert_has_calls(expected_calls)


@pytest.mark.parametrize('auth_path, offset, query', [
    ("/var/ossec/", "1d", "query"),
])
@patch('azure-logs.get_graph_events')
@patch('azure-logs.build_graph_url')
@patch('azure-logs.get_token')
@patch('azure-logs.read_auth_file')
def test_start_graph(mock_auth, mock_token, mock_build, mock_graph, auth_path, offset, query):
    """Test start_graph attempts to process the logs available for the given authentication, query and offset values."""
    tenant = "tenant"
    azure.args = MagicMock(
        graph_tenant_domain=tenant, graph_auth_path=auth_path, graph_time_offset=offset, graph_query=query
    )
    mock_auth.return_value = credentials = ("client", "secret")
    mock_token.return_value = token = "token"
    mock_build.return_value = url = "url"

    azure.start_graph()

    if auth_path and tenant:
        mock_auth.assert_called_with(auth_path=auth_path, fields=("application_id", "application_key"))
    else:
        mock_auth.assert_not_called()

    mock_token.assert_called_with(client_id=credentials[0], secret=credentials[1], domain=tenant,
                                  scope=f"{azure.URL_GRAPH}/.default")
    md5_hash = md5(query.encode()).hexdigest()
    mock_build.assert_called_with(offset=offset, md5_hash=md5_hash)
    mock_graph.assert_called_with(url=url, headers={'Authorization': f'Bearer {token}'}, md5_hash=md5_hash)


@patch('azure-logs.logging.error')
@patch('azure-logs.get_graph_events', side_effect=HTTPError)
@patch('azure-logs.build_graph_url')
@patch('azure-logs.get_token')
@patch('azure-logs.read_auth_file', return_value=("client", "secret"))
def test_start_graph_ko(mock_auth, mock_token, mock_build, mock_get, mock_logging):
    """Test start_graph shows error message if get_log_analytics_events returns an HTTP error."""
    azure.args = MagicMock(graph_id="test", graph_key="test", graph_tenant_domain="test", graph_query="")
    azure.start_graph()
    mock_logging.assert_called_once()


@patch('azure-logs.logging.error')
def test_start_graph_ko_credentials(mock_logging):
    """Test start_graph stops its execution if no valid credentials are provided."""
    azure.args = MagicMock(graph_tenant_domain=None)
    with pytest.raises(SystemExit) as err:
        azure.start_graph()
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize('min_date, max_date, desired_date, reparse', [
    (PRESENT_DATE, FUTURE_DATE, PAST_DATE, False),
    (PAST_DATE, PRESENT_DATE, FUTURE_DATE, False),
    (PAST_DATE, FUTURE_DATE, PRESENT_DATE, False),
    (PAST_DATE, PAST_DATE, PRESENT_DATE, True),
])
@patch('azure-logs.logging.info')
@patch('azure-logs.offset_to_datetime')
@patch('azure-logs.create_new_row')
@patch('azure-logs.orm.get_row', return_value=None)
def test_build_graph_url(mock_get, mock_create, mock_datetime, mock_logging, min_date, max_date, desired_date, reparse):
    """Test build_graph_url builds the URL applying the expected filters based on the dates provided."""
    mock_create.return_value = MagicMock(min_processed_date=min_date, max_processed_date=max_date)
    mock_datetime.return_value = parse(desired_date)
    query = "query"
    offset = "1d"
    md5_hash = ""
    azure.args = MagicMock(reparse=reparse, graph_query=query)

    result = azure.build_graph_url(offset=offset, md5_hash=md5_hash)

    mock_get.assert_called_with(azure.orm.Graph, md5=md5_hash)
    mock_create.assert_called_with(table=azure.orm.Graph, query=query, md5_hash=md5_hash, offset=offset)

    filtering_condition = "createdDateTime" if "signins" in query.lower() else "activityDateTime"

    if reparse:
        expected_str = f"{filtering_condition}+ge+{desired_date}"
    else:
        if parse(desired_date) < parse(min_date, fuzzy=True):
            expected_str = f"({filtering_condition}+lt+{min_date}+and+{filtering_condition}+ge+{desired_date})" \
                           f"+or+({filtering_condition}+gt+{max_date})"
        elif parse(desired_date) > parse(max_date, fuzzy=True):
            expected_str = f"{filtering_condition}+ge+{desired_date}"
        else:
            expected_str = f"{filtering_condition}+gt+{max_date}"
    mock_logging.assert_called_once()
    assert azure.URL_GRAPH in result
    assert query in result
    assert expected_str in result


@patch('azure-logs.logging.error')
@patch('azure-logs.orm.get_row', side_effect=azure.orm.AzureORMError)
def test_build_graph_url_ko(mock_get, mock_logging):
    """Test build_log_analytics_query handles ORM exceptions."""
    with pytest.raises(SystemExit) as err:
        azure.build_graph_url(offset=None, md5_hash=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure-logs.send_message')
@patch('azure-logs.update_row_object')
@patch('azure-logs.get')
def test_get_graph_events(mock_get, mock_update, mock_send):
    """Test get_graph_events recursively request the data using the specified url and process the values present in the
    response."""
    def load_events(path):
        with open(os.path.join(TEST_DATA_PATH, path)) as f:
            return json.loads(f.read())

    azure.args = MagicMock(graph_query="test_query", graph_tag="tag")

    # The first file contains both values and a nextLink to the following file
    event_list = MagicMock(status_code=200)
    contents = load_events("graph_events")
    event_list.json.return_value = contents
    num_events = len(contents['value'])
    url = contents['@odata.nextLink']

    # The second file has no values nor nextLink
    empty_event_list = MagicMock(status_code=200)
    empty_event_list.json.return_value = load_events("graph_events_no_values")

    mock_get.side_effect = [event_list, empty_event_list]

    headers = "headers"
    azure.get_graph_events(url=url, headers=headers, md5_hash="")
    mock_get.assert_called_with(url=url, headers=headers, timeout=10)
    assert mock_update.call_count == num_events
    assert mock_send.call_count == num_events


@pytest.mark.parametrize('status_code', [400, 500])
@patch('azure-logs.logging.error')
@patch('azure-logs.get')
def test_get_graph_events_error_responses(mock_get, mock_logging, status_code):
    """Test get_graph_events handles invalid responses from the request module."""
    response_mock = MagicMock(status_code=status_code)
    mock_get.return_value = response_mock
    azure.get_graph_events(url=None, headers=None, md5_hash=None)

    if status_code == 400:
        assert mock_logging.call_count == 2
    else:
        response_mock.raise_for_status.assert_called_once()


@pytest.mark.parametrize('auth_path, container_name', [
    ("/var/ossec/", "*"),
])
@patch('azure-logs.get_blobs')
@patch('azure-logs.create_new_row')
@patch('azure-logs.orm.get_row', return_value=None)
@patch('azure-logs.BlockBlobService')
@patch('azure-logs.read_auth_file')
def test_start_storage(mock_auth, mock_blob, mock_get_row, mock_create, mock_get_blobs, auth_path, container_name):
    """Test start_storage process blobs in bucket as expected."""
    offset = "1d"
    azure.args = MagicMock(storage_auth_path=auth_path, container=container_name, storage_time_offset=offset)
    mock_create.return_value = MagicMock(min_processed_date=PRESENT_DATE, max_processed_date=PRESENT_DATE)
    mock_auth.return_value = ("name", "key")
    m = MagicMock()
    m.list_containers.return_value = [MagicMock(name=container_name)]
    mock_blob.return_value = m
    azure.start_storage()

    if auth_path:
        mock_auth.assert_called_with(auth_path=auth_path, fields=("account_name", "account_key"))
    else:
        mock_auth.assert_not_called()

    md5_hash = md5("name".encode()).hexdigest()
    mock_blob.assert_called_with(account_name="name", account_key="key")
    mock_get_row.assert_called_with(azure.orm.Storage, md5=md5_hash)
    mock_create.assert_called_with(table=azure.orm.Storage, query="name", md5_hash=md5_hash, offset=offset)
    mock_get_blobs.assert_called_once()


@pytest.mark.parametrize('container_name, exception', [
    ("", None),
    ("", azure.AzureException),
    ("*", azure.AzureSigningError),
    ("*", azure.AzureException),
    ("*", None)
])
@patch('azure-logs.logging.error')
@patch('azure-logs.create_new_row', side_effect=azure.orm.AzureORMError)
@patch('azure-logs.orm.get_row', return_value=None)
@patch('azure-logs.BlockBlobService')
def test_start_storage_ko(mock_blob, mock_get, mock_create, mock_logging, container_name, exception):
    """Test start_log_analytics shows error message if get_log_analytics_events returns an HTTP error."""
    azure.args = MagicMock(storage_auth_path=None, account_name="test", account_key="test", container=container_name,
                           storage_time_offset="")
    m = MagicMock()
    if container_name == "*":
        m.list_containers.return_value = [MagicMock(name=container_name)]
        m.list_containers.side_effect = exception
    else:
        m.exists.return_value = None
        m.exists.side_effect = exception
    mock_blob.return_value = m

    with pytest.raises(SystemExit) as err:
        azure.start_storage()
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure-logs.logging.error')
def test_start_storage_ko_credentials(mock_logging):
    """Test start_storage stops its execution if no valid credentials are provided."""
    azure.args = MagicMock(storage_auth_path=None, account_name=None, account_key=None)
    with pytest.raises(SystemExit) as err:
        azure.start_storage()
    assert err.value.code == 1
    mock_logging.assert_called_once()


@pytest.mark.parametrize(
    'blob_date, min_date, max_date, desired_date, extension, reparse, json_file, inline, send_events', [
    # blob_date < desired_date - Blobs should be skipped
    (PRESENT_DATE, PAST_DATE, PAST_DATE, FUTURE_DATE, None, False, False, False, False),
    # blob_date > desired_date, min_date == blob_date and blob_date < max_date - Blobs should be skipped
    (PRESENT_DATE, PRESENT_DATE, FUTURE_DATE, PAST_DATE, None, False, False, False, False),
    # blob_date > desired_date, min_date < blob_date and blob_date == max_date - Blobs should be skipped
    (FUTURE_DATE, PRESENT_DATE, FUTURE_DATE, PAST_DATE, None, False, False, False, False),
    # blob_date > desired_date, min_date < blob_date and blob_date < max_date - Blobs should be skipped
    (PAST_DATE, PRESENT_DATE, FUTURE_DATE, PAST_DATE, None, False, False, False, False),
    # blob_date < min_datetime - Blobs must be processed
    (PAST_DATE, PRESENT_DATE, FUTURE_DATE, PAST_DATE, None, False, False, False, True),
    # blob_date > max_datetime - Blobs must be processed
    (FUTURE_DATE, PAST_DATE, PRESENT_DATE, FUTURE_DATE, None, False, False, True, True),
    # Reparse old logs
    (FUTURE_DATE, FUTURE_DATE, FUTURE_DATE, FUTURE_DATE, None, True, False, True, True),
    # Only .json files must be processed
    (FUTURE_DATE, PAST_DATE, PRESENT_DATE, FUTURE_DATE, ".json", False, False, False, True),
    (FUTURE_DATE, PAST_DATE, PRESENT_DATE, FUTURE_DATE, ".json", False, False, True, True),
    (FUTURE_DATE, PAST_DATE, PRESENT_DATE, FUTURE_DATE, ".json", False, True, False, True),
])
@patch('azure-logs.update_row_object')
@patch('azure-logs.send_message')
def test_get_blobs(mock_send, mock_update, blob_date, min_date, max_date, desired_date, extension, reparse, json_file,
                   inline, send_events):
    """Test get_blobs obtains the blobs from a container and send their content to the socket."""
    azure.args = MagicMock(blobs=extension, json_file=json_file, json_inline=inline, reparse=reparse,
                           storage_tag="tag")
    blob_date_str = parse(blob_date)
    blob_list = [create_mocked_blob(blob_name=f"blob_{i}", last_modified=blob_date_str) for i in range(5)] + [
        create_mocked_blob(blob_name=f"blob_{i}{extension}", last_modified=blob_date_str) for i in range(5)]

    # The first iteration will contain a full blob list and a next_marker value
    blob_service_iter_1 = MagicMock(next_marker="marker")
    blob_service_iter_1.__iter__ = MagicMock(return_value=iter(blob_list))
    # The second and last iteration won't contain blob list nor next_marker
    blob_service_iter_2 = MagicMock(next_marker=None)
    blob_service = MagicMock()
    blob_service.list_blobs.side_effect = [blob_service_iter_1, blob_service_iter_2]

    if json_file:
        test_file = "storage_events_json"
    elif inline:
        test_file = "storage_events_inline"
    else:
        test_file = "storage_events_plain"

    with open(os.path.join(TEST_DATA_PATH, test_file)) as f:
        contents = f.read()
        blob_service.get_blob_to_text.return_value = MagicMock(content=contents)

    container_name = "container"
    marker = "marker"
    md5_hash = "hash"
    tag = "tag"
    azure.get_blobs(container_name=container_name, blob_service=blob_service, md5_hash=md5_hash, next_marker=marker,
                    min_datetime=parse(min_date), max_datetime=parse(max_date), desired_datetime=parse(desired_date))

    blob_service.list_blobs.assert_called_with(container_name, prefix=None, marker=marker)
    blob_service.get_blob_to_text.assert_has_calls(
        [call(container_name, blob.name) for blob in blob_list if extension and extension in blob.name])
    if send_events:
        calls = list()
        extension = extension if extension else ""
        for blob in blob_list:
            if extension in blob.name:
                if json_file:
                    for record in json.loads(contents)["records"]:
                        record['azure_tag'] = 'azure-storage'
                        record['azure_storage_tag'] = tag
                        calls.append(call(json.dumps(record)))
                else:
                    for line in [s for s in str(contents).splitlines() if s]:
                        if inline:
                            calls.append(call(f'{{"azure_tag": "azure-storage", "azure_storage_tag": "{tag}", {line[1:]}'))
                        else:
                            calls.append(call(f"azure_tag: azure-storage. azure_storage_tag: {tag}. {line}"))
        mock_send.assert_has_calls(calls)
        assert mock_update.call_count == len(blob_list) if not extension else len(
            [blob.name for blob in blob_list if extension in blob.name])

@patch('azure-logs.logging.debug')
def test_that_empty_blobs_are_omitted(mock_logging):
    """Test get_blobs checks the size of the blob and omits it if is is empty"""
    azure.args = MagicMock(blobs=None, json_file=False, json_inline=False, reparse=False)

    # List of empty blobs to use
    list_of_empty_blobs = [
        create_mocked_blob("Example1", content_length=0),
        create_mocked_blob("Example2", content_length=0)
    ]

    iterator_with_marker = MagicMock(next_marker=None)
    iterator_with_marker.__iter__.return_value = list_of_empty_blobs

    # Mock for the blob service
    blob_service = MagicMock()
    blob_service.list_blobs.return_value = iterator_with_marker

    container_name = "container"
    marker = "marker"
    md5_hash = "hash"
    azure.get_blobs(container_name=container_name, blob_service=blob_service, md5_hash=md5_hash, next_marker=marker,
                    min_datetime=parse(PRESENT_DATE), max_datetime=parse(FUTURE_DATE),
                    desired_datetime=parse(FUTURE_DATE))

    # for blob in list_of_empty_blobs:
    #     blob.properties.content_length.assert_called()
    expected_calls = [call("Empty blob Example1, skipping"), call("Empty blob Example2, skipping")]
    mock_logging.assert_has_calls(expected_calls, any_order=False)
    blob_service.get_blob_to_text.assert_not_called()


@patch('azure-logs.update_row_object')
@patch('azure-logs.send_message')
def test_get_blobs_only_with_prefix(mock_send, mock_update):
    """Test get_blobs process only the blobs corresponding to a specific prefix, ignoring the rest."""
    azure.args = MagicMock(blobs=None, json_file=False, json_inline=False, reparse=False)

    prefix = "test_prefix"
    blob_date_str = parse(FUTURE_DATE)

    blob_list = [create_mocked_blob(blob_name=f"blob_{i}", last_modified=blob_date_str) for i in range(5)] + \
        [create_mocked_blob(blob_name=f"{prefix}/blob_{i}", last_modified=blob_date_str) for i in range(5)] + \
        [create_mocked_blob(blob_name=f"other_prefix/blob_{i}", last_modified=blob_date_str) for i in range(5)]

    # The first iteration will contain a full blob list and a none next_marker
    blob_service_iter_1 = MagicMock(next_marker=None)
    blob_service_iter_1.__iter__ = MagicMock(return_value=iter(blob_list))
    blob_service = MagicMock()
    blob_service.list_blobs.return_value = blob_service_iter_1
    blob_service.get_blob_to_text.return_value = MagicMock(content="")

    container_name = "container"
    md5_hash = "hash"

    azure.get_blobs(
        container_name=container_name, blob_service=blob_service, md5_hash=md5_hash, min_datetime=parse(PAST_DATE),
        max_datetime=parse(PRESENT_DATE), desired_datetime=parse(FUTURE_DATE), prefix=prefix
    )

    blob_service.list_blobs.assert_called_with(container_name, prefix=prefix, marker=None)
    blob_service.get_blob_to_text.assert_has_calls(
        [call(container_name, blob.name) for blob in blob_list if prefix in blob.name]
    )


@patch('azure-logs.logging.error')
def test_get_blobs_list_blobs_ko(mock_logging):
    """Test get_blobs_list_blobs handles exceptions from 'list_blobs'."""
    m = MagicMock()
    m.list_blobs.side_effect = azure.AzureException

    with pytest.raises(azure.AzureException):
        azure.get_blobs(container_name=None, blob_service=m, md5_hash=None, min_datetime=None,
                        max_datetime=None, desired_datetime=None)
    mock_logging.assert_called_once()


@pytest.mark.parametrize('exception', [ValueError, azure.AzureException, azure.AzureHttpError(message="", status_code="")])
@patch('azure-logs.logging.error')
@patch('azure-logs.update_row_object')
def test_get_blobs_blob_data_ko(mock_update, mock_logging, exception):
    """Test get_blobs_list_blobs handles exceptions from 'get_blob_to_text'."""
    azure.args = MagicMock(blobs=None, reparse=True)
    num_blobs = 5
    blob_list = [create_mocked_blob(blob_name=f"blob_{i}") for i in range(num_blobs)]
    blob_service_iter = MagicMock(next_marker=None)
    blob_service_iter.__iter__ = MagicMock(return_value=iter(blob_list))
    blob_service = MagicMock()
    blob_service.list_blobs.return_value = blob_service_iter
    blob_service.get_blob_to_text.side_effect = exception

    azure.get_blobs(container_name=None, blob_service=blob_service, md5_hash=None,
                    min_datetime=None, max_datetime=None,
                    desired_datetime=None)
    assert mock_logging.call_count == num_blobs
    mock_update.assert_not_called()


@pytest.mark.parametrize('exception', [json.JSONDecodeError, TypeError, KeyError])
@patch('azure-logs.logging.error')
@patch('azure-logs.loads')
@patch('azure-logs.update_row_object')
def test_get_blobs_json_ko(mock_update, mock_loads, mock_logging, exception):
    """Test get_blobs_list_blobs handles exceptions from 'json.loads'."""
    azure.args = MagicMock(blobs=None, reparse=True, json_file=True)
    num_blobs = 5
    blob_list = [create_mocked_blob(blob_name=f"blob_{i}") for i in range(num_blobs)]
    blob_service_iter = MagicMock(next_marker=None)
    blob_service_iter.__iter__ = MagicMock(return_value=iter(blob_list))
    blob_service = MagicMock()
    blob_service.list_blobs.return_value = blob_service_iter
    blob_service.get_blob_to_text.return_value = MagicMock(content="invalid")
    mock_loads.side_effect = exception

    azure.get_blobs(container_name=None, blob_service=blob_service, md5_hash=None,
                    min_datetime=None, max_datetime=None,
                    desired_datetime=None)
    assert mock_logging.call_count == num_blobs
    mock_update.assert_not_called()


@patch('azure-logs.post')
def test_get_token(mock_post):
    """Test get_token makes the expected token request and returns its value."""
    expected_token = "token"
    client_id = "client"
    secret = "secret"
    scope = "scope"
    domain = "domain"
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': scope,
        'grant_type': 'client_credentials'
    }
    m = MagicMock()
    m.json.return_value = {"access_token": expected_token}
    mock_post.return_value = m
    token = azure.get_token(client_id, secret, domain, scope)
    auth_url = f'{azure.URL_LOGGING}/{domain}/oauth2/v2.0/token'
    mock_post.assert_called_with(auth_url, data=body, timeout=10)
    assert token == expected_token


@pytest.mark.parametrize('exception, error_msg, error_codes', [
    (azure.RequestException, None, None),
    (None, 'unauthorized_client', None),
    (None, 'invalid_client', None),
    (None, 'invalid_request', [0]),
    (None, 'invalid_request', [0, 90002]),
    (None, 'invalid', []),
    (None, '', []),
    (None, None, [])
])
@patch('azure-logs.logging.error')
@patch('azure-logs.post')
def test_get_token_ko(mock_post, mock_logging, exception, error_msg, error_codes):
    """Test get_token handles exceptions when the 'access_token' field is not present in the response."""
    m = MagicMock()
    m.json.return_value = {"error": error_msg, 'error_codes': error_codes}
    mock_post.return_value = m
    mock_post.side_effect = exception
    with pytest.raises(SystemExit) as err:
        azure.get_token(client_id=None, secret=None, domain=None, scope=None)
    assert err.value.code == 1
    mock_logging.assert_called_once()


@patch('azure-logs.socket.close')
@patch('azure-logs.socket.send')
@patch('azure-logs.socket.connect')
def test_send_message(mock_connect, mock_send, mock_close):
    """Test send_message sends the messages to the Wazuh queue socket."""
    message = "msg"
    azure.send_message(message)
    mock_connect.assert_called_with(azure.ANALYSISD)
    mock_send.assert_called_with(f'{azure.SOCKET_HEADER}{message}'.encode(errors='replace'))
    mock_close.assert_called_once()


@pytest.mark.parametrize('error_code', [111, 90, 1])
@patch('azure-logs.logging.error')
@patch('azure-logs.socket.close')
@patch('azure-logs.socket.send')
@patch('azure-logs.socket.connect')
def test_send_message_ko(mock_connect, mock_send, mock_close, mock_logging, error_code):
    """Test send_message handle the socket exceptions."""
    s = socket.error()
    s.errno = error_code
    mock_send.side_effect = s

    if error_code == 90:
        azure.send_message("")
    else:
        with pytest.raises(SystemExit) as err:
            azure.send_message("")
        assert err.value.code == 1
    mock_close.assert_called_once()
    mock_logging.assert_called_once()


@pytest.mark.parametrize('offset, expected_date', [
    ("1d", "2022-12-30T12:00:00.000000Z"),
    ("1h", "2022-12-31T11:00:00.000000Z"),
    ("1m", "2022-12-31T11:59:00.000000Z")
])
@patch('azure-logs.datetime')
def test_offset_to_datetime(mock_time, offset, expected_date):
    """Test offset_to_datetime returns the expected values for the offset provided."""
    mock_time.utcnow.return_value = parse("2022-12-31T12:00:00.000000Z")
    result = azure.offset_to_datetime(offset)
    assert result == parse(expected_date)


@patch('azure-logs.logging.error')
@patch('azure-logs.datetime')
def test_offset_to_datetime_ko(mock_time, mock_logging):
    """Test offset_to_datetime handles the exception when an invalid offset format was provided."""
    with pytest.raises(SystemExit) as err:
        azure.offset_to_datetime("1x")
    assert err.value.code == 1
    mock_logging.assert_called_once()
