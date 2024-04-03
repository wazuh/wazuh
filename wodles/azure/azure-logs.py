#!/usr/bin/env python3

###
# Integration of Wazuh agent with Microsoft Azure
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
###

################################################################################################
# pip install azure
# https://github.com/Azure/azure-sdk-for-python
# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
################################################################################################
import logging
import sys
from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from hashlib import md5
from json import dumps, loads, JSONDecodeError
from os.path import abspath, dirname
from socket import socket, AF_UNIX, SOCK_DGRAM, error as socket_error

from azure.common import AzureException, AzureHttpError
from azure.storage.blob import BlockBlobService
from azure.storage.common._error import AzureSigningError
from azure.storage.common.retry import no_retry
from dateutil.parser import parse
from requests import get, post, HTTPError, RequestException

import orm

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from utils import ANALYSISD, MAX_EVENT_SIZE


# URLs
URL_LOGGING = 'https://login.microsoftonline.com'
URL_ANALYTICS = 'https://api.loganalytics.io'
URL_GRAPH = 'https://graph.microsoft.com'

SOCKET_HEADER = '1:Azure:'

DATETIME_MASK = '%Y-%m-%dT%H:%M:%S.%fZ'

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s azure: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_LEVELS = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}


def set_logger():
    """Set the logger configuration."""
    logging.basicConfig(level=LOG_LEVELS.get(args.debug_level, logging.INFO), format=LOGGING_MSG_FORMAT,
                        datefmt=LOGGING_DATE_FORMAT)
    logging.getLogger('azure').setLevel(LOG_LEVELS.get(args.debug_level, logging.WARNING))
    logging.getLogger('urllib3').setLevel(logging.ERROR)


def get_script_arguments():
    """Read and parse arguments."""
    parser = ArgumentParser()

    # only one must be present (log_analytics, graph or storage)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--log_analytics", action='store_true', required=False, help="Activates Log Analytics API call.")
    group.add_argument("--graph", action='store_true', required=False, help="Activates Graph API call.")
    group.add_argument("--storage", action="store_true", required=False, help="Activates Storage API call.")

    # Log Analytics arguments #
    parser.add_argument("--la_auth_path", metavar="filepath", type=str, required=False,
                        help="Path of the file containing the credentials for authentication.")
    parser.add_argument("--la_tenant_domain", metavar="domain", type=str, required=False,
                        help="Tenant domain for Log Analytics.")
    parser.add_argument("--la_query", metavar="query", required=False,
                        help="Query for Log Analytics.", type=arg_valid_la_query)
    parser.add_argument("--workspace", metavar="workspace", type=str, required=False,
                        help="Workspace for Log Analytics.")
    parser.add_argument("--la_tag", metavar="tag", type=str, required=False,
                        help="Tag that is added to the query result.")
    parser.add_argument("--la_time_offset", metavar="time", type=str, required=False,
                        help="Time range for the request.")

    # Graph arguments #
    parser.add_argument("--graph_auth_path", metavar="filepath", type=str, required=False,
                        help="Path of the file containing the credentials authentication.")
    parser.add_argument("--graph_tenant_domain", metavar="domain", type=str, required=False,
                        help="Tenant domain for Graph.")
    parser.add_argument("--graph_query", metavar="query", required=False, type=arg_valid_graph_query,
                        help="Query for Graph.")
    parser.add_argument("--graph_tag", metavar="tag", type=str, required=False,
                        help="Tag that is added to the query result.")
    parser.add_argument("--graph_time_offset", metavar="time", type=str, required=False,
                        help="Time range for the request.")

    # Storage arguments #
    parser.add_argument("--storage_auth_path", metavar="filepath", type=str, required=False,
                        help="Path of the file containing the credentials authentication.")
    parser.add_argument("--container", metavar="container", required=False, type=arg_valid_container_name,
                        help="Name of the container where searches the blobs.")
    parser.add_argument("--blobs", metavar="blobs", required=False, type=arg_valid_blob_extension,
                        help="Extension of blobs. For example: '*.log'")
    parser.add_argument("--storage_tag", metavar="tag", type=str, required=False,
                        help="Tag that is added to each blob request.")
    parser.add_argument("--json_file", action="store_true", required=False,
                        help="Specifies that the blob is only composed of events in json file format. "
                             "By default, the content of the blob is considered to be plain text.")
    parser.add_argument("--json_inline", action="store_true", required=False,
                        help="Specifies that the blob is only composed of events in json inline format. "
                             "By default, the content of the blob is considered to be plain text.")
    parser.add_argument("--storage_time_offset", metavar="time", type=str, required=False,
                        help="Time range for the request.")
    parser.add_argument('-p', '--prefix', dest='prefix', help='The relative path to the logs', type=str, required=False)


    # General parameters #
    parser.add_argument('--reparse', action='store_true', dest='reparse',
                        help='Parse the log, even if its been parsed before', default=False)
    parser.add_argument('-d', '--debug', action='store', type=int, dest='debug_level', default=0,
                        help='Specify debug level. Admits values from 0 to 2.')

    return parser.parse_args()


def arg_valid_container_name(arg_string):
    return arg_string.replace('"', '') if arg_string else arg_string


def arg_valid_graph_query(arg_string):
    if arg_string:
        if arg_string[0] == "'":
            arg_string = arg_string[1:]
        if arg_string[-1] == "'":
            arg_string = arg_string[:-1]
        return arg_string.replace('\\$', '$')


def arg_valid_la_query(arg_string):
    return arg_string.replace('\\!', '!') if arg_string else arg_string


def arg_valid_blob_extension(arg_string):
    return arg_string.replace('"', '').replace("*", "") if arg_string else arg_string


def read_auth_file(auth_path: str, fields: tuple):
    """Read the authentication file. Its contents must be in 'field = value' format.

    Parameters
    ----------
    auth_path : str
        Path to the authentication file.
    fields : tuple
        Tuple of 2 str field names expected to be in the authentication file.

    Returns
    -------
    tuple of str
        The field values for the requested authentication fields.
    """
    credentials = {}
    try:
        with open(auth_path, 'r') as auth_file:
            for line in auth_file:
                key, value = line.replace(" ", "").replace("\n", "").split("=", maxsplit=1)
                if not value:
                    continue
                credentials[key] = value.replace("\n", "")
        if fields[0] not in credentials or fields[1] not in credentials:
            logging.error(f"Error: The authentication file does not contains the expected '{fields[0]}' "
                          f"and '{fields[1]}' fields.")
            sys.exit(1)
        return credentials[fields[0]], credentials[fields[1]]
    except ValueError:
        logging.error("Error: The authentication file format is not valid. "
                      "Make sure that it is composed of only 2 lines with 'field = value' format.")
        sys.exit(1)
    except OSError as e:
        logging.error(f"Error: The authentication file could not be opened: {e}")
        sys.exit(1)


def update_row_object(table: orm.Base, md5_hash: str, new_min: str, new_max: str, query: str = None):
    """Update the database with the specified values if applicable.

    Parameters
    ----------
    table : orm.Base
        Database table reference for the service.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.
    new_min : str
        Value to compare with the current min value stored.
    new_max : str
        Value to compare with the current max value stored.
    query : str
        Query value before applying the md5 hash transformation.
    """
    try:
        row = orm.get_row(table=table, md5=md5_hash)
        old_min_str = row.min_processed_date
        old_max_str = row.max_processed_date
    except (orm.AzureORMError, AttributeError) as e:
        logging.error(f"Error trying to obtain row object from '{table.__tablename__}' using md5='{md5}': {e}")
        sys.exit(1)
    old_min_date = parse(old_min_str, fuzzy=True)
    old_max_date = parse(old_max_str, fuzzy=True)
    # "parse" adds compatibility with "last_dates_files" from previous releases as the format wasn't localized
    # It also handles any datetime with more than 6 digits for the microseconds value provided by Azure
    new_min_date = parse(new_min, fuzzy=True)
    new_max_date = parse(new_max, fuzzy=True)
    if new_min_date < old_min_date or new_max_date > old_max_date:
        min_ = new_min if new_min_date < old_min_date else old_min_str
        max_ = new_max if new_max_date > old_max_date else old_max_str
        logging.debug(f"Attempting to update a {table.__tablename__} row object. "
                      f"MD5: '{md5_hash}', min_date: '{min_}', max_date: '{max_}'")
        try:
            orm.update_row(table=table, md5=md5_hash, min_date=min_, max_date=max_, query=query)
        except orm.AzureORMError as e:
            logging.error(f"Error updating row object from {table.__tablename__}: {e}")
            sys.exit(1)


def create_new_row(table: orm.Base, md5_hash: str, query: str, offset: str) -> orm.Base:
    """Create a new row object for the given table, insert it into the database and return it.

    Parameters
    ----------
    table : orm.Base
        Database table reference for the service.
    md5_hash : str
        md5 value used as the key for the table.
    query : str
        The query value before applying the md5 transformation.
    offset : str
        Value used to determine the desired datetime.

    Returns
    -------
    orm.Base
        A copy of the inserted row object.
    """
    logging.info(f"{md5_hash} was not found in the database for {table.__tablename__}. Adding it.")
    desired_datetime = offset_to_datetime(offset) if offset else datetime.utcnow().replace(hour=0, minute=0,
                                                                                           second=0, microsecond=0)
    desired_str = desired_datetime.strftime(DATETIME_MASK)
    item = table(md5=md5_hash, query=query, min_processed_date=desired_str, max_processed_date=desired_str)
    logging.debug(f"Attempting to insert row object into {table.__tablename__} with md5='{md5_hash}', "
                  f"min_date='{desired_str}', max_date='{desired_str}'")
    try:
        orm.add_row(row=item)
    except orm.AzureORMError as e:
        logging.error(f"Error inserting row object into {table.__tablename__}: {e}")
        sys.exit(1)
    return item


# LOG ANALYTICS

def start_log_analytics():
    """Run the Log Analytics integration processing the logs available for the given time offset. The client or
    application must have "Contributor" permission to read Log Analytics."""
    logging.info("Azure Log Analytics starting.")

    # Read credentials
    if args.la_auth_path and args.la_tenant_domain:
        client, secret = read_auth_file(auth_path=args.la_auth_path, fields=("application_id", "application_key"))
    else:
        logging.error("Log Analytics: No parameters have been provided for authentication.")
        sys.exit(1)

    # Get authentication token
    logging.info("Log Analytics: Getting authentication token.")
    token = get_token(client_id=client, secret=secret, domain=args.la_tenant_domain, scope=f'{URL_ANALYTICS}/.default')

    # Build the request
    md5_hash = md5(args.la_query.encode()).hexdigest()
    url = f"{URL_ANALYTICS}/v1/workspaces/{args.workspace}/query"
    body = build_log_analytics_query(offset=args.la_time_offset, md5_hash=md5_hash)
    headers = {"Authorization": f"Bearer {token}"}

    # Get the logs
    try:
        get_log_analytics_events(url=url, body=body, headers=headers, md5_hash=md5_hash)
    except HTTPError as e:
        logging.error(f"Log Analytics: {e}")
    logging.info("Azure Log Analytics ending.")


def build_log_analytics_query(offset: str, md5_hash: str) -> dict:
    """Prepare and make the request, building the query based on the time of event generation.

    Parameters
    ----------
    offset : str
        The filtering condition for the query.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.

    Returns
    -------
    dict
        The required body for the requested query.
    """
    try:
        item = orm.get_row(orm.LogAnalytics, md5=md5_hash)
        if item is None:
            item = create_new_row(table=orm.LogAnalytics, query=args.la_query, md5_hash=md5_hash, offset=offset)
    except orm.AzureORMError as e:
        logging.error(f"Error trying to obtain row object from '{orm.LogAnalytics.__tablename__}' using md5='{md5}': "
                      f"{e}")
        sys.exit(1)

    min_str = item.min_processed_date
    max_str = item.max_processed_date
    min_datetime = parse(min_str, fuzzy=True)
    max_datetime = parse(max_str, fuzzy=True)
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_str = f"datetime({desired_datetime.strftime(DATETIME_MASK)})"
    min_str = f"datetime({min_str})"
    max_str = f"datetime({max_str})"

    # If reparse was provided, get the logs ignoring if they were already processed
    if args.reparse:
        filter_value = f"TimeGenerated >= {desired_str}"
    # Build the filter taking into account the min and max values from the file
    else:
        # Build the filter taking into account the min and max values
        if desired_datetime < min_datetime:
            filter_value = f"( TimeGenerated < {min_str} and TimeGenerated >= {desired_str}) or " \
                           f"( TimeGenerated > {max_str})"
        elif desired_datetime > max_datetime:
            filter_value = f"TimeGenerated >= {desired_str}"
        else:
            filter_value = f"TimeGenerated > {max_str}"

    query = f"{args.la_query} | order by TimeGenerated asc | where {filter_value} "
    logging.info(f"Log Analytics: The search starts for query: '{query}'")
    return {"query": query}


def get_log_analytics_events(url: str, body: dict, headers: dict, md5_hash: str):
    """Get the logs, process the response and iterate the events.

    Parameters
    ----------
    url : str
        The url for the request.
    body : dict
        Body for the request containing the query.
    headers : dict
        The header for the request, containing the authentication token.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.

    Raises
    ------
    HTTPError
        If the response for the request is not 200 OK.
    """
    logging.info("Log Analytics: Sending a request to the Log Analytics API.")
    response = get(url, params=body, headers=headers, timeout=10)
    if response.status_code == 200:
        try:
            columns = response.json()['tables'][0]['columns']
            rows = response.json()['tables'][0]['rows']
            if len(rows) == 0:
                logging.info("Log Analytics: There are no new results")
            else:
                time_position = get_time_position(columns)
                if time_position is not None:
                    iter_log_analytics_events(columns, rows)
                    update_row_object(table=orm.LogAnalytics, md5_hash=md5_hash, new_min=rows[0][time_position],
                                      new_max=rows[len(rows) - 1][time_position], query=args.la_query)
                else:
                    logging.error("Error: No TimeGenerated field was found")

        except KeyError as e:
            logging.error(f"Error: It was not possible to obtain the columns and rows from the event: '{e}'.")
    else:
        response.raise_for_status()


def get_time_position(columns: list):
    """Get the position of the 'TimeGenerated' field in the columns list.

    Parameters
    ----------
    columns : list
        List of columns of the log analytic logs.

    Returns
    -------
    int or None
        The index of the 'TimeGenerated' field in the given list or None if it's not present.
    """
    for i in range(0, len(columns)):
        if columns[i]['name'] == 'TimeGenerated':
            return i


def iter_log_analytics_events(columns: list, rows: list):
    """Iterate through the columns and rows to build the events and send them to the socket.

    Parameters
    ----------
    columns : list
        List of dicts containing the names and the types of each column.
    rows : list
        List of rows containing the values for each column. Each rows is an event.
    """
    # Add tag columns
    columns.append({'type': 'string', 'name': 'azure_tag'})
    if args.la_tag:
        columns.append({'type': 'string', 'name': 'log_analytics_tag'})

    for row in rows:
        # Add tag values
        row.append("azure-log-analytics")
        if args.la_tag:
            row.append(args.la_tag)

        # Build the events and send them
        event = {}
        for c in range(0, len(columns)):
            event[columns[c]['name']] = row[c]
        logging.info("Log Analytics: Sending event by socket.")
        send_message(dumps(event))


# GRAPH

def start_graph():
    """Run the Microsoft Graph integration processing the logs available for the given query and offset values in
    the configuration. The client or application must have permission to access Microsoft Graph."""
    logging.info("Azure Graph starting.")

    # Read credentials
    if args.graph_auth_path and args.graph_tenant_domain:
        client, secret = read_auth_file(auth_path=args.graph_auth_path, fields=("application_id", "application_key"))
    else:
        logging.error("Graph: No parameters have been provided for authentication.")
        sys.exit(1)

    # Get the token
    logging.info("Graph: Getting authentication token.")
    token = get_token(client_id=client, secret=secret, domain=args.graph_tenant_domain, scope=f"{URL_GRAPH}/.default")
    headers = {'Authorization': f'Bearer {token}'}

    # Build the query
    logging.info(f"Graph: Building the url.")
    md5_hash = md5(args.graph_query.encode()).hexdigest()
    url = build_graph_url(offset=args.graph_time_offset, md5_hash=md5_hash)
    logging.info(f"Graph: The URL is '{url}'")

    # Get events
    logging.info("Graph: Pagination starts")
    try:
        get_graph_events(url=url, headers=headers, md5_hash=md5_hash)
    except HTTPError as e:
        logging.error(f"Graph: {e}")
    logging.info("Graph: End")


def build_graph_url(offset: str, md5_hash: str):
    """Build the URL to use with the specified service filtering its results by the desired_datetime.

    Parameters
    ----------
    offset : str
        The filtering condition for the query.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.

    Returns
    -------
    str
        The required URL for the requested query.
    """
    try:
        item = orm.get_row(orm.Graph, md5=md5_hash)
        if item is None:
            item = create_new_row(table=orm.Graph, query=args.graph_query, md5_hash=md5_hash, offset=offset)
    except orm.AzureORMError as e:
        logging.error(f"Error trying to obtain row object from '{orm.Graph.__tablename__}' using md5='{md5}': {e}")
        sys.exit(1)

    min_str = item.min_processed_date
    max_str = item.max_processed_date
    min_datetime = parse(min_str, fuzzy=True)
    max_datetime = parse(max_str, fuzzy=True)
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_str = desired_datetime.strftime(DATETIME_MASK)
    filtering_condition = "createdDateTime" if "signins" in args.graph_query.lower() else "activityDateTime"

    # If reparse was provided, get the logs ignoring if they were already processed
    if args.reparse:
        filter_value = f"{filtering_condition}+ge+{desired_str}"
    # Build the filter taking into account the min and max values from the file
    else:
        if desired_datetime < min_datetime:
            filter_value = f"({filtering_condition}+lt+{min_str}+and+{filtering_condition}+ge+{desired_str})" \
                           f"+or+({filtering_condition}+gt+{max_str})"
        elif desired_datetime > max_datetime:
            filter_value = f"{filtering_condition}+ge+{desired_str}"
        else:
            filter_value = f"{filtering_condition}+gt+{max_str}"

    logging.info(f"Graph: The search starts for query: '{args.graph_query}' using {filter_value}")
    return f"{URL_GRAPH}/v1.0/{args.graph_query}{'?' if '?' not in args.graph_query else ''}&$filter={filter_value}"


def get_graph_events(url: str, headers: dict, md5_hash: str):
    """Request the data using the specified url and process the values in the response.

    Parameters
    ----------
    url : str
        The url for the request.
    headers : dict
        The header for the request, containing the authentication token.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.

    Raises
    ------
    HTTPError
        If the response for the request is not 200 OK.
    """
    response = get(url=url, headers=headers, timeout=10)

    if response.status_code == 200:
        response_json = response.json()
        values_json = response_json.get('value')
        for value in values_json:
            try:
                date = value["activityDateTime"]
            except KeyError:
                date = value["createdDateTime"]
            update_row_object(table=orm.Graph, md5_hash=md5_hash, new_min=date, new_max=date, query=args.graph_query)
            value["azure_tag"] = "azure-ad-graph"
            if args.graph_tag:
                value['azure_aad_tag'] = args.graph_tag
            json_result = dumps(value)
            logging.info("Graph: Sending event by socket.")
            send_message(json_result)

        if len(values_json) == 0:
            logging.info("Graph: There are no new results")
        next_url = response_json.get('@odata.nextLink')

        if next_url:
            get_graph_events(url=next_url, headers=headers, md5_hash=md5_hash)
    elif response.status_code == 400:
        logging.error(f"Bad Request for url: {response.url}")
        logging.error(f"Ensure the URL is valid and there is data available for the specified datetime.")
    else:
        response.raise_for_status()


# STORAGE

def start_storage():
    """Get access and content of the storage accounts."""
    logging.info("Azure Storage starting.")

    # Read credentials
    logging.info("Storage: Authenticating.")
    if args.storage_auth_path:
        name, key = read_auth_file(auth_path=args.storage_auth_path, fields=("account_name", "account_key"))
    else:
        logging.error("Storage: No parameters have been provided for authentication.")
        sys.exit(1)

    block_blob_service = BlockBlobService(account_name=name, account_key=key)

    # Disable max retry value before attempting to validate the credentials
    old_retry_value = block_blob_service.retry
    block_blob_service.retry = no_retry

    # Verify if the credentials grant access to the specified container
    if args.container != '*':
        try:
            if not block_blob_service.exists(args.container):
                logging.error(f"Storage: The '{args.container}' container does not exists.")
                sys.exit(1)
            containers = [args.container]
        except AzureException:
            logging.error(f"Storage: Invalid credentials for accessing the '{args.container}' container.")
            sys.exit(1)
    else:
        try:
            logging.info("Storage: Getting containers.")
            containers = [container.name for container in block_blob_service.list_containers()]
        except AzureSigningError:
            logging.error("Storage: Unable to list the containers. Invalid credentials.")
            sys.exit(1)
        except AzureException as e:
            logging.error(f"Storage: The containers could not be listed: '{e}'.")
            sys.exit(1)

    # Restore the default max retry value
    block_blob_service.retry = old_retry_value
    logging.info("Storage: Authenticated.")

    # Get the blobs
    for container in containers:
        md5_hash = md5(name.encode()).hexdigest()
        offset = args.storage_time_offset
        try:
            item = orm.get_row(orm.Storage, md5=md5_hash)
            if item is None:
                item = create_new_row(table=orm.Storage, query=name, md5_hash=md5_hash, offset=offset)
        except orm.AzureORMError as e:
            logging.error(f"Error trying to obtain row object from '{orm.Storage.__tablename__}' using md5='{md5}': {e}")
            sys.exit(1)

        min_datetime = parse(item.min_processed_date, fuzzy=True)
        max_datetime = parse(item.max_processed_date, fuzzy=True)
        desired_datetime = offset_to_datetime(offset) if offset else max_datetime
        get_blobs(container_name=container, prefix=args.prefix, blob_service=block_blob_service, md5_hash=md5_hash,
                  min_datetime=min_datetime, max_datetime=max_datetime, desired_datetime=desired_datetime)
    logging.info("Storage: End")


def get_blobs(
    container_name: str, blob_service: BlockBlobService, md5_hash: str, min_datetime: datetime, max_datetime: datetime,
    desired_datetime: datetime, next_marker: str = None, prefix: str = None
):
    """Get the blobs from a container and send their content.

    Parameters
    ----------
    container_name : str
        Name of container to read the blobs from.
    blob_service : BlockBlobService
        Client used to obtain the blobs.
    min_datetime : datetime
        Value to compare with the blobs last modified times.
    max_datetime : datetime
        Value to compare with the blobs last modified times.
    desired_datetime : datetime
        Value to compare with the blobs last modified times.
    md5_hash : str
        md5 value used to search the container in the file containing the dates.
    next_marker : str
        Token used as a marker to continue from previous iteration.
    prefix : str, optional
        Prefix value to search blobs that match with it.

    Raises
    ------
    AzureException
        If it was not possible to list the blobs for the given container.
    """
    try:
        # Get the blob list
        logging.info("Storage: Getting blobs.")
        blobs = blob_service.list_blobs(container_name, prefix=prefix, marker=next_marker)
    except AzureException as e:
        logging.error(f"Storage: Error getting blobs from '{container_name}': '{e}'.")
        raise e
    else:

        logging.info(f"Storage: The search starts from the date: {desired_datetime} for blobs in "
                     f"container: '{container_name}' and prefix: '/{prefix if prefix is not None else ''}'")
        for blob in blobs:
            # Skip if the blob is empty
            if blob.properties.content_length == 0:
                logging.debug(f"Empty blob {blob.name}, skipping")
                continue
            # Skip the blob if nested under the set prefix
            if prefix is not None and len(blob.name.split("/")) > 2:
                logging.debug(f"Skipped blob {blob.name}, nested under set prefix {prefix}")
                continue
            # Skip the blob if its name has not the expected format
            if args.blobs and args.blobs not in blob.name:
                logging.debug(f"Skipped blob, name {blob.name} does not match with the format '{args.blobs}'")
                continue

            # Skip the blob if already processed
            last_modified = blob.properties.last_modified
            if not args.reparse and (last_modified < desired_datetime or (
                    min_datetime <= last_modified <= max_datetime)):
                continue

            # Get the blob data
            try:
                data = blob_service.get_blob_to_text(container_name, blob.name)
            except (ValueError, AzureException, AzureHttpError) as e:
                logging.error(f"Storage: Error reading the blob data: '{e}'.")
                continue
            else:
                # Process the data as a JSON
                if args.json_file:
                    try:
                        content_list = loads(data.content)
                        records = content_list["records"]
                    except (JSONDecodeError, TypeError) as e:
                        logging.error(f"Storage: Error reading the contents of the blob: '{e}'.")
                        continue
                    except KeyError as e:
                        logging.error(f"Storage: No records found in the blob's contents: '{e}'.")
                        continue
                    else:
                        for log_record in records:
                            # Add azure tags
                            log_record['azure_tag'] = 'azure-storage'
                            if args.storage_tag:
                                log_record['azure_storage_tag'] = args.storage_tag
                            logging.info("Storage: Sending event by socket.")
                            send_message(dumps(log_record))
                # Process the data as plain text
                else:
                    for line in [s for s in str(data.content).splitlines() if s]:
                        if args.json_inline:
                            msg = '{"azure_tag": "azure-storage"'
                            if args.storage_tag:
                                msg = f'{msg}, "azure_storage_tag": "{args.storage_tag}"'
                            msg = f'{msg}, {line[1:]}'
                        else:
                            msg = "azure_tag: azure-storage."
                            if args.storage_tag:
                                msg = f'{msg} azure_storage_tag: {args.storage_tag}.'
                            msg = f'{msg} {line}'
                        logging.info("Storage: Sending event by socket.")
                        send_message(msg)
            update_row_object(table=orm.Storage, md5_hash=md5_hash, query=container_name,
                              new_min=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                              new_max=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))

        # Continue until no marker is returned
        if blobs.next_marker:
            get_blobs(container_name=container_name, blob_service=blob_service, next_marker=blobs.next_marker,
                      min_datetime=min_datetime, max_datetime=max_datetime, desired_datetime=desired_datetime,
                      md5_hash=md5_hash)


def get_token(client_id: str, secret: str, domain: str, scope: str):
    """Get the authentication token for accessing a given resource in the specified domain.

    Parameters
    ----------
    client_id : str
        The client ID.
    secret : str
        The client secret.
    domain : str
        The tenant domain.
    scope : str
        The scope for the token requested.

    Returns
    -------
    str
        A valid token.
    """
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': scope,
        'grant_type': 'client_credentials'
    }
    auth_url = f'{URL_LOGGING}/{domain}/oauth2/v2.0/token'
    try:
        token_response = post(auth_url, data=body, timeout=10).json()
        return token_response['access_token']
    except (ValueError, KeyError):
        if token_response['error'] == 'unauthorized_client':
            err_msg = "The application id provided is not valid."
        elif token_response['error'] == 'invalid_client':
            err_msg = "The application key provided is not valid."
        elif token_response['error'] == 'invalid_request' and 90002 in token_response['error_codes']:
            err_msg = f"The '{domain}' tenant domain was not found."
        else:
            err_msg = "Couldn't get the token for authentication."
        logging.error(f"Error: {err_msg}")

    except RequestException as e:
        logging.error(f"Error: An error occurred while trying to obtain the authentication token: {e}")

    sys.exit(1)


def send_message(message: str):
    """Send a message with a header to the analysisd queue.

    Parameters
    ----------
    message : str
        The message body to send to analysisd.
    """
    s = socket(AF_UNIX, SOCK_DGRAM)
  
    try:
        msg = message
        sign_in_logs_matches = ['azure_aad_tag','azure-active_directory_signIns']
        if all([m in message for m in sign_in_logs_matches]):
            msg_tmp = loads(message)
            # Copy the status fields into a azureSignInStatus field and put a dummy keyword in status field
            # only if we have an signIn log from Microsoft Entra ID. Otherwise, the log remains unmodified.
            msg_tmp['azureSignInStatus'] = msg_tmp["status"]
            msg_tmp['status'] = 'None'
            msg = dumps(msg_tmp)
        encoded_msg = f'{SOCKET_HEADER}{msg}'.encode(errors='replace')

        # Logs warning if event is bigger than max size
        if len(encoded_msg) > MAX_EVENT_SIZE:
            logging.warning(f"WARNING: Event size exceeds the maximum allowed limit of {MAX_EVENT_SIZE} bytes.")
        s.connect(ANALYSISD)
        s.send(encoded_msg)
    except socket_error as e:
        if e.errno == 111:
            logging.error("ERROR: Wazuh must be running.")
            sys.exit(1)
        elif e.errno == 90:
            logging.error("ERROR: Message too long to send to Wazuh.  Skipping message...")
        else:
            logging.error(f"ERROR: Error sending message to wazuh: {e}")
            sys.exit(1)
    finally:
        s.close()


def offset_to_datetime(offset: str):
    """Transform an offset value to a datetime object.

    Parameters
    ----------
    offset : str
        A positive number containing a suffix character that indicates its time unit,
        such as, s (seconds), m (minutes), h (hours), d (days), w (weeks), M (months).

    Returns
    -------
    datetime
        The result of subtracting the offset value from the current datetime.
    """
    offset = offset.replace(" ", "")
    value = int(offset[:len(offset) - 1])
    unit = offset[len(offset) - 1:]

    if unit == 'h':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(hours=value)
    if unit == 'm':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(minutes=value)
    if unit == 'd':
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=value)

    logging.error("Invalid offset format. Use 'h', 'm' or 'd' time unit.")
    exit(1)


if __name__ == "__main__":
    args = get_script_arguments()
    set_logger()

    if not orm.check_database_integrity():
        sys.exit(1)

    if args.log_analytics:
        start_log_analytics()
    elif args.graph:
        start_graph()
    elif args.storage:
        start_storage()
    else:
        logging.error("No valid API was specified. Please use 'graph', 'log_analytics' or 'storage'.")
        sys.exit(1)
