#!/usr/bin/env python3

###
# Integration of Wazuh agent with Microsoft Azure
# Copyright (C) 2015-2021, Wazuh Inc.
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
from azure.common import AzureException, AzureHttpError
from azure.storage.blob import BlockBlobService
from datetime import datetime, timedelta
from dateutil.parser import parse
from hashlib import md5
from json import dump, dumps, load, loads, JSONDecodeError
from os import linesep
from os.path import abspath, dirname, exists, join
from pytz import UTC
from requests import get, post
from socket import socket, AF_UNIX, SOCK_DGRAM, error as socket_error
from typing import Union

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from utils import ANALYSISD, find_wazuh_path


date_file = "last_dates.json"
last_dates_file = join(dirname(abspath(__file__)), date_file)

# URLs
url_logging = 'https://login.microsoftonline.com'
url_analytics = 'https://api.loganalytics.io'
url_graph = 'https://graph.microsoft.com'

socket_header = '1:Azure:'

################################################################################################
# Read and parser arguments.
################################################################################################

parser = ArgumentParser()
parser.add_argument("-v", "--verbose", action='store_true', required=False, help="Debug mode.")

# Log Analytics arguments #
parser.add_argument("--log_analytics", action='store_true', required=False,
                    help="Activates Log Analytics API call.")
parser.add_argument("--la_id", metavar='ID', type=str, required=False,
                    help="Application ID for Log Analytics authentication.")
parser.add_argument("--la_key", metavar="KEY", type=str, required=False,
                    help="Application Key for Log Analytics authentication.")
parser.add_argument("--la_auth_path", metavar="filepath", type=str, required=False,
                    help="Path of the file containing the credentials for authentication.")
parser.add_argument("--la_tenant_domain", metavar="domain", type=str, required=False,
                    help="Tenant domain for Log Analytics.")
parser.add_argument("--la_query", metavar="query", type=str, required=False,
                    help="Query for Log Analytics.")
parser.add_argument("--workspace", metavar="workspace", type=str, required=False,
                    help="Workspace for Log Analytics.")
parser.add_argument("--la_tag", metavar="tag", type=str, required=False,
                    help="Tag that is added to the query result.")
parser.add_argument("--la_time_offset", metavar="time", type=str, required=False,
                    help="Time range for the request.")

# Graph arguments #
parser.add_argument("--graph", action='store_true', required=False,
                    help="Activates Graph API call.")
parser.add_argument("--graph_id", metavar='ID', type=str, required=False,
                    help="Application ID for Graph authentication.")
parser.add_argument("--graph_key", metavar="KEY", type=str, required=False,
                    help="Application KEY for Graph authentication.")
parser.add_argument("--graph_auth_path", metavar="filepath", type=str, required=False,
                    help="Path of the file containing the credentials authentication.")
parser.add_argument("--graph_tenant_domain", metavar="domain", type=str, required=False,
                    help="Tenant domain for Graph.")
parser.add_argument("--graph_query", metavar="query", type=str, required=False,
                    help="Query for Graph.")
parser.add_argument("--graph_tag", metavar="tag", type=str, required=False,
                    help="Tag that is added to the query result.")
parser.add_argument("--graph_time_offset", metavar="time", type=str, required=False,
                    help="Time range for the request.")

# Storage arguments #
parser.add_argument("--storage", action="store_true", required=False,
                    help="Activates Storage API call.")
parser.add_argument("--account_name", metavar='account', type=str, required=False,
                    help="Storage account name for authentication.")
parser.add_argument("--account_key", metavar='KEY', type=str, required=False,
                    help="Storage account key for authentication.")
parser.add_argument("--storage_auth_path", metavar="filepath", type=str, required=False,
                    help="Path of the file containing the credentials authentication.")
parser.add_argument("--container", metavar="container", type=str, required=False,
                    help="Name of the container where searches the blobs.")
parser.add_argument("--blobs", metavar="blobs", type=str, required=False,
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

# General parameters #
parser.add_argument('--reparse', action='store_true', dest='reparse',
                    help='Parse the log, even if its been parsed before', default=False)

args = parser.parse_args()

if args.la_query:
    la_format_query = args.la_query.replace('"', '')
if args.graph_query:
    graph_formatted_query = args.graph_query.replace("'", "")
if args.container:
    container_format = args.container.replace('"', '')
if args.blobs:
    blobs_format = args.blobs.replace('"', '')


def set_logger():
    """Set the logger configuration."""
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: AZURE %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    else:
        log_path = "{}/logs/azure_logs.log".format(find_wazuh_path())
        logging.basicConfig(filename=log_path, level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: AZURE %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


def read_auth_file(auth_path: str, fields: tuple):
    """Read the authentication file. Its contents must be in 'field = value' format.

    Parameters
    ----------
    auth_path : str
        Path to the authentication file
    fields : tuple
        Tuple of 2 str field names expected to be in the authentication file

    Returns
    -------
    A tuple with the field values for the requested authentication fields.
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
    except OSError as e:
        logging.error("Error: The authentication file could not be opened: '{}'".format(e))
        sys.exit(1)


def get_min_max(service_name: str, md5_hash: str, offset: str):
    """Get the min and max values from the "last_dates_file" for the given service.

    Parameters
    ----------
    service_name : str
        Name of the service to look up in the file
    md5_hash : str
        Hash of the query, used as the key in the last_dates dict
    offset : str
        The filtering condition for the query

    Returns
    -------
    A tuple with the min and max values
    """
    try:
        # Using "parse" adds compatibility with "last_dates_files" from previous releases as the format wasn't localized
        # It also handles any datetime with more than 6 digits for the microseconds value provided by Azure
        min_ = parse(dates_json[service_name][md5_hash]['min'], fuzzy=True)
        max_ = parse(dates_json[service_name][md5_hash]['max'], fuzzy=True)
    except KeyError:
        # The service name or the md5 value is not present in the dates file
        desired_datetime = offset_to_datetime(offset) if offset else datetime.now()
        logging.info(f"{md5_hash} was not found in {last_dates_file} for {service_name}. Updating the file")
        dates_json[service_name][md5_hash] = {'min': f"{desired_datetime}", 'max': f"{desired_datetime}"}
        min_ = max_ = UTC.localize(desired_datetime)
    return min_, max_


def load_dates_json():
    """Read the "last_dates_file" containing the different processed dates. It will be created with empty values in
    case it does not exist.

    Returns
    -------
    A dict with the contents of the "last_dates_file"
    """
    logging.info(f"Getting the data from {last_dates_file}.")
    try:
        if exists(last_dates_file):
            contents = load(open(last_dates_file))
            # This adds compatibility with "last_dates_files" from previous releases as the format was different
            for key in contents.keys():
                for md5_hash in contents[key].keys():
                    if not isinstance(contents[key][md5_hash], dict):
                        contents[key][md5_hash] = {"min": contents[key][md5_hash], "max": contents[key][md5_hash]}
        else:
            contents = {'log_analytics': {}, 'graph': {}, 'storage': {}}
            with open(join(last_dates_file), 'w') as file:
                dump(contents, file)
        return contents
    except (JSONDecodeError, OSError) as e:
        logging.error("Error: The file of the last dates could not be read: '{}.".format(e))
        sys.exit(1)


def save_dates_json(json_obj):
    """Save the json object containing the different processed dates in the "last_dates_file"."""
    logging.info(f"Updating {last_dates_file} file.")
    try:
        with open(join(last_dates_file), 'w') as jsonFile:
            dump(json_obj, jsonFile)
    except (TypeError, ValueError, OSError) as e:
        logging.error("Error: The file of the last dates could not be updated: '{}.".format(e))


def update_dates_json(new_min: str, new_max: str, service_name: str, md5_hash: str):
    """Update the dates_json dictionary with the specified values if applicable.

    Parameters
    ----------
    new_min : str
        Value to compare with the current min value stored.
    new_max : str
        Value to compare with the current max value stored.
    service_name : str
        Name of the service used as the key for the dates_json.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.
    """
    if parse(new_min, fuzzy=True) < parse(dates_json[service_name.lower()][md5_hash]["min"], fuzzy=True):
        dates_json[service_name.lower()][md5_hash]["min"] = new_min
    if parse(new_max, fuzzy=True) > parse(dates_json[service_name.lower()][md5_hash]["max"], fuzzy=True):
        dates_json[service_name.lower()][md5_hash]["max"] = new_max


# LOG ANALYTICS

def start_log_analytics():
    """Run the Log Analytics integration processing the logs available for the given time offset. The client or
    application must have "Contributor" permission to read Log Analytics."""
    logging.info("Azure Log Analytics starting.")

    # Read credentials
    if args.la_auth_path and args.la_tenant_domain:
        client, secret = read_auth_file(auth_path=args.la_auth_path, fields=("application_id", "application_key"))
    elif args.la_id and args.la_key and args.la_tenant_domain:
        client = args.la_id
        secret = args.la_key
    else:
        logging.error("Log Analytics: No parameters have been provided for authentication.")
        sys.exit(1)

    # Get authentication token
    logging.info("Log Analytics: Getting authentication token.")
    token = get_token(client_id=client, secret=secret, domain=args.la_tenant_domain, scope=f'{url_analytics}/.default')

    # Build the request
    md5_hash = md5(la_format_query.encode()).hexdigest()
    url = f"{url_analytics}/v1/workspaces/{args.workspace}/query"
    body = build_log_analytics_query(offset=args.la_time_offset, md5_hash=md5_hash)
    headers = {"Authorization": f"Bearer {token}"}

    # Get the logs
    get_log_analytics_events(url=url, body=body, headers=headers, md5_hash=md5_hash)
    logging.info("Azure Log Analytics ending.")


def build_log_analytics_query(offset: str, md5_hash: str):
    """Prepares and makes the request, building the query based on the time of event generation.

    Parameters
    ----------
    offset : str
        The filtering condition for the query
    md5_hash : str
        md5 value used to search the query in the file containing the dates

    Returns
    -------
    The required body for the requested query in dict format
    """
    min_datetime, max_datetime = get_min_max(service_name="log_analytics", md5_hash=md5_hash, offset=offset)
    # If no offset value was provided continue from the previous processed date
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_strf = f"datetime({desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"

    # If reparse was provided, get the logs ignoring if they were already processed
    if args.reparse:
        filter_value = f"TimeGenerated >= {desired_strf}"
    # Build the filter taking into account the min and max values from the file
    else:
        min_strf = f"datetime({min_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
        max_strf = f"datetime({max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"

        # Build the filter taking into account the min and max values
        if desired_datetime < min_datetime:
            filter_value = f"( TimeGenerated < {min_strf} and TimeGenerated >= {desired_strf} ) or " \
                           f"( TimeGenerated > {max_strf} )"
        elif desired_datetime > max_datetime:
            filter_value = f"TimeGenerated >= {desired_strf}"
        else:
            filter_value = f"TimeGenerated > {max_strf}"

    query = f"{la_format_query} | order by TimeGenerated asc | where {filter_value} "
    logging.info(f"Log Analytics: The search starts for query: '{query}'")
    return {"query": query}


def get_log_analytics_events(url: str, body: dict, headers: dict, md5_hash: str):
    """ Obtains the list with the last time generated of each query.

    Parameters
    ----------
    url : str
        The url for the request
    body : dict
        Body for the request containing the query
    headers : dict
        The header for the request, containing the authentication token
    md5_hash : str
        md5 value used to search the query in the file containing the dates

    Raises
    ------
    HTTPError if the response for the request is not 200 OK.
    """
    logging.info("Log Analytics: Sending a request to the Log Analytics API.")
    response = get(url, params=body, headers=headers)
    if response.status_code == 200:
        try:
            columns = response.json()['tables'][0]['columns']
            rows = response.json()['tables'][0]['rows']

            if len(rows) == 0:
                logging.info("Log Analytics: There are no new results")
            elif time_position := get_time_position(columns):
                iter_log_analytics_events(columns, rows)
                update_dates_json(new_min=rows[0][time_position],
                                  new_max=rows[len(rows) - 1][time_position],
                                  service_name="log_analytics",
                                  md5_hash=md5_hash)
                save_dates_json(dates_json)
            else:
                logging.error("Error: No TimeGenerated field was found")

        except KeyError as e:
            logging.error("Error: It was not possible to obtain the columns and rows from the event: '{}'.".format(e))
    else:
        response.raise_for_status()


def get_time_position(columns: list):
    """Get the position of the 'TimeGenerated' field in the columns list.

    Parameters
    ----------
    columns : list
        List of columns of the log analytic logs

    Returns
    -------
    The index of the 'TimeGenerated' field in the given list or None if it's not present.
    """
    for i in range(0, len(columns)):
        if columns[i]['name'] == 'TimeGenerated':
            return i


def iter_log_analytics_events(columns: list, rows: list):
    """Iterate through the columns and rows to build the events and sent them to the socket.

    Parameters
    ----------
    columns : list
        List of dicts containing the names and the types of each column
    rows : list
        List of rows containing the values for each column. Each rows is an event
    """
    # Add tag columns
    columns.append({u'type': u'string', u'name': u'azure_tag'})
    if args.la_tag:
        columns.append({u'type': u'string', u'name': u'log_analytics_tag'})

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
    elif args.graph_id and args.graph_key and args.graph_tenant_domain:
        client = args.graph_id
        secret = args.graph_key
    else:
        logging.error("Graph: No parameters have been provided for authentication.")
        sys.exit(1)

    # Get the token
    logging.info("Graph: Getting authentication token.")
    token = get_token(client_id=client, secret=secret, domain=args.graph_tenant_domain, scope=f"{url_graph}/.default")
    headers = {'Authorization': f'Bearer {token}'}

    # Build the query
    logging.info(f"Graph: Building url for {offset_to_datetime(args.graph_time_offset)}.")
    md5_hash = md5(graph_formatted_query.encode()).hexdigest()
    url = build_graph_query(offset=args.graph_time_offset, md5_hash=md5_hash)
    logging.info(f"Graph: The URL is '{url}'")

    # Get events
    logging.info("Graph: Pagination starts")
    get_graph_events(url=url, headers=headers, md5_hash=md5_hash)
    logging.info("Graph: End")


def build_graph_query(offset: str, md5_hash: str):
    """Build a query to use with the specified service filtering its results by the desired_datetime.

    Parameters
    ----------
    offset : str
        The filtering condition for the query
    md5_hash : str
        md5 value used to search the query in the file containing the dates

    Returns
    -------
    The required URL for the requested query in str format
    """
    min_datetime, max_datetime = get_min_max(service_name="graph", md5_hash=md5_hash, offset=offset)
    # If no offset value was provided continue from the previous processed date
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_strf = f"datetime({desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
    filtering_condition = "createdDateTime" if "signinEventsV2" in graph_formatted_query else "activityDateTime"

    # If reparse was provided, get the logs ignoring if they were already processed
    if args.reparse:
        filter_value = f"{filtering_condition}+ge+{desired_strf}"
    # Build the filter taking into account the min and max values from the file
    else:
        min_strf = f"datetime({min_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
        max_strf = f"datetime({max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
        desired_strf = f"datetime({desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"

        if desired_datetime < min_datetime:
            filter_value = f"({filtering_condition}+lt+{min_strf}+and+{filtering_condition}+ge+{desired_strf})" \
                           f"+or+({filtering_condition}+gt+{max_strf})"
        elif desired_datetime > max_datetime:
            filter_value = f"{filtering_condition}+ge+{desired_strf}"
        else:
            filter_value = f"{filtering_condition}+gt+{max_strf}"

    logging.info(f"Graph: The search starts for query: '{graph_formatted_query}' using {filter_value}")
    return f"{url_graph}/v1.0/{graph_formatted_query}?$filter={filter_value}"


def get_graph_events(url: str, headers: dict, md5_hash: str):
    """Request the data using the specified url and process the values in the response.

    Parameters
    ----------
    url : str
        The url for the request
    headers : dict
        The header for the request, containing the authentication token
    md5_hash : str
        md5 value used to search the query in the file containing the dates

    Raises
    ------
    HTTPError if the response for the request is not 200 OK.

    Returns
    -------
    The nextLink url value contained in the response or None.
    """
    response = get(url=url, headers=headers)

    if response.status_code == 200:
        response_json = response.json()
        values_json = response_json.get('value')
        for value in values_json:
            update_dates_json(new_min=value["activityDateTime"],
                              new_max=value["activityDateTime"],
                              service_name="graph",
                              md5_hash=md5_hash)
            value["azure_tag"] = "azure-ad-graph"
            if args.graph_tag:
                value['azure_aad_tag'] = args.graph_tag
            json_result = dumps(value)
            logging.info("Graph: Sending event by socket.")
            send_message(json_result)
        save_dates_json(dates_json)

        if len(values_json) == 0:
            logging.info("Graph: There are no new results")

        if nex_url := response_json.get('@odata.nextLink'):
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
    elif args.account_name and args.account_key:
        name = args.account_name
        key = args.account_key
    else:
        logging.error("Storage: No parameters have been provided for authentication.")
        sys.exit(1)

    try:
        # Authenticate
        block_blob_service = BlockBlobService(account_name=name, account_key=key)
        logging.info("Storage: Authenticated.")

        # Get containers from the storage account or the configuration file
        logging.info("Storage: Getting containers.")
        containers = block_blob_service.list_containers() if container_format == '*' else [container_format]

        # Get the blobs
        for container in containers:
            name = container.name if container_format == '*' else container_format
            get_blobs(container_name=name, blob_service=blob_service)
    except AzureException as e:
        logging.error("Storage: The containers could not be obtained. '{}'.".format(e))
        sys.exit(1)

    logging.info("Storage: End")


def get_blobs(container_name: str, blob_service: BlockBlobService, next_marker: str = None):
    """Get the blobs from a container and send their content.

    Parameters
    ----------
    container_name : str
        Name of container to read the blobs from
    blob_service : BlockBlobService
        Client used to obtain the blobs
    next_marker : str
        Token used as a marker to continue from previous iteration
    """
    try:
        # Get the blob list
        logging.info("Storage: Getting blobs.")
        blobs = blob_service.list_blobs(name, marker=next_marker)
    except AzureException as e:
        logging.error(f"Storage: Error getting blobs: '{e}'.")
        sys.exit(1)
    else:
        desired_datetime = offset_to_datetime(args.storage_time_offset) if args.storage_time_offset else max_datetime
        logging.info(f"Storage: The search starts from the date: {desired_datetime} for blobs in "
                     f"container: '{container_name}' ")
        search = "." if blobs_format == '*' else blobs_format.replace('*', '')
        for blob in blobs:
            # Skip the blob if its name has not the expected format
            if search not in blob.name:
                continue

            # Skip the blob if already processed
            last_modified = blob.properties.last_modified
            md5_hash = md5(name.encode()).hexdigest()
            min_datetime, max_datetime = get_min_max(service_name="storage", md5_hash=md5_hash, offset=offset)
            if not args.reparse and (last_modified < desired_datetime or (
                    min_datetime <= last_modified <= max_datetime)):
                continue

            # Get the blob data
            try:
                data = blob_service.get_blob_to_text(name, blob.name)
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
                                msg = f'{msg}, "azure_storage_tag": {args.storage_tag}'
                            msg = f'{msg}, {line[1:]}'
                        else:
                            msg = "azure_tag: azure-storage."
                            if args.storage_tag:
                                msg = f'{msg} azure_storage_tag: {args.storage_tag}.'
                            msg = f'{msg} {line}'
                        logging.info("Storage: Sending event by socket.")
                        send_message(msg)

            update_dates_json(new_min=str(last_modified),
                              new_max=str(last_modified),
                              service_name="storage",
                              md5_hash=md5_hash)
            save_dates_json(dates_json)

            # Continue until no marker is returned
            if blobs.next_marker:
                get_blobs(container_name=container_name, blob_service=blob_service,next_marker=blobs.next_marker)


def get_token(client_id: str, secret: str, domain: str, scope: str):
    """Get the authentication token for accessing a given resource in the specified domain.

    Parameters
    ----------
    client_id : str
        The client ID
    secret : str
        The client secret
    domain : str
        The tenant domain
    scope : str
        The scope for the token requested

    Returns
    -------
    A valid token in str format
    """
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': scope,
        'grant_type': 'client_credentials'
    }
    auth_url = f'{url_logging}/{domain}/oauth2/v2.0/token'
    try:
        token_response = post(auth_url, data=body)
        return token_response.json()['access_token']
    except (ValueError, KeyError) as e:
        logging.error("Error: Couldn't get the token for authentication: '{}'.".format(e))
        sys.exit(1)


def send_message(message):
    """Send a message with a header to the analysisd queue.

    Parameters
    ----------
    message : str
        The message body to send to analysisd
    """
    s = socket(AF_UNIX, SOCK_DGRAM)
    try:
        s.connect(ANALYSISD)
        s.send(f'{socket_header}{message}'.encode(errors='replace'))
    except socket_error as e:
        if e.errno == 111:
            logging.error("ERROR: Wazuh must be running.")
            sys.exit(1)
        elif e.errno == 90:
            logging.error("ERROR: Message too long to send to Wazuh.  Skipping message...")
        else:
            logging.error("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(1)
    finally:
        s.close()


def offset_to_datetime(date):
    """Transform an offset value to a datetime object.

    Parameters
    ----------
    date : str
        A positive number containing a suffix character that indicates it's time unit,
        such as, s (seconds), m (minutes), h (hours), d (days), w (weeks), M (months)

    Returns
    -------
    A datetime object resulting from subtracting the offset value from the current datetime.
    """
    date = date.replace(" ", "")
    value = int(date[:len(date) - 1])
    unit = date[len(date) - 1:]

    if unit == 'h':
        return datetime.utcnow().replace(tzinfo=UTC) - timedelta(hours=value)
    if unit == 'm':
        return datetime.utcnow().replace(tzinfo=UTC) - timedelta(minutes=value)
    if unit == 'd':
        return datetime.utcnow().replace(tzinfo=UTC) - timedelta(days=value)


if __name__ == "__main__":
    set_logger()
    dates_json = load_dates_json()

    if args.log_analytics:
        start_log_analytics()
    elif args.graph:
        start_graph()
    elif args.storage:
        start_storage()
    else:
        logging.error("No valid API was specified. Please use 'graph', 'log_analytics' or 'storage'.")
        sys.exit(1)
