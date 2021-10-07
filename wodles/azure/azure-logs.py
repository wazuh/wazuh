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
from argparse import ArgumentParser
from azure.storage.blob import BlockBlobService
from datetime import datetime, timedelta
from dateutil.parser import parse
from hashlib import md5
from json import dump, dumps, load, JSONDecodeError
from os import linesep
from os.path import abspath, dirname, exists, join
from pytz import UTC
from requests import get, post
from socket import socket, AF_UNIX, SOCK_DGRAM, error as socket_error
from sys import exit, path
from typing import Union

path.insert(0, dirname(dirname(abspath(__file__))))
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
                    help="Storage account name for authenticacion.")
parser.add_argument("--account_key", metavar='KEY', type=str, required=False,
                    help="Storage account key for authentication.")
parser.add_argument("--storage_auth_path", metavar="filepath", type=str, required=False,
                    help="Path of the file containing the credentials authentication.")
parser.add_argument("--container", metavar="container", type=str, required=False,
                    help="Name of the container where searchs the blobs.")
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


def read_auth_file(auth_path: str):
    """Read the authentication file. Its contents must be in 'field = value' format.

    Parameters
    ----------
    auth_path : str
        Path to the authentication file

    Returns
    -------
    A tuple with the "application_id" and "application_key" values for authentication.
    """
    credentials = {}
    try:
        with open(auth_path, 'r') as auth_file:
            for line in auth_file:
                key, value = line.replace(" ", "").split("=")
                if not value:
                    continue
                credentials[key] = value.replace("\n", "")
    except OSError as e:
        logging.error("Error: The authentication file could not be opened: '{}'".format(e))
        exit(1)
    if "application_id" not in credentials or "application_key" not in credentials:
        logging.error("Error: The authentication file does not contains the expected 'application_id' "
                      "and 'application_key' fields.")
        exit(1)
    return credentials["application_id"], credentials["application_key"]


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
        exit(1)


def save_dates_json(json_obj):
    """Save the json object containing the different processed dates in the "date_file" file."""
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
        client, secret = read_auth_file(auth_path=args.la_auth_path)
    elif args.la_id and args.la_key and args.la_tenant_domain:
        client = args.la_id
        secret = args.la_key
    else:
        logging.error("Log Analytics: No parameters have been provided for authentication.")
        exit(1)

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


def build_log_analytics_query(offset: str, md5_hash: str) -> dict:
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
    desired_datetime = offset_to_datetime(offset) if offset else None

    # Get min and max values from the file
    try:
        # We use "parse" to handle any datetime with more than 6 digits for the microseconds value provided by Azure
        min_datetime = parse(dates_json["log_analytics"][md5_hash]['min'], fuzzy=True)
        max_datetime = parse(dates_json["log_analytics"][md5_hash]['max'], fuzzy=True)
    except KeyError:
        # The "graph" key or the md5 value is not present in the dates file
        logging.info(f"{md5_hash} was not found in {last_dates_file} for Log Analytics. Updating the file")
        min_datetime = max_datetime = desired_datetime
        dates_json["log_analytics"][md5_hash] = {'min': f"{desired_datetime}", 'max': f"{desired_datetime}"}

    min_strf = f"datetime({min_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
    max_strf = f"datetime({max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"
    desired_strf = f"datetime({desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})"

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
    def get_time_position():
        """Get the position of the 'TimeGenerated' field in the columns list.

        Returns
        -------
        The index of the 'TimeGenerated' field in the given list or None if it's not present.
        """
        for i in range(0, len(columns)):
            if columns[i]['name'] == 'TimeGenerated':
                return i

    logging.info("Log Analytics: Sending a request to the Log Analytics API.")
    response = get(url, params=body, headers=headers)
    if response.status_code == 200:
        try:
            columns = response.json()['tables'][0]['columns']
            rows = response.json()['tables'][0]['rows']
        except KeyError as e:
            logging.error("Error: It was not possible to obtain the columns and rows from the event: '{}'.".format(e))
        else:
            if len(rows) == 0:
                logging.info("Log Analytics: There are no new results")
            elif time_position := get_time_position():
                iter_log_analytics_events(columns, rows)
                update_dates_json(new_min=rows[0][time_position],
                                  new_max=rows[len(rows) - 1][time_position],
                                  service_name="log_analytics",
                                  md5_hash=md5_hash)
                save_dates_json(dates_json)
            else:
                logging.error("Error: No TimeGenerated field was found")
    else:
        response.raise_for_status()


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
        client, secret = read_auth_file(auth_path=args.graph_auth_path)
    elif args.graph_id and args.graph_key and args.graph_tenant_domain:
        client = args.graph_id
        secret = args.graph_key
    else:
        logging.error("Graph: No parameters have been provided for authentication.")
        exit(1)

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
    desired_datetime = offset_to_datetime(offset) if offset else None
    filtering_condition = "createdDateTime" if "signinEventsV2" in graph_formatted_query else "activityDateTime"

    # Get min and max values from the file
    try:
        # We use "parse" to handle any datetime with more than 6 digits for the microseconds value provided by Azure
        min_datetime = parse(dates_json["graph"][md5_hash]['min'], fuzzy=True)
        max_datetime = parse(dates_json["graph"][md5_hash]['max'], fuzzy=True)
    except KeyError:
        logging.info(f"{md5_hash} was not found in {last_dates_file} for Graph. Updating the file")
        min_datetime = max_datetime = desired_datetime
        dates_json["graph"][md5_hash] = {'min': f"{desired_datetime}", 'max': f"{desired_datetime}"}

    min_strf = min_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')
    max_strf = max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')
    desired_strf = desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')

    # Build the filter taking into account the min and max values
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

    Returns
    -------
    The nextLink url value contained in the response or None.
    """
    try:
        response = get(url=url, headers=headers)
        logging.info("Graph: Request status: {}".format(response.status_code))
    except Exception as e:
        logging.error(f"Error: The request for the query could not be made: '{e}'")
        return

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

################################################################################################
# Get access and content of the storage accounts
# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
################################################################################################

def start_storage(first_run):
    logging.info("Azure Storage starting.")

    storage_time = offset_to_datetime(args.storage_time_offset)
    time_format = str(storage_time)
    length_time_format = len(time_format) - 7
    time_format = time_format[:length_time_format]
    time_format_storage = datetime.strptime(time_format, '%Y-%m-%d %H:%M:%S')

    try:
        dates_json = load(open(last_dates_file))
    except Exception as e:
        logging.error("Error: The file of the last dates could not be updated: '{}.".format(e))

    try:
        # Authentication
        logging.info("Storage: Authenticating.")
        if args.storage_auth_path:
            auth_fields = read_auth_file(args.storage_auth_path)
            block_blob_service = BlockBlobService(account_name=auth_fields['id'], account_key=auth_fields['key'])
            logging.info("Storage: Authenticated.")
        elif args.account_name and args.account_key:
            block_blob_service = BlockBlobService(account_name=args.account_name, account_key=args.account_key)
            logging.info("Storage: Authenticated.")
        else:
            logging.error("Storage: No parameters have been provided for authentication.")

        logging.info("Storage: Getting containers.")
        # Getting containers from the storage account
        if container_format == '*':
            try:
                containers = block_blob_service.list_containers()
            except Exception as e:
                logging.error("Storage: The containers could not be obtained. '{}'.".format(e))

        # Getting containers from the configuration file
        else:
            try:
                containers = [container_format]
            except Exception as e:
                logging.error("Storage: The containers could not be obtained. '{}'.".format(e))

        # Getting blobs
        get_blobs(containers, block_blob_service, time_format_storage, first_run, dates_json, last_dates_file)

    except Exception as e:
        logging.error(" Storage account: '{}'.".format(e))

    logging.info("Storage: End")


################################################################################################
# Get the blobs from a container and sends or writes their content
################################################################################################
def get_blobs(containers, block_blob_service, time_format_storage, first_run, dates_json, path):
    for container in containers:

        # Differentiates possible cases of access to containers
        if container_format == '*':
            name = container.name
        else:
            name = container_format

        container_md5 = md5(name.encode()).hexdigest()
        next_marker = None

        while True:
            try:
                # Extraction of blobs from containers
                logging.info("Storage: Getting blobs.")
                blobs = block_blob_service.list_blobs(name, marker=next_marker)
            except Exception as e:
                logging.error("Error getting blobs: '{}'.".format(e))

            if blobs_format == '*':
                search = "."
            else:
                search = blobs_format
                search = search.replace('*', '')

            max_blob = UTC.localize(time_format_storage)

            for blob in blobs:
                try:
                    # Access to the desired blobs
                    if search in blob.name:
                        data = block_blob_service.get_blob_to_text(name, blob.name)
                        last_modified = blob.properties.last_modified

                        if first_run == False:
                            if container_md5 not in dates_json["storage"]:
                                last_blob = time_format_storage
                            else:
                                blob_date_format = dates_json["storage"][container_md5]
                                blob_date_length = len(blob_date_format) - 6
                                blob_date_format = blob_date_format[:blob_date_length]
                                last_blob = datetime.strptime(blob_date_format, '%Y-%m-%d %H:%M:%S')
                        else:
                            last_blob = time_format_storage

                        last_blob = UTC.localize(last_blob)
                        logging.info(
                            "Storage: The search starts from the date: {} for blobs in container: '{}' ".format(
                                last_blob, name))

                        if last_modified > last_blob:
                            if last_modified > max_blob:
                                max_blob = last_modified
                            socket_data = str(data.content)
                            socket_data = linesep.join([s for s in socket_data.splitlines() if s])
                            split_data = socket_data.splitlines()
                            storage_counter = 0

                            if args.json_file:
                                content_list = loads(data.content)
                                content_records = content_list["records"]
                                for log_record in content_records:
                                    log_record['azure_tag'] = ('azure-storage')
                                    if args.storage_tag:
                                        log_record['azure_storage_tag'] = (args.storage_tag)
                                    logging.info("Storage: Sending event by socket.")
                                    log_json = dumps(log_record)
                                    send_message(log_json)
                                    storage_counter += 1
                            else:
                                for line in split_data:
                                    if args.json_inline:
                                        size = len(line)
                                        sub_data = line[1:size]
                                        if args.storage_tag:
                                            send_data = '{"azure_tag": "azure-storage",' + '"azure_storage_tag": "' + args.storage_tag + '", ' + sub_data
                                        else:
                                            send_data = '{"azure_tag": "azure-storage",' + sub_data
                                    else:
                                        if args.storage_tag:
                                            send_data = "azure_tag: azure-storage. azure_storage_tag: {}. {}".format(
                                                args.storage_tag, line)
                                        else:
                                            send_data = "azure_tag: azure-storage. {}".format(line)

                                    if send_data != "":
                                        logging.info("Storage: Sending event by socket.")
                                        send_message(send_data)
                                        storage_counter += 1
                except Exception as e:
                    logging.error("Storage: sending blob: '{}'.".format(e))

            next_marker = blobs.next_marker
            if not next_marker:
                break

        try:
            if first_run == True:
                write_time = max_blob
            else:
                if container_md5 in dates_json["storage"]:
                    previous_time = dates_json["storage"][container_md5]
                    previous_time_length = len(previous_time) - 6
                    previous_time_format = previous_time[:previous_time_length]
                    previous_date = datetime.strptime(previous_time_format, '%Y-%m-%d %H:%M:%S')
                    previous_date = UTC.localize(previous_date)
                    if previous_date > max_blob:
                        write_time = previous_date
                    else:
                        write_time = max_blob
                else:
                    write_time = max_blob

            dates_json['storage'][container_md5] = str(write_time)
            with open(join(path), 'w') as jsonFile:
                dump(dates_json, jsonFile)
        except Exception as e:
            logging.error("Error: The file of the last dates could not be uploaded: '{}.".format(e))


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
        exit(1)


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
            exit(1)
        elif e.errno == 90:
            logging.error("ERROR: Message too long to send to Wazuh.  Skipping message...")
        else:
            logging.error("ERROR: Error sending message to wazuh: {}".format(e))
            exit(1)
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
        exit(1)
