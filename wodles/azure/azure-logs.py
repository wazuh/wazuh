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
import utils

date_file = "last_dates.json"
last_dates_file = join(dirname(abspath(__file__)), date_file)
url_log_analytics = 'https://api.loganalytics.io/v1'
graph_base_url = 'https://graph.microsoft.com'
loggin_url = 'https://login.microsoftonline.com'
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
        log_path = "{}/logs/azure_logs.log".format(utils.find_wazuh_path())
        logging.basicConfig(filename=log_path, level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: AZURE %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


def read_auth_file(path: str):
    """Read the authentication file. Its contents must be in 'field = value' format.

    Parameters
    ----------
    path : str
        Path to the authentication file

    Returns
    -------
    A dict with the processed "application_id" and "application_key" values for authentication.
    """
    try:
        credentials = {}
        with open(path, 'r') as auth_file:
            for line in auth_file:
                key, value = line.replace(" ", "").split("=")
                if not value:
                    continue
                credentials[key] = value.replace("\n", "")
        if "application_id" not in credentials or "application_key" not in credentials:
            logging.error("Error: The authentication file does not contains the expected 'application_id' "
                          "and 'application_key' fields.")
            exit(1)
        return credentials
    except OSError as e:
        logging.error("Error: The authentication file could not be opened: '{}'".format(e))
        exit(1)


def build_query(service_name: str, offset: str, md5_hash: str, dates_json: dict):
    """Build a query to use with the specified service filtering its results by the desired_datetime.

    Parameters
    ----------
    service_name : str
        Name of the service to fetch the data from the "last_dates_file"
    offset : str
        The filtering condition for the query
    md5_hash : str
        md5 value used to search the query in the file containing the dates
    dates_json : dict
        The contents of the "last_dates_file"

    Returns
    -------
    The required URL for the requested query in str format
    """
    desired_datetime = offset_to_datetime(offset) if offset else None
    service_name_lower = service_name.lower()
    if dates_json.get(service_name_lower) and md5_hash in dates_json[service_name_lower]:
        # This adds compatibility with "last_dates_files" from previous releases
        if isinstance(dates_json[service_name_lower][md5_hash], dict):
            min_datetime = parse(dates_json[service_name_lower][md5_hash].get('min'), fuzzy=True)
            max_datetime = parse(dates_json[service_name_lower][md5_hash].get('max'), fuzzy=True)
        else:
            min_datetime = parse(dates_json[service_name_lower][md5_hash], fuzzy=True)
            max_datetime = parse(dates_json[service_name_lower][md5_hash], fuzzy=True)
    else:
        logging.info(f"{md5_hash} was not found in {last_dates_file} for {service_name_lower}. Updating the file")
        min_datetime = desired_datetime
        max_datetime = desired_datetime
        dates_json[service_name_lower][md5_hash] = {'min': f"{min_datetime}", 'max': f"{max_datetime}"}

    filtering_condition = "createdDateTime" if "signinEventsV2" in graph_formatted_query else "activityDateTime"

    if desired_datetime < min_datetime:
        filter_value = f"({filtering_condition}+lt+{min_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')}" \
                       f"+and+{filtering_condition}+ge+{desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')})" \
                       f"+or+({filtering_condition}+gt+{max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')})"
    elif desired_datetime > max_datetime:
        filter_value = f"{filtering_condition}+ge+{desired_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')}"
    else:
        filter_value = f"{filtering_condition}+gt+{max_datetime.strftime('%Y-%m-%dT%H:%M:%S.%sZ')}"

    logging.info(f"Graph: The search starts for query: '{graph_formatted_query}' using {filter_value}")

    return f"{graph_base_url}/v1.0/{graph_formatted_query}?$filter={filter_value}"


def load_dates():
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
        else:
            contents = {'log_analytics': {}, 'graph': {}, 'storage': {}}
            with open(join(last_dates_file), 'w') as file:
                dump(contents, file)
        return contents
    except (JSONDecodeError, OSError) as e:
        logging.error("Error: The file of the last dates could not be read: '{}.".format(e))
        exit(1)


def save_dates(json_obj):
    """Save the json object containing the different processed dates in the "date_file" file."""
    logging.info(f"Updating {last_dates_file} file.")
    try:
        with open(join(last_dates_file), 'w') as jsonFile:
            dump(json_obj, jsonFile)
    except (TypeError, ValueError, OSError) as e:
        logging.error("Error: The file of the last dates could not be updated: '{}.".format(e))


################################################################################################
# The client or application must have permission to read Log Analytics.
# https://dev.loganalytics.io/documentation/1-Tutorials/Direct-API
################################################################################################

def start_log_analytics():
    logging.info("Azure Log Analytics starting.")

    try:
        # Getting authentication token
        logging.info("Log Analytics: Getting authentication token.")
        logging.info(args.la_auth_path)
        if args.la_auth_path and args.la_tenant_domain:
            auth = read_auth_file(path=args.la_auth_path)
            logging.error(auth)
            client_id = auth['application_id']
            secret = auth['application_key']
        elif args.graph_id and args.graph_key and args.graph_tenant_domain:
            client_id = args.graph_id
            secret = args.graph_key
        else:
            logging.error("Log Analytics: No parameters have been provided for authentication.")
            exit(1)

        # log_analytics_token = get_token(client_id, secret, 'https://api.loganalytics.io', args.la_tenant_domain)
        log_analytics_token = get_token(client_id=client_id, secret=secret, domain=args.la_tenant_domain)

        log_analytics_headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + log_analytics_token
        }
        first_run = False
        if not first_run:
            first_time = "0"
        else:
            first_time = offset_to_datetime(args.la_time_offset)

        try:
            dates_json = load(open(last_dates_file))
            get_analytic(first_time, dates_json, url_log_analytics, log_analytics_headers)
            with open(join(last_dates_file), 'w') as jsonFile:
                dump(dates_json, jsonFile)
        except Exception as e:
            logging.error("Error: The file of the last dates could not be uploaded: '{}.".format(e))

    except Exception as e:
        logging.error("Log Analytics: Couldn't get the token for authentication: '{}'.".format(e))

    logging.info("Azure Log Analytics ending.")


################################################################################################
# Prepares and makes the request, building the query based on the time of event generation.
################################################################################################

def get_analytic(date, last_time_list, url, log_headers):
    analytics_url = "{}/workspaces/{}/query".format(url, args.workspace)
    logging.info("Log Analytics: Sending a request to the Log Analytics API.")

    try:
        md5_hash = md5(la_format_query.encode()).hexdigest()
        # Differentiates the first execution of the script from the rest of the executions.
        if date != "0":
            date_search = date
        else:
            if md5_hash not in last_time_list["log_analytics"]:
                date_search = date
            else:
                date_search = last_time_list["log_analytics"][md5_hash]

        logging.info(
            "Log Analytics: The search starts from the date: {} for query: '{}' ".format(date_search, la_format_query))
        query = "{} | order by TimeGenerated asc | where TimeGenerated > datetime({}) ".format(la_format_query,
                                                                                               date_search)
        body = {'query': query}
        analytics_request = get(analytics_url, params=body, headers=log_headers)
        get_time_list(analytics_request, last_time_list, date_search, md5_hash)
    except Exception as e:
        logging.error("Error: The query requested to the API Log Analytics has failed. '{}'.".format(e))


################################################################################################
# Obtains the list with the last time generated of each query.
################################################################################################

def get_time_list(request_received, last_timegen, no_results, md5_hash):
    try:
        if request_received.status_code == 200:
            columns = request_received.json()['tables'][0]['columns']
            rows = request_received.json()['tables'][0]['rows']
            time_position = get_TimeGenerated_position(columns)
            # Searches for the position of the TimeGenerated field
            if time_position == -1:
                logging.error("Error: Couldn't get TimeGenerated position")
            else:
                last_row = len(request_received.json()['tables'][0]['rows']) - 1
                # Checks for new results
                if last_row < 0:
                    logging.info("Log Analytics: There are no new results")
                    last_timegen['log_analytics'][md5_hash] = str(no_results)
                else:
                    last_timegen['log_analytics'][md5_hash] = request_received.json()['tables'][0]['rows'][last_row][
                        time_position]
                    file_json = request_received.json()
                    get_log_analytics_event(columns, rows)
        else:
            if args.verbose:
                logging.info("Log Analytics request: {}".format(request_received.status_code))
            request_received.raise_for_status()
    except Exception as e:
        logging.error("Error: It was not possible to obtain the latest event: '{}'.".format(e))


################################################################################################
# Obtains the position of the time field in which the event was generated.
################################################################################################

def get_TimeGenerated_position(columns):
    position = 0
    found = "false"
    for column in columns:
        if column['name'] == 'TimeGenerated':
            found = "true"
            break
        position += 1
    if found == "false":
        return -1
    else:
        return position


################################################################################################
# Adds the field name to each row of the result and converts it to json. Writes or sends events
################################################################################################

def get_log_analytics_event(columns, rows):
    columns.append({u'type': u'string', u'name': u'azure_tag'})
    if args.la_tag:
        columns.append({u'type': u'string', u'name': u'log_analytics_tag'})

    for row in rows:
        row.append("azure-log-analytics")
        if args.la_tag:
            row.append(args.la_tag)

    columns_len = len(columns)
    rows_len = len(rows)
    row_iterator = 0

    while row_iterator < rows_len:
        la_result = {}
        column_iterator = 0
        while column_iterator < columns_len:
            la_result[columns[column_iterator]['name']] = rows[row_iterator][column_iterator]
            column_iterator += 1
        row_iterator += 1
        json_result = dumps(la_result)
        logging.info("Log Analytics: Sending event by socket.")
        send_message(json_result)


def start_graph():
    """Run the Microsoft Graph integration processing the logs available for the given query and offset values in
    the configuration. The client or application must have permission to access Microsoft Graph."""
    logging.info("Azure Graph starting.")

    if args.graph_auth_path and args.graph_tenant_domain:
        auth = read_auth_file(args.graph_auth_path)
        client_id = auth['application_id']
        secret = auth['application_key']
    elif args.graph_id and args.graph_key and args.graph_tenant_domain:
        client_id = args.graph_id
        secret = args.graph_key
    else:
        logging.error("Graph: No parameters have been provided for authentication.")
        exit(1)

    logging.info("Graph: Getting authentication token.")
    graph_token = get_token(client_id=client_id, secret=secret, domain=args.graph_tenant_domain)
    headers = {'Authorization': 'Bearer ' + graph_token}
    md5_hash = md5(graph_formatted_query.encode()).hexdigest()
    dates_json = load_dates()
    logging.info(f"Graph: Building url for {offset_to_datetime(args.graph_time_offset)}.")
    url = build_query(service_name="Graph", offset=args.graph_time_offset, md5_hash=md5_hash, dates_json=dates_json)
    logging.info(f"Graph: The URL is '{url}'")
    logging.info("Graph: Pagination starts")
    graph_pagination(url=url, headers=headers, md5_hash=md5_hash, dates_json=dates_json)
    logging.info("Graph: End")


def graph_pagination(url: str, headers: dict, md5_hash: str, dates_json: dict):
    """Request the data using the specified url and process the values in the response.

    Parameters
    ----------
    url : str
        The url for the required query
    headers : dict
        The header for the request, containing the authentication token
    md5_hash : str
        md5 value used to search the query in the file containing the dates
    dates_json
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
            logging.info(value["activityDateTime"])
            activityDateTime = parse(value["activityDateTime"], fuzzy=True)
            if activityDateTime > parse(dates_json['graph'][md5_hash]['max'], fuzzy=True):
                logging.info(f"Graph: The current item's activityDateTime is greater that the MAX value stored. "
                             f"Updating the MAX value to {value['activityDateTime']}")
                dates_json['graph'][md5_hash]['max'] = value["activityDateTime"]
            if activityDateTime < parse(dates_json['graph'][md5_hash]['min'], fuzzy=True):
                logging.info(f"Graph: The current item's activityDateTime is lower that the MIN value stored. "
                             f"Updating the MIN value to {value['activityDateTime']}")
                dates_json['graph'][md5_hash]['min'] = value["activityDateTime"]
            value["azure_tag"] = "azure-ad-graph"
            if args.graph_tag:
                value['azure_aad_tag'] = args.graph_tag
            json_result = dumps(value)
            logging.info("Graph: Sending event by socket.")
            send_message(json_result)
        save_dates(dates_json)

        if len(values_json) == 0:
            logging.info("Graph: There are no new results")

        if nex_url := response_json.get('@odata.nextLink'):
            graph_pagination(url=next_url, headers=headers, md5_hash=md5_hash, dates_json=dates_json)
    elif response.status_code == 400:
        logging.error(f"Bad Request for url: {response.url}")
        logging.error(f"Ensure the URL is valid and there is data available for the specified datetime.")
    else:
        response.raise_for_status()


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


def get_token(client_id: str, secret: str, domain: str, resource: str = None):
    """Get the authentication token for accessing a given resource in the specified domain.

    Parameters
    ----------
    client_id : str
        The client ID
    secret : str
        The client secret
    domain : str
        The tenant domain
    resource : str
        The resource for which access is requested

    Returns
    -------
    A valid token in str format
    """
    body = {
        'client_id': client_id,
        'client_secret': secret,
        'scope': f'{resource if resource else graph_base_url}/.default',
        'grant_type': 'client_credentials'
    }
    auth_url = f'{loggin_url}/{domain}/oauth2/v2.0/token'
    try:
        token_response = post(auth_url, data=body)
        logging.info(f"RESPONSE: {token_response}")
        return token_response.json()['access_token']
    except Exception as e:
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
        s.connect(utils.ANALYSISD)
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

    if args.log_analytics:
        start_log_analytics()
    elif args.graph:
        start_graph()
    elif args.storage:
        start_storage()
    else:
        logging.error("No valid API was specified. Please use 'graph', 'log_analytics' or 'storage'.")
        exit(1)
