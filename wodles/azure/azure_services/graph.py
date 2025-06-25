#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import sys
from hashlib import md5
from json import dumps
from os.path import abspath, dirname
import time

from dateutil.parser import parse
from requests import HTTPError, get

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import (
    CREDENTIALS_URL,
    DATETIME_MASK,
    DEPRECATED_MESSAGE,
    MAX_EPS,
    get_token,
    offset_to_datetime,
    read_auth_file,
    SocketConnection,
)
from db import orm
from db.utils import create_new_row, update_row_object

URL_GRAPH = 'https://graph.microsoft.com'


def start_graph(args):
    """Run the Microsoft Graph integration processing the logs available for the given query and offset values in
    the configuration. The client or application must have permission to access Microsoft Graph."""
    logging.info('Azure Graph starting.')

    # Read credentials
    if args.graph_auth_path and args.graph_tenant_domain:
        logging.debug(f"Graph: Using the auth file {args.graph_auth_path} for authentication")
        client, secret = read_auth_file(
            auth_path=args.graph_auth_path, fields=('application_id', 'application_key')
        )
    elif args.graph_id and args.graph_key and args.graph_tenant_domain:
        logging.debug("Graph: Using id and key from configuration for authentication")
        logging.warning(
            DEPRECATED_MESSAGE.format(
                name='graph_id and graph_key', release='4.4', url=CREDENTIALS_URL
            )
        )
        client = args.graph_id
        secret = args.graph_key
    else:
        logging.error('Graph: No parameters have been provided for authentication.')
        sys.exit(1)

    # Get the token
    logging.info('Graph: Getting authentication token.')
    token = get_token(
        client_id=client,
        secret=secret,
        domain=args.graph_tenant_domain,
        scope=f'{URL_GRAPH}/.default',
    )
    headers = {'Authorization': f'Bearer {token}'}

    # Build the query
    logging.info('Graph: Building the url.')
    md5_hash = md5(args.graph_query.encode()).hexdigest()
    url = build_graph_url(
        query=args.graph_query,
        offset=args.graph_time_offset,
        reparse=args.reparse,
        md5_hash=md5_hash,
    )
    logging.info(f'Graph: The URL is "{url}"')

    # Get events
    logging.info('Graph: Pagination starts')
    try:
        get_graph_events(
            url=url,
            headers=headers,
            md5_hash=md5_hash,
            query=args.graph_query,
            tag=args.graph_tag,
        )
    except HTTPError as e:
        logging.error(f'Graph: {e}')
    logging.info('Graph: End')


def build_graph_url(query: str, offset: str, reparse: bool, md5_hash: str):
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
            item = create_new_row(
                table=orm.Graph,
                query=query,
                md5_hash=md5_hash,
                offset=offset,
            )
    except orm.AzureORMError as e:
        logging.error(
            f'Error trying to obtain row object from "{orm.Graph.__tablename__}" using md5="{md5}": {e}'
        )
        sys.exit(1)

    min_str = item.min_processed_date
    max_str = item.max_processed_date
    min_datetime = parse(min_str, fuzzy=True)
    max_datetime = parse(max_str, fuzzy=True)
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_str = desired_datetime.strftime(DATETIME_MASK)
    filtering_condition = (
        'createdDateTime' if 'signins' in query.lower() else 'activityDateTime'
    )

    # If reparse was provided, get the logs ignoring if they were already processed
    if reparse:
        filter_value = f'{filtering_condition}+ge+{desired_str}'
    # Build the filter taking into account the min and max values from the file
    else:
        if desired_datetime < min_datetime:
            logging.debug(f"Graph: Making request query for the following intervals: "
                          f"from {desired_str} to {min_str} and from {max_str}")
            filter_value = (
                f'({filtering_condition}+lt+{min_str}+and+{filtering_condition}+ge+{desired_str})'
                f'+or+({filtering_condition}+gt+{max_str})'
            )
        elif desired_datetime > max_datetime:
            logging.debug(f"Graph: Making request for the following interval: from {desired_str}")
            filter_value = f'{filtering_condition}+ge+{desired_str}'
        else:
            logging.debug(f"Graph: Making request for the following interval: from {max_str}")
            filter_value = f'{filtering_condition}+gt+{max_str}'

    logging.debug(f'Graph: The search starts for query: "{query}" using {filter_value}')
    return f'{URL_GRAPH}/v1.0/{query}{"?" if "?" not in query else ""}&$filter={filter_value}'


def get_graph_events(url: str, headers: dict, md5_hash: str, query: str, tag: str):
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

    logging.debug(f"Graph request - URL: {url} - Headers: {headers}")
    logging.info("Graph: Requesting data")
    response = get(url=url, headers=headers, timeout=10)

    if response.status_code == 200:
        response_json = response.json()
        values_json = response_json.get('value')
        with SocketConnection() as socket:
            eps_counter = 0
            start = time.monotonic()
            for value in values_json:
                now = time.monotonic()
                time_passed = now - start
                if time_passed <= 1 and eps_counter == MAX_EPS:
                    sleep_time = 1 + time_passed
                    logging.info('Sleeping %f sec, since the max 100 EPS was exceeded.', sleep_time)
                    time.sleep(sleep_time)
                    eps_counter = 0
                    start = time.monotonic()
                try:
                    date = value['activityDateTime']
                except KeyError:
                    date = value['createdDateTime']
                update_row_object(
                    table=orm.Graph,
                    md5_hash=md5_hash,
                    new_min=date,
                    new_max=date,
                    query=query,
                )
                value['azure_tag'] = 'azure-ad-graph'
                if tag:
                    value['azure_aad_tag'] = tag
                json_result = dumps(value)
                logging.info('Graph: Sending event by socket.')
                socket.send_message(json_result)

            if len(values_json) == 0:
                logging.info('Graph: There are no new results')
            next_url = response_json.get('@odata.nextLink')

            if next_url:
                logging.info("Graph: Requesting data from next page")
                logging.debug(f"Iterating to next url: {next_url}")
                get_graph_events(
                    url=next_url, headers=headers, md5_hash=md5_hash, query=query, tag=tag
                )
    elif response.status_code == 400:
        logging.error(f'Bad Request for url: {response.url}')
        logging.error(
            'Ensure the URL is valid and there is data available for the specified datetime.'
        )
    else:
        logging.error(f"Error with Graph request: {response.json()}")
        response.raise_for_status()
