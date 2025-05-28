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

from dateutil.parser import parse
from requests import HTTPError, get

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import (
    CREDENTIALS_URL,
    DATETIME_MASK,
    DEPRECATED_MESSAGE,
    get_token,
    offset_to_datetime,
    read_auth_file,
    send_message,
)
from db import orm
from db.utils import create_new_row, update_row_object

URL_ANALYTICS = 'https://api.loganalytics.io'


def start_log_analytics(args):
    """Run the Log Analytics integration processing the logs available for the given time offset. The client or
    application must have "Contributor" permission to read Log Analytics."""

    logging.info('Azure Log Analytics starting.')

    # Read credentials
    if args.la_auth_path and args.la_tenant_domain:
        logging.debug(f"Log Analytics: Using the auth file {args.la_auth_path} for authentication")
        client, secret = read_auth_file(
            auth_path=args.la_auth_path, fields=('application_id', 'application_key')
        )
    elif args.la_id and args.la_key and args.la_tenant_domain:
        logging.debug(f"Log Analytics: Using id and key from configuration for authentication")
        logging.warning(
            DEPRECATED_MESSAGE.format(
                name='la_id and la_key', release='4.4', url=CREDENTIALS_URL
            )
        )
        client = args.la_id
        secret = args.la_key
    else:
        logging.error(
            'Log Analytics: No parameters have been provided for authentication.'
        )
        sys.exit(1)

    # Get authentication token
    logging.info('Log Analytics: Getting authentication token.')
    token = get_token(
        client_id=client,
        secret=secret,
        domain=args.la_tenant_domain,
        scope=f'{URL_ANALYTICS}/.default',
    )

    # Build the request
    md5_hash = md5(args.la_query.encode()).hexdigest()
    url = f'{URL_ANALYTICS}/v1/workspaces/{args.workspace}/query'
    body = build_log_analytics_query(
        query=args.la_query,
        offset=args.la_time_offset,
        reparse=args.reparse,
        md5_hash=md5_hash,
    )
    headers = {'Authorization': f'Bearer {token}'}

    # Get the logs
    try:
        get_log_analytics_events(
            url=url,
            body=body,
            headers=headers,
            md5_hash=md5_hash,
            query=args.la_query,
            tag=args.la_tag,
            tenant=args.la_tenant_domain,
        )
    except HTTPError as e:
        logging.error(f'Log Analytics: {e}')
    logging.info('Azure Log Analytics ending.')


def build_log_analytics_query(
        query: str, offset: str, reparse: bool, md5_hash: str
) -> dict:
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
            item = create_new_row(
                table=orm.LogAnalytics,
                query=query,
                md5_hash=md5_hash,
                offset=offset,
            )
    except orm.AzureORMError as e:
        logging.error(
            f'Error trying to obtain row object from "{orm.LogAnalytics.__tablename__}" using md5="{md5}": '
            f'{e}'
        )
        sys.exit(1)

    min_str = item.min_processed_date
    max_str = item.max_processed_date
    min_datetime = parse(min_str, fuzzy=True)
    max_datetime = parse(max_str, fuzzy=True)
    desired_datetime = offset_to_datetime(offset) if offset else max_datetime
    desired_str = f'datetime({desired_datetime.strftime(DATETIME_MASK)})'
    min_str = f'datetime({min_str})'
    max_str = f'datetime({max_str})'

    # If reparse was provided, get the logs ignoring if they were already processed
    if reparse:
        filter_value = f'TimeGenerated >= {desired_str}'
    # Build the filter taking into account the min and max values from the file
    else:
        # Build the filter taking into account the min and max values
        if desired_datetime < min_datetime:
            logging.debug(f"Log Analytics: Making request query for the following intervals: "
                          f"from {desired_str} to {min_str} and from {max_str}")
            filter_value = (
                f'( TimeGenerated < {min_str} and TimeGenerated >= {desired_str}) or '
                f'( TimeGenerated > {max_str})'
            )
        elif desired_datetime > max_datetime:
            logging.debug(f"Log Analytics: Making request for the following interval: from {desired_str}")
            filter_value = f'TimeGenerated >= {desired_str}'
        else:
            logging.debug(f"Log Analytics: Making request for the following interval: from {max_str}")
            filter_value = f'TimeGenerated > {max_str}'

    query = f'{query} | order by TimeGenerated asc | where {filter_value} '
    logging.debug(f'Log Analytics: The search starts for query: "{query}"')
    return {'query': query}


def get_log_analytics_events(
        url: str, body: dict, headers: dict, md5_hash: str, query: str, tag: str, tenant:str
):
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
    tenant : str
        The tenant domain.

    Raises
    ------
    HTTPError
        If the response for the request is not 200 OK.
    """
    logging.info('Log Analytics: Sending a request to the Log Analytics API.')
    logging.debug(f"Log Analytics request - URL: {url} - Params: {body} - Headers: {headers}")
    response = get(url, params=body, headers=headers, timeout=10)
    if response.status_code == 200:
        try:
            columns = response.json()['tables'][0]['columns']
            rows = response.json()['tables'][0]['rows']
            if len(rows) == 0:
                logging.info(f'Log Analytics: There are no new results for {tenant}')
            else:
                time_position = get_time_position(columns)
                if time_position is not None:
                    iter_log_analytics_events(columns, rows, tag)
                    update_row_object(
                        table=orm.LogAnalytics,
                        md5_hash=md5_hash,
                        new_min=rows[0][time_position],
                        new_max=rows[len(rows) - 1][time_position],
                        query=query,
                    )
                else:
                    logging.error('No TimeGenerated field was found')

        except KeyError as e:
            logging.error(
                f'It was not possible to obtain the columns and rows from the event: "{e}".'
            )
    else:
        logging.error(f"Error with Log Analytics request: {response.json()}")
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


def iter_log_analytics_events(columns: list, rows: list, tag: str):
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
    if tag:
        columns.append({'type': 'string', 'name': 'log_analytics_tag'})

    for row in rows:
        # Add tag values
        row.append('azure-log-analytics')
        if tag:
            row.append(tag)

        # Build the events and send them
        event = {}
        for c in range(0, len(columns)):
            event[columns[c]['name']] = row[c]
        logging.info('Log Analytics: Sending event by socket.')
        logging.debug(f"Event send to socket: {event}")
        send_message(dumps(event))
