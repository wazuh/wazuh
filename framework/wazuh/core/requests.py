# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP
import os
import ssl
from datetime import datetime
from logging import getLogger
from typing import Optional

import aiohttp
import certifi

import wazuh
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.utils import get_utc_now

CTI_URL = get_ossec_conf(section='global').get(
    'cti_url', 'http://cti:4041'
)  # This default must be removed once we have the configuration in the ossec parser.
RELEASE_UPDATES_URL = os.path.join(CTI_URL, 'api', 'v1', 'ping')
ONE_DAY_SLEEP = 60 * 60 * 24
WAZUH_UID_KEY = 'wazuh-uid'
WAZUH_TAG_KEY = 'wazuh-tag'


logger = getLogger('wazuh')


def _get_connector() -> aiohttp.TCPConnector:
    """Return a TCPConnector with default ssl context.

    Returns
    -------
    aiohttp.TCPConnector
        Instance with default ssl connector.
    """
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    return aiohttp.TCPConnector(ssl=ssl_context)


def get_update_information_template(
        update_check: bool,
        current_version: str = wazuh.__version__,
        last_check_date: Optional[datetime] = None
) -> dict:
    """Build and return a template for the update_information dict.

    Parameters
    ----------
    update_check : bool
        Indicates if the check is enabled or not.
    current_version : str, optional
        Indicates the current version of Wazuh, by default wazuh.__version__.
    last_check_date : Optional[datetime], optional
        Indicates the datetime of the last check, by default None.

    Returns
    -------
    dict
        Template with the given data.
    """
    return {
        'last_check_date': last_check_date if last_check_date is not None else '',
        'current_version': current_version,
        'update_check': update_check,
        'last_available_major': {},
        'last_available_minor': {},
        'last_available_patch': {},
    }


async def query_update_check_service(installation_uid: str) -> dict:
    """Make a query to the update check service and retrieve updates information.

    Parameters
    ----------
    installation_uid : str
        Wazuh UID to include in the query.

    Returns
    -------
    update_information : dict
        Updates information.
    """
    current_version = f'v{wazuh.__version__}'
    headers = {WAZUH_UID_KEY: installation_uid, WAZUH_TAG_KEY: current_version}

    update_information = get_update_information_template(
        update_check=True,
        current_version=current_version,
        last_check_date=get_utc_now()
    )

    async with aiohttp.ClientSession(connector=_get_connector()) as session:
        try:
            async with session.get(RELEASE_UPDATES_URL, headers=headers) as response:
                response_data = await response.json()

                update_information['status_code'] = response.status

                if response.status == 200:
                    if len(response_data['data']['major']):
                        update_information['last_available_major'].update(
                            **response_data['data']['major'][-1]
                        )
                    if len(response_data['data']['minor']):
                        update_information['last_available_minor'].update(
                            **response_data['data']['minor'][-1]
                        )
                    if len(response_data['data']['patch']):
                        update_information['last_available_patch'].update(
                            **response_data['data']['patch'][-1]
                        )
                else:
                    update_information['message'] = response_data['errors']['detail']
        except aiohttp.ClientError as err:
            update_information.update({'message': str(err), 'status_code': 500})
        except Exception as err:
            update_information.update({'message': str(err), 'status_code': 500})

    return update_information
