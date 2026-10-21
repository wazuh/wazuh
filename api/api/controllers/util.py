# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion.lifecycle import ConnexionResponse
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhException
from wazuh.manager import get_master_installation_uid

from api.encoder import dumps, prettify

JSON_CONTENT_TYPE="application/json"
XML_CONTENT_TYPE="application/xml; charset=utf-8"
ERROR_CONTENT_TYPE="application/problem+json; charset=utf-8"


def json_response(data: dict, pretty: bool = False, status_code: int = 200, content_type: str = JSON_CONTENT_TYPE) -> ConnexionResponse:
    """Generate a json Response from a dictionary.

    Parameters
    ----------
    data : dict
        Data dictionary to convert to json.
    pretty : bool
        Prettify the response to be human readable.
    status_code : int
        HTTP status code to return. Default 200.
    content_type : str
        Content type to return. Default JSON_CONTENT_TYPE

    Returns
    -------
    Response
        JSON response  generated from the data.
    """
    return ConnexionResponse(body=prettify(data) if pretty else dumps(data),
                             content_type=content_type,
                             status_code=status_code)

def build_recursion_error_response(pretty: bool = False) -> ConnexionResponse:
    problem = {
        "title": "Maximum recursion depth exceeded.",
        "detail": "The JSON structure of the request exceeds the maximum nesting depth allowed by the API."
    }

    return json_response(
        data=problem,
        pretty=pretty,
        status_code=400,
        content_type=ERROR_CONTENT_TYPE
    )


async def fill_master_uuid(data) -> None:
    """Set the master's installation UID in a node info result when the node did not provide one.

    Worker nodes do not have their own UID, so it is requested to the master. If it cannot be obtained the
    result is left untouched.

    Parameters
    ----------
    data : AffectedItemsWazuhResult
        Result of `get_basic_info`. It is modified in place.
    """
    items = getattr(data, 'affected_items', None)
    if not items or items[0].get('uuid') is not None:
        return

    dapi = DistributedAPI(f=get_master_installation_uid,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=False,
                          logger=logging.getLogger('wazuh-api'))
    result = await dapi.distribute_function()
    if not isinstance(result, WazuhException):
        items[0]['uuid'] = result.dikt['uuid']
