# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.lifecycle import ConnexionResponse
from api.encoder import dumps, prettify

JSON_CONTENT_TYPE="application/json"
XML_CONTENT_TYPE="application/xml; charset=utf-8"


def json_response(data: dict, pretty: bool = False) -> ConnexionResponse:
    """Generate a json Response from a dictionary.

    Parameters
    ----------
    data: dict
        Data dictionary to convert to json.
    pretty:
        Prettify the response to be human readable.

    Returns
    -------
    Response
        JSON response  generated from the data.
    """
    return ConnexionResponse(body=prettify(data) if pretty else dumps(data),
                             content_type=JSON_CONTENT_TYPE,
                             status_code=200)
