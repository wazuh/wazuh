# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""api.controllers.util module unit tests."""

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.util import json_response

@pytest.mark.parametrize('pretty, body', [(False, '{"a": "1", "b": "2"}'), 
                                          (True, '{\n   "a": "1",\n   "b": "2"\n}')])
def test_json_response(pretty, body):
    """Veryfy if the response body is converted to json and prettyfied."""
    data = {"a": "1", "b": "2"}
    response = json_response(data=data, pretty=pretty)
    assert isinstance(response, ConnexionResponse)
    assert response.body == body
