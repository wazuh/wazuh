# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import base64
import re

import connexion

from api.authentication import check_user
from api.models.token_response import TokenResponse  # noqa: E501

auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


def login_user():  # noqa: E501
    """User/password authentication to get an access token

    This method should be called to get an API token. This token will expire at some time. # noqa: E501


    :rtype: TokenResponse
    """
    try:
        match = auth_re.match(connexion.request.headers['Authorization'])
        auth_info = match.group(1)
        user, password = base64.b64decode(auth_info).split(':', 2)
        if check_user(user=user, password=password):
            return TokenResponse(token='blablablablabla'), 200
    except (KeyError, AttributeError, ValueError, TypeError) as e:
        pass  # Just send unauthorized access

    return {}, 401
