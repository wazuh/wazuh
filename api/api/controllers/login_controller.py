# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from api.models.token_response import TokenResponse  # noqa: E501
from api.authentication import generate_token


auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


def login_user(user):  # noqa: E501
    """User/password authentication to get an access token

    This method should be called to get an API token. This token will expire at some time. # noqa: E501


    :rtype: TokenResponse
    """

    return TokenResponse(token=generate_token(user)), 200
