# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import binascii
import hashlib
import json
import logging
import re
from base64 import b64decode

from aiohttp.abc import AbstractAccessLogger

from wazuh.core.wlogging import WazuhLogger

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"


class AccessLogger(AbstractAccessLogger):

    def log(self, request, response, time):
        query = dict(request.query)
        body = request.get("body", dict())
        if 'password' in query:
            query['password'] = '****'
        if 'password' in body:
            body['password'] = '****'
        if 'key' in body and '/agents' in request.path:
            body['key'] = '****'

        # With permanent redirect, not found responses or any response with no token information,
        # decode the JWT token to get the username
        user = request.get('user', '')
        if not user:
            try:
                user = b64decode(request.headers["authorization"].split()[1]).decode().split(':')[0]
            except (KeyError, IndexError, binascii.Error):
                user = UNKNOWN_USER_STRING

        # Get or create authorization context hash
        hash_auth_context = ''
        # Get hash from token information
        if 'token_info' in request:
            hash_auth_context = request['token_info'].get('hash_auth_context', '')
        # Create hash if run_as login
        if not hash_auth_context and request.path == RUN_AS_LOGIN_ENDPOINT:
            hash_auth_context = hashlib.blake2b(json.dumps(body).encode(), digest_size=16).hexdigest()

        self.logger.info(f'{user}{f" {hash_auth_context} " if hash_auth_context else " "}{request.remote} '
                         f'"{request.method} {request.path}" with parameters {json.dumps(query)} and body '
                         f'{json.dumps(body)} done in {time:.3f}s: {response.status}')


class APILogger(WazuhLogger):
    """
    Defines the logger used by wazuh-apid
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor
        """
        super().__init__(*args, **kwargs, tag='{asctime} {levelname}: {message}')

    def setup_logger(self):
        """
        Set ups API logger. In addition to super().setup_logger() this method adds:
            * Sets up log level based on the log level defined in API configuration file.
        """
        super().setup_logger()

        if self.debug_level == 'debug2':
            debug_level = logging.DEBUG2
        elif self.debug_level == 'debug':
            debug_level = logging.DEBUG
        elif self.debug_level == 'critical':
            debug_level = logging.CRITICAL
        elif self.debug_level == 'error':
            debug_level = logging.ERROR
        elif self.debug_level == 'warning':
            debug_level = logging.WARNING
        else:  # self.debug_level == 'info'
            debug_level = logging.INFO

        self.logger.setLevel(debug_level)
