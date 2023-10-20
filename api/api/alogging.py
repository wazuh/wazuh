# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import binascii
import collections
import hashlib
import json
import logging
import re
from base64 import b64decode

from aiohttp import web_request
from aiohttp.abc import AbstractAccessLogger
from pythonjsonlogger import jsonlogger

from wazuh.core.wlogging import WazuhLogger

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"


class AccessLogger(AbstractAccessLogger):
    """
    Define the log writer used by aiohttp.
    """
    def custom_logging(self, user, remote, method, path, query, body, time, status, hash_auth_context=''):
        """Provide the log entry structure depending on the logging format.

        Parameters
        ----------
        user : str
            User who perform the request.
        remote : str
            IP address of the request.
        method : str
            HTTP method used in the request.
        path : str
            Endpoint used in the request.
        query : dict
            Dictionary with the request parameters.
        body : dict
            Dictionary with the request body.
        time : float
            Required time to compute the request.
        status : int
            Status code of the request.
        hash_auth_context : str, optional
            Hash representing the authorization context. Default: ''
        """
        json_info = {
            'user': user,
            'ip': remote,
            'http_method': method,
            'uri': f'{method} {path}',
            'parameters': query,
            'body': body,
            'time': f'{time:.3f}s',
            'status_code': status
        }

        if not hash_auth_context:
            log_info = f'{user} {remote} "{method} {path}" '
        else:
            log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
            json_info['hash_auth_context'] = hash_auth_context

        if path == '/events' and self.logger.level >= 20:
            # If log level is info simplify the messages for the /events requests.
            events = body.get('events', [])
            body = {'events': len(events)}
            json_info['body'] = body

        log_info += f'with parameters {json.dumps(query)} and body {json.dumps(body)} done in {time:.3f}s: {status}'

        self.logger.info(log_info, extra={'log_type': 'log'})
        self.logger.info(json_info, extra={'log_type': 'json'})

    def log(self, request: web_request.BaseRequest, response: web_request.StreamResponse, time: float):
        """Override the log method to log messages.

        Parameters
        ----------
        request : web_request.BaseRequest
            API request onject.
        response : web_request.StreamResponse
            API response object.
        time : float
            Time taken by the API to respond to the request.
        """
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

        self.custom_logging(user, request.remote, request.method, request.path, query, body, time, response.status,
                            hash_auth_context=hash_auth_context)


class APILogger(WazuhLogger):
    """
    Define the logger used by wazuh-apid.
    """

    def __init__(self, *args: dict, **kwargs: dict):
        """APIlogger class constructor."""
        log_path = kwargs.get('log_path', '')
        super().__init__(*args, **kwargs,
                         custom_formatter=WazuhJsonFormatter if log_path.endswith('json') else None)

    def setup_logger(self, custom_handler: logging.Handler = None):
        """
        Set ups API logger. In addition to super().setup_logger() this method adds:
            * Sets up log level based on the log level defined in API configuration file.

        :param custom_handler: custom handler that can be set instead of the default one from the WazuhLogger class.
        """
        super().setup_logger(handler=custom_handler)

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


class WazuhJsonFormatter(jsonlogger.JsonFormatter):
    """
    Define the custom JSON log formatter used by wlogging.
    """

    def add_fields(self, log_record: collections.OrderedDict, record: logging.LogRecord, message_dict: dict):
        """Implement custom logic for adding fields in a log entry.

        Parameters
        ----------
        log_record : collections.OrderedDict
            Dictionary with custom fields used to generate a log entry.
        record : logging.LogRecord
            Contains all the information to the event being logged.
        message_dict : dict
            Dictionary with a request or exception information.
        """
        # Request handling
        if record.message is None:
            record.message = {
                'type': 'request',
                'payload': message_dict
            }
        else:
            # Traceback handling
            traceback = message_dict.get('exc_info')
            if traceback is not None:
                record.message = {
                    'type': 'error',
                    'payload': f'{record.message}. {traceback}'
                }
            else:
                # Plain text messages
                record.message = {
                    'type': 'informative',
                    'payload': record.message
                }
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['levelname'] = record.levelname
        log_record['data'] = record.message
